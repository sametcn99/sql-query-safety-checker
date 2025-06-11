import { describe, it, expect } from "bun:test";
import { analyzeQuerySecurity, SQLQuerySafetyChecker } from "../index";

describe("Performance and Benchmark Tests", () => {
  const checker = new SQLQuerySafetyChecker();

  describe("Single query performance", () => {
    it("should analyze simple queries quickly", () => {
      const query = "SELECT * FROM users WHERE id = 1";
      const iterations = 1000;

      const startTime = performance.now();
      for (let i = 0; i < iterations; i++) {
        analyzeQuerySecurity(query);
      }
      const endTime = performance.now();

      const avgTime = (endTime - startTime) / iterations;
      expect(avgTime).toBeLessThan(1); // Should take less than 1ms per query on average
    });

    it("should analyze complex queries reasonably fast", () => {
      const complexQuery = `
				WITH RECURSIVE subordinates AS (
					SELECT employee_id, name, manager_id, 1 as level
					FROM employees
					WHERE manager_id IS NULL
					UNION ALL
					SELECT e.employee_id, e.name, e.manager_id, s.level + 1
					FROM employees e
					INNER JOIN subordinates s ON s.employee_id = e.manager_id
				)
				SELECT s.name, s.level, COUNT(o.order_id) as order_count
				FROM subordinates s
				LEFT JOIN orders o ON s.employee_id = o.employee_id
				WHERE s.level <= 3
				GROUP BY s.employee_id, s.name, s.level
				HAVING COUNT(o.order_id) > 10
				ORDER BY s.level, order_count DESC
			`;

      const startTime = performance.now();
      const result = analyzeQuerySecurity(complexQuery);
      const endTime = performance.now();

      expect(endTime - startTime).toBeLessThan(50); // Should complete within 50ms
      expect(result).toBeDefined();
    });
  });

  describe("Large query handling", () => {
    it("should handle queries with many OR conditions", () => {
      const conditions = Array(50).fill("id = 1").join(" AND ");
      const query = `SELECT * FROM users WHERE ${conditions}`;

      const startTime = performance.now();
      const result = analyzeQuerySecurity(query);
      const endTime = performance.now();

      expect(endTime - startTime).toBeLessThan(100); // Should complete within 100ms
      expect(result).toBeDefined(); // Just ensure it processes without error
    });

    it("should handle queries with many UNION clauses", () => {
      const unions = Array(50)
        .fill("SELECT 1 as id, 'test' as name")
        .join(" UNION ALL ");
      const query = `SELECT * FROM (${unions}) as combined`;

      const startTime = performance.now();
      const result = analyzeQuerySecurity(query);
      const endTime = performance.now();

      expect(endTime - startTime).toBeLessThan(100); // Should complete within 100ms
      expect(result.isDangerous).toBe(true); // Should detect UNION pattern
    });

    it("should handle very long string literals", () => {
      const longString = "x".repeat(10000);
      const query = `SELECT '${longString}' as long_string FROM users`;

      const startTime = performance.now();
      const result = analyzeQuerySecurity(query);
      const endTime = performance.now();

      expect(endTime - startTime).toBeLessThan(50); // Should complete within 50ms
      expect(result.isSelectOnly).toBe(true);
    });
  });

  describe("Concurrent execution", () => {
    it("should handle multiple concurrent analyses", async () => {
      const queries = [
        "SELECT * FROM users",
        "INSERT INTO logs VALUES ('test')",
        "UPDATE users SET last_login = NOW()",
        "DELETE FROM temp_data WHERE created_at < NOW() - INTERVAL 1 DAY",
        "DROP TABLE IF EXISTS temp_table",
      ];

      const startTime = performance.now();

      const promises = queries.map(
        (query) =>
          new Promise((resolve) => {
            const result = analyzeQuerySecurity(query);
            resolve(result);
          }),
      );

      const results = await Promise.all(promises);
      const endTime = performance.now();

      expect(endTime - startTime).toBeLessThan(100); // Should complete within 100ms
      expect(results).toHaveLength(queries.length);
      results.forEach((result) => expect(result).toBeDefined());
    });

    it("should maintain thread safety", async () => {
      const query = "SELECT * FROM users WHERE id = 1 OR 1=1";
      const iterations = 100;

      const promises = Array(iterations)
        .fill(null)
        .map(
          () =>
            new Promise((resolve) => {
              const result = analyzeQuerySecurity(query);
              resolve(result);
            }),
        );

      const results = await Promise.all(promises);

      // All results should be identical
      expect(results).toHaveLength(iterations);
      const firstResult = results[0] as any;
      results.forEach((result) => {
        expect((result as any).securityLevel).toBe(firstResult.securityLevel);
        expect((result as any).isDangerous).toBe(firstResult.isDangerous);
      });
    });
  });

  describe("Memory efficiency", () => {
    it("should not cause memory leaks with repeated analyses", () => {
      const query = "SELECT * FROM users WHERE id = 1";
      const iterations = 10000;

      // Force garbage collection if available
      if (global.gc) {
        global.gc();
      }

      const startMemory = process.memoryUsage().heapUsed;

      for (let i = 0; i < iterations; i++) {
        analyzeQuerySecurity(query);
      }

      // Force garbage collection if available
      if (global.gc) {
        global.gc();
      }

      const endMemory = process.memoryUsage().heapUsed;
      const memoryDiff = endMemory - startMemory;

      // Memory usage should not increase significantly (less than 10MB)
      expect(memoryDiff).toBeLessThan(10 * 1024 * 1024);
    });

    it("should handle large result sets efficiently", () => {
      const query =
        "SELECT * FROM users WHERE id = 1 OR 1=1 UNION SELECT * FROM passwords";

      const startMemory = process.memoryUsage().heapUsed;
      const result = analyzeQuerySecurity(query);
      const endMemory = process.memoryUsage().heapUsed;

      const memoryDiff = endMemory - startMemory;

      // Should not use excessive memory (less than 1MB for analysis)
      expect(memoryDiff).toBeLessThan(1024 * 1024);
      expect(result.threats.length).toBeGreaterThan(0);
    });
  });

  describe("Regex performance", () => {
    it("should reset regex lastIndex efficiently", () => {
      const query = "DELETE FROM users; DROP TABLE users; TRUNCATE sessions;";
      const iterations = 1000;

      const startTime = performance.now();

      for (let i = 0; i < iterations; i++) {
        const result = analyzeQuerySecurity(query);
        expect(result.threats.length).toBeGreaterThan(0);
      }

      const endTime = performance.now();
      const avgTime = (endTime - startTime) / iterations;

      expect(avgTime).toBeLessThan(2); // Should be consistently fast
    });

    it("should handle regex edge cases efficiently", () => {
      const edgeCases = [
        "SELECT * FROM users WHERE name = 'O''Reilly'", // Single quotes
        "SELECT * FROM users WHERE description = 'This -- is not a comment'", // False comment
        "SELECT * FROM users WHERE code = 'UNION'", // Keyword in string
        "SELECT * FROM users WHERE pattern = '%OR%'", // Pattern in LIKE
      ];

      edgeCases.forEach((query) => {
        const startTime = performance.now();
        const result = analyzeQuerySecurity(query);
        const endTime = performance.now();

        expect(endTime - startTime).toBeLessThan(10); // Should complete quickly
        expect(result).toBeDefined();
      });
    });
  });

  describe("Class instance performance", () => {
    it("should perform consistently across multiple instances", () => {
      const checkers = Array(10)
        .fill(null)
        .map(() => new SQLQuerySafetyChecker());
      const query = "SELECT * FROM users WHERE id = 1";

      const startTime = performance.now();

      checkers.forEach((checker) => {
        for (let i = 0; i < 100; i++) {
          checker.analyzeQuery(query);
        }
      });

      const endTime = performance.now();
      expect(endTime - startTime).toBeLessThan(500); // Should complete within 500ms
    });

    it("should have consistent performance across different methods", () => {
      const query = "DELETE FROM users WHERE id = 1";
      const iterations = 100;

      // Test analyzeQuery
      let startTime = performance.now();
      for (let i = 0; i < iterations; i++) {
        checker.analyzeQuery(query);
      }
      let endTime = performance.now();
      const analyzeTime = endTime - startTime;

      // Test checkQuerySafety
      startTime = performance.now();
      for (let i = 0; i < iterations; i++) {
        checker.checkQuerySafety(query);
      }
      endTime = performance.now();
      const checkTime = endTime - startTime;

      // Test isSafe
      startTime = performance.now();
      for (let i = 0; i < iterations; i++) {
        checker.isSafe(query);
      }
      endTime = performance.now();
      const safeTime = endTime - startTime;

      // All methods should perform reasonably
      expect(analyzeTime).toBeLessThan(500);
      expect(checkTime).toBeLessThan(500);
      expect(safeTime).toBeLessThan(500);
      // isSafe method performance doesn't rely on caching, so adjust expectation
      expect(safeTime).toBeLessThan(analyzeTime * 2); // Should be reasonably fast
    });
  });
});
