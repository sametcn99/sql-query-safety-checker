import { describe, it, expect } from "bun:test";
import {
  analyzeQuerySecurity,
  needsConfirmation,
  getQuerySecuritySummary,
  getSecurityLevelColor,
  SecurityLevel,
} from "../index";
import "./setup"; // Import custom matchers

describe("Utility Functions Tests", () => {
  describe("needsConfirmation", () => {
    it("should not require confirmation for safe queries", () => {
      const safeQueries = [
        "SELECT * FROM users",
        "EXPLAIN SELECT * FROM products",
        "DESCRIBE users",
        "SHOW TABLES",
        "",
        "/* just a comment */",
      ];

      safeQueries.forEach((query) => {
        const result = needsConfirmation(query);
        expect(result.required).toBe(false);
        expect(result.level).toBe(SecurityLevel.SAFE);
        expect(result.reason).toContain("safe");
      });
    });

    it("should require confirmation for medium risk queries", () => {
      const mediumRiskQueries = [
        "INSERT INTO users (name) VALUES ('John')",
        "UPDATE users SET name = 'John' WHERE id = 1",
        "REPLACE INTO users (id, name) VALUES (1, 'John')",
      ];
      mediumRiskQueries.forEach((query) => {
        const result = needsConfirmation(query);
        expect(result.required).toBe(true);
        expect(result.level).toBe(SecurityLevel.MEDIUM_RISK);
        expect(
          result.reason.includes("medium-risk") ||
            result.reason.includes("data modification"),
        ).toBe(true);
      });
    });

    it("should require confirmation for high risk queries", () => {
      const highRiskQueries = [
        "DELETE FROM users WHERE id = 1",
        "TRUNCATE TABLE logs",
        "CREATE TABLE test (id INT)",
      ];

      highRiskQueries.forEach((query) => {
        const result = needsConfirmation(query);
        expect(result.required).toBe(true);
        expect(result.level).toBeOneOf([
          SecurityLevel.HIGH_RISK,
          SecurityLevel.CRITICAL,
        ]);
        expect(result.reason).toBeDefined();
      });
    });
    it("should require confirmation for critical queries", () => {
      const criticalQueries = [
        "DROP TABLE users",
        "SELECT * FROM users WHERE id = 1' OR 1=1",
        "BACKUP DATABASE mydb TO DISK = 'backup.bak'",
      ];

      criticalQueries.forEach((query) => {
        const result = needsConfirmation(query);
        expect(result.required).toBe(true);
        expect(result.level).toBe(SecurityLevel.CRITICAL);
        expect(result.reason).toContain("critical");
      });
    });
  });

  describe("getSecurityLevelColor", () => {
    it("should return correct hex colors for each security level", () => {
      const expectedColors = {
        [SecurityLevel.SAFE]: "#4caf50",
        [SecurityLevel.LOW_RISK]: "#8bc34a",
        [SecurityLevel.MEDIUM_RISK]: "#ff9800",
        [SecurityLevel.HIGH_RISK]: "#f44336",
        [SecurityLevel.CRITICAL]: "#9c27b0",
      };

      Object.entries(expectedColors).forEach(([level, expectedColor]) => {
        const color = getSecurityLevelColor(level as SecurityLevel);
        expect(color).toBe(expectedColor);
      });
    });

    it("should return default color for unknown levels", () => {
      const unknownLevel = "unknown" as SecurityLevel;
      const color = getSecurityLevelColor(unknownLevel);
      expect(color).toBe("#757575"); // Grey default
    });

    it("should handle null and undefined gracefully", () => {
      expect(() => getSecurityLevelColor(null as any)).not.toThrow();
      expect(() => getSecurityLevelColor(undefined as any)).not.toThrow();
    });
  });

  describe("getQuerySecuritySummary", () => {
    it("should provide meaningful summaries for safe queries", () => {
      const safeQueries = [
        "SELECT * FROM users",
        "EXPLAIN SELECT COUNT(*) FROM products",
        "DESCRIBE users",
        "",
        "/* comment only */",
      ];

      safeQueries.forEach((query) => {
        const summary = getQuerySecuritySummary(query);
        expect(summary).toBeDefined();
        expect(typeof summary).toBe("string");
        expect(summary.length).toBeGreaterThan(0);
        expect(summary.toLowerCase()).toMatch(/safe|read.?only|no.*threat/);
      });
    });

    it("should provide detailed summaries for dangerous queries", () => {
      const testCases = [
        {
          query: "DELETE FROM users",
          expectedContent: ["high-risk", "1"],
        },
        {
          query: "DROP TABLE users",
          expectedContent: ["critical", "1"],
        },
        {
          query: "DELETE FROM users; DROP TABLE users",
          expectedContent: ["critical", "high-risk"],
        },
      ];

      testCases.forEach(({ query, expectedContent }) => {
        const summary = getQuerySecuritySummary(query);
        expect(summary).toBeDefined();
        expect(typeof summary).toBe("string");

        expectedContent.forEach((content) => {
          expect(summary.toLowerCase()).toContain(content.toLowerCase());
        });
      });
    });

    it("should handle empty and null queries gracefully", () => {
      expect(getQuerySecuritySummary("")).toBeDefined();
      expect(getQuerySecuritySummary("   ")).toBeDefined();
      expect(() => getQuerySecuritySummary(null as any)).not.toThrow();
      expect(() => getQuerySecuritySummary(undefined as any)).not.toThrow();
    });

    it("should provide appropriate summaries for different threat levels", () => {
      const testCases = [
        {
          level: SecurityLevel.SAFE,
          queries: ["SELECT * FROM users"],
          shouldContain: ["safe", "read"],
        },
        {
          level: SecurityLevel.MEDIUM_RISK,
          queries: ["INSERT INTO users VALUES (1, 'test')"],
          shouldContain: ["medium-risk"],
        },
        {
          level: SecurityLevel.HIGH_RISK,
          queries: ["DELETE FROM users"],
          shouldContain: ["high-risk"],
        },
        {
          level: SecurityLevel.CRITICAL,
          queries: ["DROP TABLE users"],
          shouldContain: ["critical"],
        },
      ];

      testCases.forEach(({ queries, shouldContain }) => {
        queries.forEach((query) => {
          const summary = getQuerySecuritySummary(query);
          const lowerSummary = summary.toLowerCase();

          const containsExpected = shouldContain.some((keyword) =>
            lowerSummary.includes(keyword.toLowerCase()),
          );
          expect(containsExpected).toBe(true);
        });
      });
    });
    it("should count multiple threats correctly", () => {
      const multiThreatQuery =
        "DELETE FROM users; DROP TABLE sessions; BACKUP DATABASE mydb TO DISK = 'backup.bak'";
      const summary = getQuerySecuritySummary(multiThreatQuery);

      expect(summary).toBeDefined();
      expect(summary.toLowerCase()).toContain("critical");

      // Should mention multiple threats or highest severity
      const hasMultipleThreatIndication =
        summary.includes("critical") ||
        summary.includes("multiple") ||
        /\d+/.test(summary); // Contains numbers indicating count

      expect(hasMultipleThreatIndication).toBe(true);
    });
  });

  describe("Edge cases and error handling", () => {
    it("should handle malformed SQL gracefully", () => {
      const malformedQueries = [
        "SELECT * FROM", // Incomplete
        "SELEC * FORM users", // Typos
        "SELECT * FROM users WHERE", // Incomplete WHERE
        ";;;", // Just semicolons
        "SELECT SELECT SELECT", // Repeated keywords
      ];

      malformedQueries.forEach((query) => {
        expect(() => analyzeQuerySecurity(query)).not.toThrow();
        expect(() => needsConfirmation(query)).not.toThrow();
        expect(() => getQuerySecuritySummary(query)).not.toThrow();
      });
    });

    it("should handle extremely long queries", () => {
      const veryLongQuery =
        "SELECT " + "column1,".repeat(1000) + " column_last FROM users";

      expect(() => analyzeQuerySecurity(veryLongQuery)).not.toThrow();
      expect(() => needsConfirmation(veryLongQuery)).not.toThrow();
      expect(() => getQuerySecuritySummary(veryLongQuery)).not.toThrow();

      const result = analyzeQuerySecurity(veryLongQuery);
      expect(result).toBeDefined();
      expect(result.isSelectOnly).toBe(true);
    });

    it("should handle special characters and encoding", () => {
      const specialQueries = [
        "SELECT * FROM users WHERE name = 'José'", // Unicode
        "SELECT * FROM users WHERE name = 'O\\'Reilly'", // Escaped quotes
        "SELECT * FROM users WHERE data = '\\x41\\x42'", // Hex escapes
        "SELECT * FROM users WHERE pattern = '%\\%'", // Escaped wildcards
      ];

      specialQueries.forEach((query) => {
        expect(() => analyzeQuerySecurity(query)).not.toThrow();
        const result = analyzeQuerySecurity(query);
        expect(result).toBeDefined();
      });
    });

    it("should handle queries with various comment styles", () => {
      const commentQueries = [
        "SELECT * FROM users -- line comment",
        "/* block comment */ SELECT * FROM users",
        "SELECT * FROM users /* inline comment */ WHERE id = 1",
        "SELECT * FROM users # MySQL style comment",
      ];

      commentQueries.forEach((query) => {
        const result = analyzeQuerySecurity(query);
        expect(result).toBeDefined();
        // Comments should be normalized away for safe queries
        if (!result.isDangerous) {
          expect(result.isSelectOnly).toBe(true);
        }
      });
    });
  });
});
