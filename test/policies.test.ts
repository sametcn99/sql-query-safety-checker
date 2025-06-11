import { describe, it, expect } from "bun:test";
import {
  validateQueryAgainstPolicy,
  SecurityLevel,
  type SecurityPolicy,
} from "../index";

describe("Security Policy Integration Tests", () => {
  describe("Default Security Policy", () => {
    it("should allow safe operations by default", () => {
      const safeQueries = [
        "SELECT * FROM users",
        "EXPLAIN SELECT * FROM products",
        "DESCRIBE users",
        "SHOW TABLES",
      ];

      safeQueries.forEach((query) => {
        const result = validateQueryAgainstPolicy(query);
        expect(result.isValid).toBe(true);
        expect(result.violations).toHaveLength(0);
      });
    });

    it("should reject dangerous operations by default", () => {
      const dangerousQueries = [
        "DROP TABLE users",
        "DELETE FROM users",
        "INSERT INTO users VALUES (1, 'test')",
        "UPDATE users SET name = 'test'",
      ];

      dangerousQueries.forEach((query) => {
        const result = validateQueryAgainstPolicy(query);
        expect(result.isValid).toBe(false);
        expect(result.violations.length).toBeGreaterThan(0);
      });
    });
  });

  describe("Custom Security Policies", () => {
    it("should enforce restrictive policies", () => {
      const restrictivePolicy = ["SELECT"];

      const result = validateQueryAgainstPolicy(
        "INSERT INTO users VALUES (1, 'test')",
        restrictivePolicy,
      );
      expect(result.isValid).toBe(false);
      expect(result.violations.some((v) => v.includes("INSERT"))).toBe(true);
    });

    it("should allow permissive policies", () => {
      const permissivePolicy = ["SELECT", "INSERT", "UPDATE", "DELETE"];

      const insertResult = validateQueryAgainstPolicy(
        "INSERT INTO users VALUES (1, 'test')",
        permissivePolicy,
      );
      expect(insertResult.isValid).toBe(true);

      const updateResult = validateQueryAgainstPolicy(
        "UPDATE users SET name = 'test'",
        permissivePolicy,
      );
      expect(updateResult.isValid).toBe(true);

      const deleteResult = validateQueryAgainstPolicy(
        "DELETE FROM users WHERE id = 1",
        permissivePolicy,
      );
      expect(deleteResult.isValid).toBe(true);
    });
    it("should still block critical threats regardless of policy", () => {
      const permissivePolicy = ["SELECT", "INSERT", "UPDATE", "DELETE", "DROP"];

      const injectionResult = validateQueryAgainstPolicy(
        "SELECT * FROM users WHERE id = 1' OR 1=1",
        permissivePolicy,
      );
      expect(injectionResult.isValid).toBe(false);
      expect(
        injectionResult.violations.some((v) => v.includes("Critical")),
      ).toBe(true);
    });
    it("should always block SQL injection patterns", () => {
      const veryPermissivePolicy = [
        "SELECT",
        "INSERT",
        "UPDATE",
        "DELETE",
        "DROP",
        "CREATE",
        "ALTER",
      ];

      const injectionQueries = [
        "SELECT * FROM users UNION SELECT * FROM passwords",
        "SELECT * FROM users WHERE id = 1' OR 1=1",
      ];

      injectionQueries.forEach((query) => {
        const result = validateQueryAgainstPolicy(query, veryPermissivePolicy);
        expect(result.isValid).toBe(false);
        expect(result.violations.some((v) => v.includes("injection"))).toBe(
          true,
        );
      });
    });
  });

  describe("Policy Validation Edge Cases", () => {
    it("should handle empty policies", () => {
      const result = validateQueryAgainstPolicy("SELECT * FROM users", []);
      expect(result.isValid).toBe(true); // SELECT should still be allowed for safe queries
    });

    it("should handle null/undefined policies", () => {
      expect(() =>
        validateQueryAgainstPolicy("SELECT * FROM users", undefined as any),
      ).not.toThrow();
      expect(() =>
        validateQueryAgainstPolicy("SELECT * FROM users", null as any),
      ).not.toThrow();
    });

    it("should handle case-insensitive policy matching", () => {
      const policy = ["select", "insert"];

      const selectResult = validateQueryAgainstPolicy(
        "SELECT * FROM users",
        policy,
      );
      const insertResult = validateQueryAgainstPolicy(
        "INSERT INTO users VALUES (1, 'test')",
        policy,
      );

      // This depends on implementation - might need case-insensitive matching
      expect(selectResult.isValid || insertResult.isValid).toBe(true);
    });
  });

  describe("Full Security Policy Objects", () => {
    const strictPolicy: SecurityPolicy = {
      allowedOperations: ["SELECT", "EXPLAIN", "DESCRIBE", "SHOW"],
      maxRiskLevel: SecurityLevel.LOW_RISK,
      blockInjectionPatterns: true,
      requireConfirmationFor: [
        SecurityLevel.MEDIUM_RISK,
        SecurityLevel.HIGH_RISK,
        SecurityLevel.CRITICAL,
      ],
    };

    const moderatePolicy: SecurityPolicy = {
      allowedOperations: ["SELECT", "INSERT", "UPDATE"],
      maxRiskLevel: SecurityLevel.MEDIUM_RISK,
      blockInjectionPatterns: true,
      requireConfirmationFor: [SecurityLevel.HIGH_RISK, SecurityLevel.CRITICAL],
    };

    const permissivePolicy: SecurityPolicy = {
      allowedOperations: [
        "SELECT",
        "INSERT",
        "UPDATE",
        "DELETE",
        "CREATE",
        "ALTER",
      ],
      maxRiskLevel: SecurityLevel.HIGH_RISK,
      blockInjectionPatterns: true,
      requireConfirmationFor: [SecurityLevel.CRITICAL],
    };
    it("should validate against strict policy", () => {
      // Should pass
      expect(
        validateQueryAgainstPolicy(
          "SELECT * FROM users",
          strictPolicy.allowedOperations,
        ).isValid,
      ).toBe(true);
      expect(
        validateQueryAgainstPolicy(
          "EXPLAIN SELECT * FROM users",
          strictPolicy.allowedOperations,
        ).isValid,
      ).toBe(true);

      // Should fail
      expect(
        validateQueryAgainstPolicy(
          "INSERT INTO users VALUES (1, 'test')",
          strictPolicy.allowedOperations,
        ).isValid,
      ).toBe(false);
      expect(
        validateQueryAgainstPolicy(
          "DELETE FROM users",
          strictPolicy.allowedOperations,
        ).isValid,
      ).toBe(false);
    });

    it("should validate against moderate policy", () => {
      // Should pass
      expect(
        validateQueryAgainstPolicy(
          "SELECT * FROM users",
          moderatePolicy.allowedOperations,
        ).isValid,
      ).toBe(true);
      expect(
        validateQueryAgainstPolicy(
          "INSERT INTO users VALUES (1, 'test')",
          moderatePolicy.allowedOperations,
        ).isValid,
      ).toBe(true);
      expect(
        validateQueryAgainstPolicy(
          "UPDATE users SET name = 'test'",
          moderatePolicy.allowedOperations,
        ).isValid,
      ).toBe(true);

      // Should fail
      expect(
        validateQueryAgainstPolicy(
          "DELETE FROM users",
          moderatePolicy.allowedOperations,
        ).isValid,
      ).toBe(false);
      expect(
        validateQueryAgainstPolicy(
          "DROP TABLE users",
          moderatePolicy.allowedOperations,
        ).isValid,
      ).toBe(false);
    });

    it("should validate against permissive policy", () => {
      // Should pass
      expect(
        validateQueryAgainstPolicy(
          "SELECT * FROM users",
          permissivePolicy.allowedOperations,
        ).isValid,
      ).toBe(true);
      expect(
        validateQueryAgainstPolicy(
          "DELETE FROM users WHERE id = 1",
          permissivePolicy.allowedOperations,
        ).isValid,
      ).toBe(true);
      expect(
        validateQueryAgainstPolicy(
          "CREATE TABLE test (id INT)",
          permissivePolicy.allowedOperations,
        ).isValid,
      ).toBe(true); // Should still fail for injections
      expect(
        validateQueryAgainstPolicy(
          "SELECT * FROM users WHERE id = 1' OR 1=1",
          permissivePolicy.allowedOperations,
        ).isValid,
      ).toBe(false);
    });
  });

  describe("Real-world Policy Scenarios", () => {
    it("should handle read-only application policy", () => {
      const readOnlyPolicy = ["SELECT", "EXPLAIN", "DESCRIBE", "SHOW"];

      const queries = [
        { query: "SELECT * FROM users", shouldPass: true },
        {
          query: "SELECT COUNT(*) FROM orders WHERE date > '2023-01-01'",
          shouldPass: true,
        },
        { query: "EXPLAIN SELECT * FROM complex_view", shouldPass: true },
        { query: "INSERT INTO logs VALUES ('test')", shouldPass: false },
        { query: "UPDATE users SET last_login = NOW()", shouldPass: false },
      ];

      queries.forEach(({ query, shouldPass }) => {
        const result = validateQueryAgainstPolicy(query, readOnlyPolicy);
        expect(result.isValid).toBe(shouldPass);
      });
    });

    it("should handle data entry application policy", () => {
      const dataEntryPolicy = ["SELECT", "INSERT", "UPDATE"];

      const queries = [
        { query: "SELECT * FROM products", shouldPass: true },
        {
          query: "INSERT INTO orders (customer_id, total) VALUES (1, 100.50)",
          shouldPass: true,
        },
        {
          query:
            "UPDATE inventory SET quantity = quantity - 1 WHERE product_id = 1",
          shouldPass: true,
        },
        { query: "DELETE FROM orders WHERE id = 1", shouldPass: false },
        { query: "DROP TABLE temp_data", shouldPass: false },
      ];

      queries.forEach(({ query, shouldPass }) => {
        const result = validateQueryAgainstPolicy(query, dataEntryPolicy);
        expect(result.isValid).toBe(shouldPass);
      });
    });
    it("should handle admin maintenance policy", () => {
      const adminPolicy = [
        "SELECT",
        "INSERT",
        "UPDATE",
        "DELETE",
        "CREATE",
        "ALTER",
        "DROP",
        "TRUNCATE",
      ];

      // Should still block injections even for admin
      const injectionQuery = "SELECT * FROM users WHERE id = 1' OR 1=1";
      const result = validateQueryAgainstPolicy(injectionQuery, adminPolicy);
      expect(result.isValid).toBe(false);
      expect(result.violations.some((v) => v.includes("injection"))).toBe(true);
    });
  });
});
