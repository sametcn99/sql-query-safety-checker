import { describe, it, expect, beforeEach } from "bun:test";
import {
  SecurityLevel,
  SQLQuerySafetyChecker,
  analyzeQuerySecurity,
  needsConfirmation,
  getSecurityLevelColor,
  validateQueryAgainstPolicy,
  isQuerySafe,
  getQuerySecuritySummary,
  createSafetyChecker,
  type QueryAnalysis,
  type ConfirmationResult,
  type PolicyValidationResult,
  type SecurityPolicy,
} from "../index";

describe("SQL Query Safety Checker", () => {
  let checker: SQLQuerySafetyChecker;

  beforeEach(() => {
    checker = new SQLQuerySafetyChecker();
  });
  describe("SecurityLevel enum", () => {
    it("should have all required security levels", () => {
      expect(SecurityLevel.SAFE).toBe(SecurityLevel.SAFE);
      expect(SecurityLevel.LOW_RISK).toBe(SecurityLevel.LOW_RISK);
      expect(SecurityLevel.MEDIUM_RISK).toBe(SecurityLevel.MEDIUM_RISK);
      expect(SecurityLevel.HIGH_RISK).toBe(SecurityLevel.HIGH_RISK);
      expect(SecurityLevel.CRITICAL).toBe(SecurityLevel.CRITICAL);
    });
    it("should have correct string values", () => {
      expect(SecurityLevel.SAFE as string).toBe("safe");
      expect(SecurityLevel.LOW_RISK as string).toBe("low_risk");
      expect(SecurityLevel.MEDIUM_RISK as string).toBe("medium_risk");
      expect(SecurityLevel.HIGH_RISK as string).toBe("high_risk");
      expect(SecurityLevel.CRITICAL as string).toBe("critical");
    });
  });

  describe("analyzeQuerySecurity", () => {
    it("should return safe for empty queries", () => {
      const result = analyzeQuerySecurity("");
      expect(result.securityLevel).toBe(SecurityLevel.SAFE);
      expect(result.isDangerous).toBe(false);
      expect(result.isSelectOnly).toBe(true);
      expect(result.threats).toHaveLength(0);
      expect(result.allowExecution).toBe(true);
    });

    it("should detect SELECT queries as safe", () => {
      const result = analyzeQuerySecurity("SELECT * FROM users WHERE id = 1");
      expect(result.securityLevel).toBe(SecurityLevel.SAFE);
      expect(result.isDangerous).toBe(false);
      expect(result.isSelectOnly).toBe(true);
      expect(result.allowExecution).toBe(true);
    });

    it("should detect DELETE operations as high risk", () => {
      const result = analyzeQuerySecurity("DELETE FROM users WHERE id = 1");
      expect(result.securityLevel).toBe(SecurityLevel.HIGH_RISK);
      expect(result.isDangerous).toBe(true);
      expect(result.isSelectOnly).toBe(false);
      expect(result.threats).toHaveLength(1);
      expect(result.threats[0].name).toBe("DELETE");
      expect(result.threats[0].category).toBe("DML");
    });

    it("should detect UPDATE operations as medium risk", () => {
      const result = analyzeQuerySecurity(
        "UPDATE users SET name = 'John' WHERE id = 1",
      );
      expect(result.securityLevel).toBe(SecurityLevel.MEDIUM_RISK);
      expect(result.isDangerous).toBe(true);
      expect(result.isSelectOnly).toBe(false);
      expect(result.threats).toHaveLength(1);
      expect(result.threats[0].name).toBe("UPDATE");
      expect(result.threats[0].category).toBe("DML");
    });

    it("should detect INSERT operations as medium risk", () => {
      const result = analyzeQuerySecurity(
        "INSERT INTO users (name, email) VALUES ('John', 'john@example.com')",
      );
      expect(result.securityLevel).toBe(SecurityLevel.MEDIUM_RISK);
      expect(result.isDangerous).toBe(true);
      expect(result.isSelectOnly).toBe(false);
      expect(result.threats).toHaveLength(1);
      expect(result.threats[0].name).toBe("INSERT");
      expect(result.threats[0].category).toBe("DML");
    });

    it("should detect DROP operations as critical", () => {
      const result = analyzeQuerySecurity("DROP TABLE users");
      expect(result.securityLevel).toBe(SecurityLevel.CRITICAL);
      expect(result.isDangerous).toBe(true);
      expect(result.isSelectOnly).toBe(false);
      expect(result.threats).toHaveLength(1);
      expect(result.threats[0].name).toBe("DROP");
      expect(result.threats[0].category).toBe("DDL");
    });
    it("should detect SQL injection patterns as critical", () => {
      const result = analyzeQuerySecurity(
        "SELECT * FROM users WHERE id = 1' OR 1=1",
      );
      expect(result.securityLevel).toBe(SecurityLevel.CRITICAL);
      expect(result.isDangerous).toBe(true);
      expect(result.threats.some((t) => t.category === "INJECTION")).toBe(true);
    });

    it("should detect union-based injection", () => {
      const result = analyzeQuerySecurity(
        "SELECT * FROM users WHERE id = 1 UNION SELECT * FROM passwords",
      );
      expect(result.securityLevel).toBe(SecurityLevel.CRITICAL);
      expect(result.threats.some((t) => t.name === "UNION_INJECTION")).toBe(
        true,
      );
    });
    it("should detect comment-based injection patterns", () => {
      const result = analyzeQuerySecurity(
        "SELECT * FROM users WHERE id = 1 || 'test'",
      );
      expect(result.isDangerous).toBe(true);
      expect(result.threats.some((t) => t.name === "COMMENT_INJECTION")).toBe(
        true,
      );
    });

    it("should normalize queries by removing comments", () => {
      const result = analyzeQuerySecurity(
        "SELECT * FROM users /* this is a comment */ WHERE id = 1",
      );
      expect(result.securityLevel).toBe(SecurityLevel.SAFE);
      expect(result.isSelectOnly).toBe(true);
    });
    it("should handle multiple threats and return highest security level", () => {
      const result = analyzeQuerySecurity(
        "DELETE FROM users; DROP TABLE users",
      );
      expect(result.securityLevel).toBe(SecurityLevel.CRITICAL);
      expect(result.threats.length).toBeGreaterThan(1);
    });
    it("should detect administrative operations", () => {
      const result = analyzeQuerySecurity(
        "BACKUP DATABASE mydb TO DISK = 'backup.bak'",
      );
      expect(result.securityLevel).toBe(SecurityLevel.CRITICAL);
      expect(result.threats.some((t) => t.category === "ADMIN")).toBe(true);
    });
    it("should detect system operations", () => {
      const result = analyzeQuerySecurity("EXEC xp_cmdshell 'dir'");
      expect(result.securityLevel).toBe(SecurityLevel.CRITICAL);
      expect(result.threats.some((t) => t.category === "SYSTEM")).toBe(true);
    });
  });

  describe("SQLQuerySafetyChecker class", () => {
    it("should analyze queries correctly", () => {
      const result = checker.analyzeQuery("SELECT * FROM users");
      expect(result.securityLevel).toBe(SecurityLevel.SAFE);
      expect(result.isSelectOnly).toBe(true);
    });

    it("should check query safety", () => {
      const safeResult = checker.checkQuerySafety("SELECT * FROM users");
      expect(safeResult.isDangerous).toBe(false);
      expect(safeResult.isSelectOnly).toBe(true);
      expect(safeResult.dangerousOperations).toHaveLength(0);

      const dangerousResult = checker.checkQuerySafety("DROP TABLE users");
      expect(dangerousResult.isDangerous).toBe(true);
      expect(dangerousResult.isSelectOnly).toBe(false);
      expect(dangerousResult.dangerousOperations).toContain("DROP");
    });

    it("should detect SELECT-only queries", () => {
      expect(checker.isSelectOnlyQuery("SELECT * FROM users")).toBe(true);
      expect(checker.isSelectOnlyQuery("DELETE FROM users")).toBe(false);
    });

    it("should determine confirmation requirements", () => {
      const safeResult = checker.requiresConfirmation("SELECT * FROM users");
      expect(safeResult.required).toBe(false);
      expect(safeResult.level).toBe(SecurityLevel.SAFE);

      const dangerousResult = checker.requiresConfirmation("DELETE FROM users");
      expect(dangerousResult.required).toBe(true);
      expect(dangerousResult.level).toBe(SecurityLevel.HIGH_RISK);
    });

    it("should validate against security policies", () => {
      const policy: SecurityPolicy = {
        allowedOperations: ["SELECT"],
        maxRiskLevel: SecurityLevel.LOW_RISK,
        blockInjectionPatterns: true,
        requireConfirmationFor: [
          SecurityLevel.MEDIUM_RISK,
          SecurityLevel.HIGH_RISK,
        ],
      };

      const validResult = checker.validateAgainstPolicy(
        "SELECT * FROM users",
        policy,
      );
      expect(validResult.isValid).toBe(true);
      expect(validResult.violations).toHaveLength(0);

      const invalidResult = checker.validateAgainstPolicy(
        "DELETE FROM users",
        policy,
      );
      expect(invalidResult.isValid).toBe(false);
      expect(invalidResult.violations.length).toBeGreaterThan(0);
    });

    it("should provide security summaries", () => {
      const safeQuery = checker.getSecuritySummary("SELECT * FROM users");
      expect(safeQuery).toContain("Safe");

      const dangerousQuery = checker.getSecuritySummary("DELETE FROM users");
      expect(dangerousQuery).toContain("high-risk");
    });

    it("should determine if queries are safe", () => {
      expect(checker.isSafe("SELECT * FROM users")).toBe(true);
      expect(checker.isSafe("DROP DATABASE production")).toBe(false);
    });
  });

  describe("needsConfirmation", () => {
    it("should not require confirmation for safe queries", () => {
      const result = needsConfirmation("SELECT * FROM users");
      expect(result.required).toBe(false);
      expect(result.level).toBe(SecurityLevel.SAFE);
      expect(result.reason).toContain("safe");
    });

    it("should require confirmation for dangerous queries", () => {
      const result = needsConfirmation("DELETE FROM users");
      expect(result.required).toBe(true);
      expect(result.level).toBe(SecurityLevel.HIGH_RISK);
      expect(result.reason).toContain("high-risk");
    });

    it("should require confirmation for critical queries", () => {
      const result = needsConfirmation("DROP DATABASE production");
      expect(result.required).toBe(true);
      expect(result.level).toBe(SecurityLevel.CRITICAL);
      expect(result.reason).toContain("critical");
    });
  });

  describe("getSecurityLevelColor", () => {
    it("should return correct colors for each security level", () => {
      expect(getSecurityLevelColor(SecurityLevel.SAFE)).toBe("#4caf50");
      expect(getSecurityLevelColor(SecurityLevel.LOW_RISK)).toBe("#8bc34a");
      expect(getSecurityLevelColor(SecurityLevel.MEDIUM_RISK)).toBe("#ff9800");
      expect(getSecurityLevelColor(SecurityLevel.HIGH_RISK)).toBe("#f44336");
      expect(getSecurityLevelColor(SecurityLevel.CRITICAL)).toBe("#9c27b0");
    });
  });

  describe("validateQueryAgainstPolicy", () => {
    it("should validate safe queries against default policy", () => {
      const result = validateQueryAgainstPolicy("SELECT * FROM users");
      expect(result.isValid).toBe(true);
      expect(result.violations).toHaveLength(0);
    });

    it("should reject dangerous operations not in allowed list", () => {
      const result = validateQueryAgainstPolicy("DELETE FROM users", [
        "SELECT",
      ]);
      expect(result.isValid).toBe(false);
      expect(result.violations.some((v) => v.includes("DELETE"))).toBe(true);
    });
    it("should reject critical security threats", () => {
      const result = validateQueryAgainstPolicy(
        "SELECT * FROM users WHERE id = 1' OR 1=1",
      );
      expect(result.isValid).toBe(false);
      expect(result.violations.some((v) => v.includes("Critical"))).toBe(true);
    });

    it("should reject SQL injection patterns", () => {
      const result = validateQueryAgainstPolicy(
        "SELECT * FROM users UNION SELECT * FROM passwords",
      );
      expect(result.isValid).toBe(false);
      expect(result.violations.some((v) => v.includes("injection"))).toBe(true);
    });
  });

  describe("isQuerySafe", () => {
    it("should return true for safe queries", () => {
      expect(isQuerySafe("SELECT * FROM users")).toBe(true);
      expect(isQuerySafe("EXPLAIN SELECT * FROM users")).toBe(true);
      expect(isQuerySafe("DESCRIBE users")).toBe(true);
    });
    it("should return false for dangerous queries", () => {
      expect(isQuerySafe("DROP DATABASE production")).toBe(false);
      expect(isQuerySafe("SELECT * FROM users WHERE id = 1' OR 1=1")).toBe(
        false,
      );
      expect(isQuerySafe("DELETE FROM users")).toBe(false);
    });
  });

  describe("getQuerySecuritySummary", () => {
    it("should provide appropriate summaries for different query types", () => {
      expect(getQuerySecuritySummary("SELECT * FROM users")).toContain("Safe");
      expect(getQuerySecuritySummary("DELETE FROM users")).toContain(
        "high-risk",
      );
      expect(getQuerySecuritySummary("DROP TABLE users")).toContain("critical");
      expect(getQuerySecuritySummary("")).toContain("Safe read-only query");
    });
    it("should count threats correctly", () => {
      const summary = getQuerySecuritySummary(
        "DELETE FROM users; DROP TABLE users",
      );
      expect(summary).toContain("critical");
      expect(summary).toContain("high-risk");
    });
  });

  describe("createSafetyChecker", () => {
    it("should create a new SQLQuerySafetyChecker instance", () => {
      const newChecker = createSafetyChecker();
      expect(newChecker).toBeInstanceOf(SQLQuerySafetyChecker);
      expect(newChecker.isSafe("SELECT * FROM users")).toBe(true);
    });
  });

  describe("Edge cases and error handling", () => {
    it("should handle null and undefined queries", () => {
      expect(() => analyzeQuerySecurity(null as any)).not.toThrow();
      expect(() => analyzeQuerySecurity(undefined as any)).not.toThrow();

      const nullResult = analyzeQuerySecurity(null as any);
      expect(nullResult.securityLevel).toBe(SecurityLevel.SAFE);
    });

    it("should handle queries with only whitespace", () => {
      const result = analyzeQuerySecurity("   \n\t   ");
      expect(result.securityLevel).toBe(SecurityLevel.SAFE);
      expect(result.isSelectOnly).toBe(true);
    });

    it("should handle queries with only comments", () => {
      const result = analyzeQuerySecurity("/* This is just a comment */");
      expect(result.securityLevel).toBe(SecurityLevel.SAFE);
      expect(result.isSelectOnly).toBe(true);
    });

    it("should handle complex multi-line queries", () => {
      const complexQuery = `
				WITH user_stats AS (
					SELECT user_id, COUNT(*) as post_count
					FROM posts
					GROUP BY user_id
				)
				SELECT u.name, us.post_count
				FROM users u
				JOIN user_stats us ON u.id = us.user_id
				WHERE us.post_count > 10
			`;
      const result = analyzeQuerySecurity(complexQuery);
      expect(result.securityLevel).toBe(SecurityLevel.SAFE);
      expect(result.isSelectOnly).toBe(true);
    });

    it("should handle case-insensitive SQL keywords", () => {
      const upperResult = analyzeQuerySecurity("DELETE FROM USERS");
      const lowerResult = analyzeQuerySecurity("delete from users");
      const mixedResult = analyzeQuerySecurity("Delete From Users");

      expect(upperResult.securityLevel).toBe(SecurityLevel.HIGH_RISK);
      expect(lowerResult.securityLevel).toBe(SecurityLevel.HIGH_RISK);
      expect(mixedResult.securityLevel).toBe(SecurityLevel.HIGH_RISK);
    });

    it("should reset regex lastIndex to avoid state issues", () => {
      // Test multiple calls to ensure regex patterns don't maintain state
      const query = "DELETE FROM users";
      const result1 = analyzeQuerySecurity(query);
      const result2 = analyzeQuerySecurity(query);
      const result3 = analyzeQuerySecurity(query);

      expect(result1.threats).toHaveLength(result2.threats.length);
      expect(result2.threats).toHaveLength(result3.threats.length);
    });
  });

  describe("Performance tests", () => {
    it("should handle large queries efficiently", () => {
      const largeQuery =
        "SELECT * FROM users WHERE " +
        Array(100).fill("id = 1").join(" AND ") +
        " OR id = 999";

      const startTime = Date.now();
      const result = analyzeQuerySecurity(largeQuery);
      const endTime = Date.now();

      expect(endTime - startTime).toBeLessThan(1000); // Should complete within 1 second
      expect(result).toBeDefined(); // Just ensure it completes
    });

    it("should handle multiple threat detection efficiently", () => {
      const multiThreatQuery = `
				DROP TABLE users; 
				DELETE FROM posts; 
				UPDATE settings SET value = 'hacked' WHERE 1=1; 
				GRANT ALL ON *.* TO 'hacker'@'%';
			`;

      const startTime = Date.now();
      const result = analyzeQuerySecurity(multiThreatQuery);
      const endTime = Date.now();

      expect(endTime - startTime).toBeLessThan(500); // Should complete within 500ms
      expect(result.threats.length).toBeGreaterThan(3);
      expect(result.securityLevel).toBe(SecurityLevel.CRITICAL);
    });
  });
});
