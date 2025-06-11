import { describe, it, expect } from "bun:test";
import { analyzeQuerySecurity, SecurityLevel } from "../index";
import "./setup"; // Import custom matchers

describe("Database Operations Security Tests", () => {
  describe("Data Definition Language (DDL)", () => {
    it("should detect CREATE operations as high risk", () => {
      const queries = [
        "CREATE TABLE users (id INT, name VARCHAR(50))",
        "CREATE INDEX idx_user_name ON users(name)",
        "CREATE VIEW active_users AS SELECT * FROM users WHERE active = 1",
        "CREATE DATABASE test_db",
      ];

      queries.forEach((query) => {
        const result = analyzeQuerySecurity(query);
        expect(result.securityLevel).toBeOneOf([
          SecurityLevel.HIGH_RISK,
          SecurityLevel.CRITICAL,
        ]);
        expect(result.threats.some((t) => t.category === "DDL")).toBe(true);
      });
    });

    it("should detect ALTER operations as high risk", () => {
      const queries = [
        "ALTER TABLE users ADD COLUMN email VARCHAR(100)",
        "ALTER TABLE users DROP COLUMN password",
        "ALTER DATABASE test_db CHARACTER SET utf8",
      ];

      queries.forEach((query) => {
        const result = analyzeQuerySecurity(query);
        expect(result.securityLevel).toBeOneOf([
          SecurityLevel.HIGH_RISK,
          SecurityLevel.CRITICAL,
        ]);
        expect(result.threats.some((t) => t.category === "DDL")).toBe(true);
      });
    });

    it("should detect DROP operations as critical", () => {
      const queries = [
        "DROP TABLE users",
        "DROP DATABASE production",
        "DROP INDEX idx_user_name",
        "DROP VIEW user_stats",
      ];

      queries.forEach((query) => {
        const result = analyzeQuerySecurity(query);
        expect(result.securityLevel).toBe(SecurityLevel.CRITICAL);
        expect(result.threats.some((t) => t.category === "DDL")).toBe(true);
      });
    });

    it("should detect TRUNCATE operations as high risk", () => {
      const result = analyzeQuerySecurity("TRUNCATE TABLE users");
      expect(result.securityLevel).toBe(SecurityLevel.HIGH_RISK);
      expect(result.threats.some((t) => t.name === "TRUNCATE")).toBe(true);
    });
  });

  describe("Data Manipulation Language (DML)", () => {
    it("should detect INSERT operations as medium risk", () => {
      const queries = [
        "INSERT INTO users (name, email) VALUES ('John', 'john@example.com')",
        "INSERT INTO logs SELECT * FROM temp_logs",
      ];

      queries.forEach((query) => {
        const result = analyzeQuerySecurity(query);
        expect(result.securityLevel).toBe(SecurityLevel.MEDIUM_RISK);
        expect(result.threats.some((t) => t.name === "INSERT")).toBe(true);
      });
    });

    it("should detect UPDATE operations as medium risk", () => {
      const queries = [
        "UPDATE users SET email = 'new@example.com' WHERE id = 1",
        "UPDATE products SET price = price * 1.1",
      ];

      queries.forEach((query) => {
        const result = analyzeQuerySecurity(query);
        expect(result.securityLevel).toBe(SecurityLevel.MEDIUM_RISK);
        expect(result.threats.some((t) => t.name === "UPDATE")).toBe(true);
      });
    });

    it("should detect DELETE operations as high risk", () => {
      const queries = [
        "DELETE FROM users WHERE id = 1",
        "DELETE FROM logs WHERE created_at < '2023-01-01'",
      ];

      queries.forEach((query) => {
        const result = analyzeQuerySecurity(query);
        expect(result.securityLevel).toBe(SecurityLevel.HIGH_RISK);
        expect(result.threats.some((t) => t.name === "DELETE")).toBe(true);
      });
    });

    it("should detect REPLACE operations as medium risk", () => {
      const result = analyzeQuerySecurity(
        "REPLACE INTO users (id, name) VALUES (1, 'John')",
      );
      expect(result.securityLevel).toBe(SecurityLevel.MEDIUM_RISK);
      expect(result.threats.some((t) => t.name === "REPLACE")).toBe(true);
    });
  });
  describe("Data Control Language (DCL)", () => {
    it("should detect GRANT operations as critical", () => {
      const queries = [
        "GRANT ALL PRIVILEGES ON database.* TO 'user'@'localhost'",
        "GRANT SELECT, INSERT ON users TO 'app_user'@'%'",
      ];

      queries.forEach((query) => {
        const result = analyzeQuerySecurity(query);
        expect(result.securityLevel).toBe(SecurityLevel.CRITICAL);
        expect(result.threats.some((t) => t.name === "PERMISSIONS")).toBe(true);
      });
    });

    it("should detect REVOKE operations as critical", () => {
      const result = analyzeQuerySecurity(
        "REVOKE ALL PRIVILEGES ON *.* FROM 'user'@'localhost'",
      );
      expect(result.securityLevel).toBe(SecurityLevel.CRITICAL);
      expect(result.threats.some((t) => t.name === "PERMISSIONS")).toBe(true);
    });
  });
  describe("Administrative Operations", () => {
    it("should detect backup/restore operations as critical", () => {
      const queries = [
        "BACKUP DATABASE mydb TO DISK = 'backup.bak'",
        "RESTORE DATABASE mydb FROM DISK = 'backup.bak'",
      ];

      queries.forEach((query) => {
        const result = analyzeQuerySecurity(query);
        expect(result.securityLevel).toBe(SecurityLevel.CRITICAL);
        expect(result.threats.some((t) => t.category === "ADMIN")).toBe(true);
      });
    });

    it("should detect system operations as critical", () => {
      const queries = [
        "EXEC xp_cmdshell 'dir'",
        "SELECT * FROM OPENROWSET('SQLNCLI', 'connection_string', 'query')",
      ];

      queries.forEach((query) => {
        const result = analyzeQuerySecurity(query);
        expect(result.securityLevel).toBe(SecurityLevel.CRITICAL);
        expect(result.threats.some((t) => t.category === "SYSTEM")).toBe(true);
      });
    });
  });

  describe("Transaction Control", () => {
    it("should detect transaction operations as low to medium risk", () => {
      const queries = [
        "BEGIN TRANSACTION",
        "COMMIT",
        "ROLLBACK",
        "SAVEPOINT sp1",
      ];

      queries.forEach((query) => {
        const result = analyzeQuerySecurity(query);
        // These should be detected but with lower risk levels
        expect(result.securityLevel).toBeOneOf([
          SecurityLevel.SAFE,
          SecurityLevel.LOW_RISK,
          SecurityLevel.MEDIUM_RISK,
        ]);
      });
    });
  });

  describe("Safe Operations", () => {
    it("should classify SELECT operations as safe", () => {
      const queries = [
        "SELECT * FROM users",
        "SELECT COUNT(*) FROM products",
        "SELECT u.name, p.title FROM users u JOIN posts p ON u.id = p.user_id",
      ];

      queries.forEach((query) => {
        const result = analyzeQuerySecurity(query);
        expect(result.securityLevel).toBe(SecurityLevel.SAFE);
        expect(result.isSelectOnly).toBe(true);
        expect(result.allowExecution).toBe(true);
      });
    });

    it("should classify utility operations as safe", () => {
      const queries = [
        "EXPLAIN SELECT * FROM users",
        "DESCRIBE users",
        "DESC products",
        "SHOW TABLES",
        "SHOW COLUMNS FROM users",
      ];

      queries.forEach((query) => {
        const result = analyzeQuerySecurity(query);
        expect(result.securityLevel).toBe(SecurityLevel.SAFE);
        expect(result.isSelectOnly).toBe(true);
      });
    });

    it("should handle CTE (Common Table Expressions) as safe", () => {
      const query = `
				WITH user_stats AS (
					SELECT user_id, COUNT(*) as post_count
					FROM posts
					GROUP BY user_id
				)
				SELECT u.name, us.post_count
				FROM users u
				JOIN user_stats us ON u.id = us.user_id
			`;

      const result = analyzeQuerySecurity(query);
      expect(result.securityLevel).toBe(SecurityLevel.SAFE);
      expect(result.isSelectOnly).toBe(true);
    });
  });
});
