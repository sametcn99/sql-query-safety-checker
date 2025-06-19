# SQL Query Safety Checker

[![npm version](https://badge.fury.io/js/sql-query-safety-checker.svg)](https://badge.fury.io/js/sql-query-safety-checker)
[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)
[![TypeScript](https://img.shields.io/badge/TypeScript-Ready-blue.svg)](https://www.typescriptlang.org/)

A comprehensive TypeScript library for analyzing SQL queries and detecting potential security threats, including SQL injection patterns, dangerous operations, and data modification commands. Perfect for applications that need to validate user-provided SQL queries before execution.

## 🚀 Features

- **🔍 SQL Injection Detection**: Identifies common SQL injection patterns including UNION attacks, boolean-based injections, and comment-based evasion
- **⚠️ Risk Assessment**: Categorizes operations by security level (Safe, Low Risk, Medium Risk, High Risk, Critical)
- **📊 Comprehensive Analysis**: Detailed threat analysis with descriptions and recommendations
- **🛡️ Policy Validation**: Validate queries against custom security policies
- **🎯 Operation Categorization**: Classifies operations into DML, DDL, DCL, Administrative, and System categories
- **✅ Read-Only Detection**: Identifies safe SELECT-only queries
- **💡 Smart Recommendations**: Provides context-aware security recommendations
- **🎨 UI-Ready**: Includes color codes for security levels for easy UI integration
- **📝 TypeScript Support**: Full TypeScript definitions included

## 📦 Installation

```bash
# Using npm
npm install sql-query-safety-checker

# Using yarn
yarn add sql-query-safety-checker

# Using bun
bun add sql-query-safety-checker
```

## 🔧 Quick Start

### Basic Usage

```typescript
import {
  SQLQuerySafetyChecker,
  analyzeQuerySecurity,
} from "sql-query-safety-checker";

// Create a checker instance
const checker = new SQLQuerySafetyChecker();

// Analyze a query
const query = "SELECT * FROM users WHERE id = 1";
const analysis = checker.analyzeQuery(query);

console.log("Security Level:", analysis.securityLevel);
console.log("Is Dangerous:", analysis.isDangerous);
console.log("Is Read-Only:", analysis.isSelectOnly);
console.log("Threats:", analysis.threats);
console.log("Recommendations:", analysis.recommendations);
```

### Quick Safety Check

```typescript
import { isQuerySafe } from "sql-query-safety-checker";

const safeQuery = "SELECT name, email FROM users";
const dangerousQuery = "DROP TABLE users";

console.log("Safe query:", isQuerySafe(safeQuery)); // true
console.log("Dangerous query:", isQuerySafe(dangerousQuery)); // false
```

## 📚 API Reference

### Core Classes

#### `SQLQuerySafetyChecker`

The main class for analyzing SQL queries.

```typescript
const checker = new SQLQuerySafetyChecker();
```

**Methods:**

- `analyzeQuery(query: string): QueryAnalysis` - Complete security analysis
- `checkQuerySafety(query: string): QuerySafetyResult` - Basic safety check
- `isSelectOnlyQuery(query: string): boolean` - Check if query is read-only
- `requiresConfirmation(query: string): ConfirmationResult` - Check if user confirmation needed
- `validateAgainstPolicy(query: string, policy: SecurityPolicy): PolicyValidationResult` - Validate against policy
- `getSecuritySummary(query: string): string` - Get human-readable summary
- `isSafe(query: string): boolean` - Quick safety check

### Security Levels

```typescript
enum SecurityLevel {
  SAFE = "safe",
  LOW_RISK = "low_risk",
  MEDIUM_RISK = "medium_risk",
  HIGH_RISK = "high_risk",
  CRITICAL = "critical",
}
```

### Utility Functions

#### `analyzeQuerySecurity(query: string): QueryAnalysis`

Performs comprehensive security analysis of a SQL query.

```typescript
const analysis = analyzeQuerySecurity("DELETE FROM users WHERE id = 1");
console.log(analysis);
// {
//   securityLevel: "high_risk",
//   isDangerous: true,
//   isSelectOnly: false,
//   threats: [
//     {
//       name: "DELETE",
//       description: "Data deletion operation",
//       level: "high_risk",
//       category: "DML"
//     }
//   ],
//   recommendations: [...],
//   allowExecution: false
// }
```

#### `needsConfirmation(query: string): ConfirmationResult`

Checks if a query needs user confirmation before execution.

```typescript
const confirmation = needsConfirmation("DELETE FROM users WHERE id = 1");
console.log(confirmation);
// {
//   required: true,
//   level: "high_risk",
//   reason: "Query contains high-risk operations..."
// }
```

## 🛡️ Security Categories

The library categorizes SQL operations into different security categories:

- **DML (Data Manipulation Language)**: INSERT, UPDATE, DELETE, MERGE operations
- **DDL (Data Definition Language)**: CREATE, ALTER, DROP, TRUNCATE operations
- **DCL (Data Control Language)**: GRANT, REVOKE operations
- **INJECTION**: SQL injection patterns and suspicious constructs
- **ADMIN**: Administrative operations like BACKUP, RESTORE
- **SYSTEM**: System-level operations that could compromise security

## 🔍 Detection Patterns

### SQL Injection Detection

The library detects various SQL injection patterns:

```typescript
// Union-based injection
"SELECT * FROM users UNION SELECT password FROM admin";

// Boolean-based injection
"SELECT * FROM users WHERE id = 1 OR 1=1";

// Time-based injection
"SELECT * FROM users WHERE id = 1; WAITFOR DELAY '00:00:05'";

// Comment-based evasion
"SELECT * FROM users WHERE id = 1 /* comment */ OR 1=1";
```

### Dangerous Operations

```typescript
// Critical operations
"DROP TABLE users";
"EXEC xp_cmdshell 'format c:'";
"GRANT ALL PRIVILEGES TO 'user'@'%'";

// High-risk operations
"DELETE FROM users";
"CREATE TABLE sensitive_data";
"ALTER TABLE users DROP COLUMN password";

// Medium-risk operations
"INSERT INTO logs VALUES (1, 'action')";
"UPDATE users SET last_login = NOW()";
```

## 🎯 Use Cases

### 1. Query Validation Before Execution

```typescript
import { SQLQuerySafetyChecker } from "sql-query-safety-checker";

const checker = new SQLQuerySafetyChecker();

function executeQuery(sql: string) {
  const analysis = checker.analyzeQuery(sql);

  if (!analysis.allowExecution) {
    throw new Error(`Query rejected: ${analysis.recommendations.join(", ")}`);
  }

  if (analysis.securityLevel === "critical") {
    throw new Error("Critical security threat detected");
  }

  // Safe to execute
  return database.query(sql);
}
```

### 2. User Interface Integration

```typescript
import {
  analyzeQuerySecurity,
  getSecurityLevelColor,
} from "sql-query-safety-checker";

function displayQueryAnalysis(query: string) {
  const analysis = analyzeQuerySecurity(query);
  const color = getSecurityLevelColor(analysis.securityLevel);

  return {
    level: analysis.securityLevel,
    color: color,
    warnings: analysis.threats.map((t) => t.description),
    recommendations: analysis.recommendations,
    canExecute: analysis.allowExecution,
  };
}
```

### 3. Policy Enforcement

```typescript
import { validateQueryAgainstPolicy } from "sql-query-safety-checker";

const readOnlyPolicy = {
  allowedOperations: ["SELECT", "WITH", "EXPLAIN", "DESCRIBE", "SHOW"],
  maxRiskLevel: "low_risk",
  blockInjectionPatterns: true,
  requireConfirmationFor: ["medium_risk", "high_risk"],
};

function enforcePolicy(query: string) {
  const validation = validateQueryAgainstPolicy(
    query,
    readOnlyPolicy.allowedOperations,
  );

  if (!validation.isValid) {
    console.error("Policy violations:", validation.violations);
    return false;
  }

  return true;
}
```

### 4. Security Monitoring

```typescript
import { analyzeQuerySecurity } from "sql-query-safety-checker";

function logSecurityEvents(query: string, userId: string) {
  const analysis = analyzeQuerySecurity(query);

  if (analysis.threats.length > 0) {
    console.warn("Security threat detected:", {
      userId,
      query: query.substring(0, 100), // Log first 100 chars
      threats: analysis.threats,
      securityLevel: analysis.securityLevel,
    });
  }
}
```

## 🧪 Testing

The library includes comprehensive tests covering various scenarios:

```bash
# Run tests
bun test

# Run specific test file
bun test injection.test.ts
```

Test categories:

- Basic functionality tests
- SQL injection detection tests
- Security policy validation tests
- Performance benchmarks
- Edge cases and malformed queries

## 🔧 Configuration

### Custom Security Policies

You can define custom security policies for different environments:

```typescript
// Development environment - more permissive
const devPolicy = {
  allowedOperations: ["SELECT", "INSERT", "UPDATE", "CREATE", "DROP"],
  maxRiskLevel: "high_risk",
  blockInjectionPatterns: true,
  requireConfirmationFor: ["critical"],
};

// Production environment - restrictive
const prodPolicy = {
  allowedOperations: ["SELECT", "WITH", "EXPLAIN"],
  maxRiskLevel: "low_risk",
  blockInjectionPatterns: true,
  requireConfirmationFor: ["medium_risk", "high_risk", "critical"],
};
```

## ⚡ Performance

The library is optimized for performance:

- **Fast Analysis**: Typical query analysis completes in <1ms
- **Memory Efficient**: Minimal memory footprint
- **RegExp Optimization**: Efficient pattern matching with proper regex handling
- **No Dependencies**: Zero external dependencies for maximum compatibility

## 🤝 Contributing

Contributions are welcome! Please read our contributing guidelines and submit pull requests to our GitHub repository.

### Development Setup

```bash
# Clone the repository
git clone https://github.com/sametcn99/sql-query-safety-checker.git

# Install dependencies
bun install

# Run tests
bun test

# Build the project
bun run build

# Watch mode for development
bun run dev
```

## 📄 License

This project is licensed under the GPL-3.0 License - see the [LICENSE](LICENSE) file for details.

## 🔗 Links

- [GitHub Repository](https://github.com/sametcn99/sql-query-safety-checker)
- [npm Package](https://www.npmjs.com/package/sql-query-safety-checker)
- [Issue Tracker](https://github.com/sametcn99/sql-query-safety-checker/issues)

## 📈 Roadmap

- [ ] Support for more SQL dialects (PostgreSQL, MySQL, Oracle)
- [ ] Integration with popular ORMs
- [ ] Real-time query monitoring dashboard
- [ ] Custom threat pattern definitions

---

**⚠️ Security Notice**: This library helps identify potential security threats but should not be your only line of defense. Always use parameterized queries, proper input validation, and follow security best practices when working with databases.
