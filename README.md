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

### Express Middleware

The library includes Express middleware for automatic SQL query validation in web applications. The middleware intercepts requests, analyzes SQL queries, and blocks dangerous operations before they reach your database.

#### Basic Usage

```typescript
import express from "express";
import { sqlSafetyMiddleware } from "sql-query-safety-checker";

const app = express();
app.use(express.json());

// Apply SQL safety middleware globally
app.use(sqlSafetyMiddleware());

app.post("/query", (req, res) => {
  // Query has been validated, req.sqlAnalysis contains the analysis
  console.log("Security Analysis:", req.sqlAnalysis);
  res.json({ 
    message: "Query is safe to execute",
    securityLevel: req.sqlAnalysis.securityLevel,
    threats: req.sqlAnalysis.threats.length
  });
});

// Test with: POST /query { "query": "SELECT * FROM users WHERE id = 1" }
```

#### Route-Specific Protection

```typescript
import express from "express";
import { sqlSafetyMiddleware, sqlSafetyPresets } from "sql-query-safety-checker";

const app = express();
app.use(express.json());

// Different security levels for different endpoints
app.post("/admin/query", 
  sqlSafetyMiddleware(sqlSafetyPresets.permissive()),
  (req, res) => {
    // Admin endpoint with more permissive rules
    res.json({ message: "Admin query executed", analysis: req.sqlAnalysis });
  }
);

app.post("/public/search", 
  sqlSafetyMiddleware(sqlSafetyPresets.readOnly()),
  (req, res) => {
    // Public endpoint with strict read-only access
    res.json({ results: [], analysis: req.sqlAnalysis });
  }
);

app.post("/api/reports", 
  sqlSafetyMiddleware(sqlSafetyPresets.moderate()),
  (req, res) => {
    // Reporting endpoint allowing data modifications
    res.json({ report: "generated", analysis: req.sqlAnalysis });
  }
);
```

#### Preset Configurations

The library provides several pre-configured security presets for common scenarios:

```typescript
import {
  sqlSafetyMiddleware,
  sqlSafetyPresets,
} from "sql-query-safety-checker";

// 1. Read-only mode - only SELECT, WITH, EXPLAIN, DESCRIBE, SHOW queries allowed
app.use("/readonly", sqlSafetyMiddleware(sqlSafetyPresets.readOnly()));
// Example safe queries: SELECT * FROM users, EXPLAIN SELECT * FROM orders
// Example blocked queries: INSERT, UPDATE, DELETE, DROP, CREATE

// 2. Moderate security - allows data modifications but blocks structure changes
app.use("/moderate", sqlSafetyMiddleware(sqlSafetyPresets.moderate()));
// Allows: SELECT, INSERT, UPDATE, DELETE, WITH, EXPLAIN, DESCRIBE, SHOW
// Blocks: DROP, CREATE, ALTER, TRUNCATE, administrative commands

// 3. Permissive security - allows most operations but blocks injections
app.use("/permissive", sqlSafetyMiddleware(sqlSafetyPresets.permissive()));
// Allows most operations up to HIGH_RISK level
// Still blocks SQL injection patterns and CRITICAL level operations

// 4. Development mode - logs everything but doesn't block execution
app.use("/dev", sqlSafetyMiddleware(sqlSafetyPresets.development()));
// Logs all security issues but continues execution
// Perfect for development and testing environments
```

#### Advanced Custom Configuration

```typescript
import { sqlSafetyMiddleware, SecurityLevel } from "sql-query-safety-checker";

const customOptions = {
  maxRiskLevel: SecurityLevel.MEDIUM_RISK,
  allowedOperations: ["SELECT", "INSERT", "UPDATE"],
  blockInjectionPatterns: true,
  enableLogging: true,
  
  // Custom query extraction from different request formats
  extractQuery: (req) => {
    // Support multiple query formats
    if (req.body.sqlQuery) return req.body.sqlQuery;
    if (req.body.queries) return req.body.queries; // Multiple queries
    if (req.query.q) return req.query.q; // URL parameter
    return req.body.query; // Default
  },
  
  // Custom error handler with detailed logging
  onError: (error, req, res, next) => {
    console.error("SQL Security Violation:", {
      ip: req.ip,
      userAgent: req.get('User-Agent'),
      query: error.query.substring(0, 200),
      threats: error.analysis.threats,
      timestamp: new Date().toISOString()
    });
    
    res.status(403).json({
      error: "SQL Query Rejected",
      reason: error.message,
      securityLevel: error.analysis.securityLevel,
      suggestions: error.analysis.recommendations,
      requestId: req.headers['x-request-id']
    });
  },
  
  // Custom warning handler for medium-risk operations
  onWarning: (warning, req, res, next) => {
    console.warn("SQL Security Warning:", {
      message: warning.message,
      query: warning.query.substring(0, 100),
      userAgent: req.get('User-Agent'),
      timestamp: new Date().toISOString()
    });
    
    // Add warning header but continue execution
    res.setHeader('X-SQL-Security-Warning', warning.message);
    next();
  }
};

app.use("/api", sqlSafetyMiddleware(customOptions));
```

#### Multiple Query Support

```typescript
import { sqlSafetyMiddleware } from "sql-query-safety-checker";

app.use(sqlSafetyMiddleware({
  extractQuery: (req) => req.body.queries, // Array of queries
  enableLogging: true
}));

app.post("/batch", (req, res) => {
  // Handle multiple queries
  // req.sqlAnalysis will be an array of analyses
  const analyses = Array.isArray(req.sqlAnalysis) ? req.sqlAnalysis : [req.sqlAnalysis];
  
  const summary = analyses.map(analysis => ({
    securityLevel: analysis.securityLevel,
    threatCount: analysis.threats.length,
    isReadOnly: analysis.isSelectOnly
  }));
  
  res.json({ 
    message: "Batch queries analyzed",
    queryCount: analyses.length,
    summary 
  });
});

// Test with: POST /batch { "queries": ["SELECT * FROM users", "INSERT INTO logs VALUES (1)"] }
```

#### Secure Router Factory

```typescript
import { createSecureRouter, sqlSafetyPresets } from "sql-query-safety-checker";

// Create different routers with built-in SQL safety
const adminRouter = createSecureRouter(sqlSafetyPresets.permissive());
const publicRouter = createSecureRouter(sqlSafetyPresets.readOnly());
const apiRouter = createSecureRouter({
  maxRiskLevel: SecurityLevel.MEDIUM_RISK,
  enableLogging: true,
  onError: (error, req, res, next) => {
    res.status(400).json({
      error: "Query blocked",
      details: error.analysis.recommendations
    });
  }
});

// Admin routes - more permissive
adminRouter.post("/execute", (req, res) => {
  res.json({ 
    message: "Admin query executed",
    analysis: req.sqlAnalysis 
  });
});

// Public routes - read-only
publicRouter.post("/search", (req, res) => {
  res.json({ 
    results: [],
    securityCheck: req.sqlAnalysis.securityLevel
  });
});

// API routes - custom configuration
apiRouter.post("/data", (req, res) => {
  res.json({
    processed: true,
    threats: req.sqlAnalysis.threats.length
  });
});

app.use("/admin", adminRouter);
app.use("/public", publicRouter);
app.use("/api/v1", apiRouter);
```

#### Error Handling Examples

```typescript
import { sqlSafetyMiddleware, SecurityLevel } from "sql-query-safety-checker";

// Production error handler - minimal information disclosure
const productionErrorHandler = (error, req, res, next) => {
  // Log detailed error internally
  console.error("Security violation:", {
    timestamp: new Date().toISOString(),
    ip: req.ip,
    userAgent: req.get('User-Agent'),
    error: error.message,
    query: error.query
  });
  
  // Send minimal response to client
  res.status(403).json({
    error: "Query not allowed",
    code: "SQL_SECURITY_VIOLATION"
  });
};

// Development error handler - detailed information
const developmentErrorHandler = (error, req, res, next) => {
  res.status(403).json({
    error: "SQL Security Violation",
    message: error.message,
    query: error.query,
    securityLevel: error.analysis.securityLevel,
    threats: error.analysis.threats,
    recommendations: error.analysis.recommendations,
    debug: {
      timestamp: new Date().toISOString(),
      userAgent: req.get('User-Agent')
    }
  });
};

// Apply different error handlers based on environment
const errorHandler = process.env.NODE_ENV === 'production' 
  ? productionErrorHandler 
  : developmentErrorHandler;

app.use(sqlSafetyMiddleware({
  maxRiskLevel: SecurityLevel.MEDIUM_RISK,
  onError: errorHandler
}));
```

#### Integration with Authentication

```typescript
import jwt from 'jsonwebtoken';
import { sqlSafetyMiddleware, SecurityLevel } from "sql-query-safety-checker";

// Role-based SQL security
const roleBasedSqlSecurity = (req, res, next) => {
  const token = req.headers.authorization?.replace('Bearer ', '');
  const user = jwt.verify(token, process.env.JWT_SECRET);
  
  let securityConfig;
  
  switch (user.role) {
    case 'admin':
      securityConfig = {
        maxRiskLevel: SecurityLevel.HIGH_RISK,
        allowedOperations: ['SELECT', 'INSERT', 'UPDATE', 'DELETE', 'CREATE', 'ALTER']
      };
      break;
    case 'editor':
      securityConfig = {
        maxRiskLevel: SecurityLevel.MEDIUM_RISK,
        allowedOperations: ['SELECT', 'INSERT', 'UPDATE', 'DELETE']
      };
      break;
    default: // 'viewer'
      securityConfig = {
        maxRiskLevel: SecurityLevel.LOW_RISK,
        allowedOperations: ['SELECT', 'EXPLAIN', 'DESCRIBE']
      };
  }
  
  sqlSafetyMiddleware(securityConfig)(req, res, next);
};

app.use("/protected", roleBasedSqlSecurity);
```

### Middleware Options

```typescript
interface SQLSafetyMiddlewareOptions {
  maxRiskLevel?: SecurityLevel; // Maximum allowed risk level
  blockInjectionPatterns?: boolean; // Block injection patterns (default: true)
  allowedOperations?: string[]; // Allowed SQL operations
  onError?: (error, req, res, next) => void; // Custom error handler
  onWarning?: (warning, req, res, next) => void; // Custom warning handler
  extractQuery?: (req) => string | string[]; // Custom query extractor
  enableLogging?: boolean; // Enable security logging
  attachAnalysis?: boolean; // Attach analysis to request (default: true)
}
```

Determines if a query requires user confirmation before execution.

```typescript
const confirmation = needsConfirmation("UPDATE users SET status = 'active'");
console.log(confirmation);
// {
//   required: true,
//   level: "medium_risk",
//   reason: "Query contains data modification operations"
// }
```

#### `validateQueryAgainstPolicy(query: string, allowedOperations: string[]): PolicyValidationResult`

Validates a query against a security policy.

```typescript
const policy = ["SELECT", "WITH", "EXPLAIN"];
const validation = validateQueryAgainstPolicy(
  "INSERT INTO logs VALUES (1)",
  policy,
);
console.log(validation);
// {
//   isValid: false,
//   violations: ["Operation 'INSERT' is not allowed by current security policy"],
//   analysis: {...}
// }
```

#### `getSecurityLevelColor(level: SecurityLevel): string`

Returns color codes for UI display of security levels.

```typescript
console.log(getSecurityLevelColor(SecurityLevel.CRITICAL)); // "#9c27b0"
console.log(getSecurityLevelColor(SecurityLevel.SAFE)); // "#4caf50"
```

#### `getQuerySecuritySummary(query: string): string`

Gets a human-readable security summary.

```typescript
const summary = getQuerySecuritySummary("DROP TABLE users; DELETE FROM logs;");
console.log(summary); // "2 critical threat(s)"
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
