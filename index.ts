export enum SecurityLevel {
  SAFE = "safe",
  LOW_RISK = "low_risk",
  MEDIUM_RISK = "medium_risk",
  HIGH_RISK = "high_risk",
  CRITICAL = "critical",
}

export type SecurityThreat = {
  pattern: RegExp;
  name: string;
  description: string;
  level: SecurityLevel;
  category: "DML" | "DDL" | "DCL" | "INJECTION" | "ADMIN" | "SYSTEM";
};

export type QueryAnalysis = {
  securityLevel: SecurityLevel;
  isDangerous: boolean;
  isSelectOnly: boolean;
  threats: Array<{
    name: string;
    description: string;
    level: SecurityLevel;
    category: string;
  }>;
  recommendations: string[];
  allowExecution: boolean;
};

export type QuerySafetyResult = {
  isDangerous: boolean;
  dangerousOperations: string[];
  isSelectOnly: boolean;
};

export type ConfirmationResult = {
  required: boolean;
  level: SecurityLevel;
  reason: string;
};

export type PolicyValidationResult = {
  isValid: boolean;
  violations: string[];
  analysis: QueryAnalysis;
};

export type SecurityPolicy = {
  allowedOperations: string[];
  maxRiskLevel: SecurityLevel;
  blockInjectionPatterns: boolean;
  requireConfirmationFor: SecurityLevel[];
};

const SECURITY_THREATS: SecurityThreat[] = [
  // Data Manipulation Language (DML) - Medium to High Risk
  {
    pattern: /\b(DELETE|delete)\s+FROM\b/gi,
    name: "DELETE",
    description: "Data deletion operation",
    level: SecurityLevel.HIGH_RISK,
    category: "DML",
  },
  {
    pattern: /\b(UPDATE|update)\s+\w+\s+SET\b/gi,
    name: "UPDATE",
    description: "Data update operation",
    level: SecurityLevel.MEDIUM_RISK,
    category: "DML",
  },
  {
    pattern: /\b(INSERT|insert)\s+INTO\b/gi,
    name: "INSERT",
    description: "Data insertion operation",
    level: SecurityLevel.MEDIUM_RISK,
    category: "DML",
  },
  {
    pattern: /\b(REPLACE|replace)\s+INTO\b/gi,
    name: "REPLACE",
    description: "Data replacement operation",
    level: SecurityLevel.MEDIUM_RISK,
    category: "DML",
  },
  {
    pattern: /\b(MERGE|merge)\s+INTO\b/gi,
    name: "MERGE",
    description: "Data merge operation",
    level: SecurityLevel.MEDIUM_RISK,
    category: "DML",
  },
  {
    pattern: /\b(UPSERT|upsert)\b/gi,
    name: "UPSERT",
    description: "Data insert/update operation",
    level: SecurityLevel.MEDIUM_RISK,
    category: "DML",
  },

  // Data Definition Language (DDL) - High to Critical Risk
  {
    pattern:
      /\b(DROP|drop)\s+(TABLE|DATABASE|SCHEMA|INDEX|VIEW|TRIGGER|FUNCTION|PROCEDURE)\b/gi,
    name: "DROP",
    description: "Structure deletion operation",
    level: SecurityLevel.CRITICAL,
    category: "DDL",
  },
  {
    pattern:
      /\b(CREATE|create)\s+(TABLE|DATABASE|SCHEMA|INDEX|VIEW|TRIGGER|FUNCTION|PROCEDURE)\b/gi,
    name: "CREATE",
    description: "Structure creation operation",
    level: SecurityLevel.HIGH_RISK,
    category: "DDL",
  },
  {
    pattern: /\b(ALTER|alter)\s+(TABLE|DATABASE|SCHEMA|INDEX|VIEW)\b/gi,
    name: "ALTER",
    description: "Structure modification operation",
    level: SecurityLevel.HIGH_RISK,
    category: "DDL",
  },
  {
    pattern: /\b(TRUNCATE|truncate)\s+(TABLE)?\b/gi,
    name: "TRUNCATE",
    description: "Table content clearing operation",
    level: SecurityLevel.HIGH_RISK,
    category: "DDL",
  },

  // Data Control Language (DCL) - Critical Risk
  {
    pattern: /\b(GRANT|grant|REVOKE|revoke)\b/gi,
    name: "PERMISSIONS",
    description: "Permission modification operation",
    level: SecurityLevel.CRITICAL,
    category: "DCL",
  },

  // Administrative Commands - Critical Risk
  {
    pattern: /\b(SHUTDOWN|shutdown|RESTART|restart)\b/gi,
    name: "SERVER_CONTROL",
    description: "Server control operation",
    level: SecurityLevel.CRITICAL,
    category: "ADMIN",
  },
  {
    pattern: /\b(BACKUP|backup|RESTORE|restore)\b/gi,
    name: "BACKUP_RESTORE",
    description: "Backup/restore operation",
    level: SecurityLevel.CRITICAL,
    category: "ADMIN",
  },
  {
    pattern: /\b(LOAD\s+DATA|load\s+data)\b/gi,
    name: "LOAD_DATA",
    description: "Data loading operation",
    level: SecurityLevel.HIGH_RISK,
    category: "ADMIN",
  },

  // System Commands - Critical Risk
  {
    pattern: /\b(EXEC|exec|EXECUTE|execute)\s+(xp_|sp_cmdshell)/gi,
    name: "SYSTEM_EXEC",
    description: "System command execution",
    level: SecurityLevel.CRITICAL,
    category: "SYSTEM",
  },
  {
    pattern: /\b(OPENROWSET|openrowset|OPENDATASOURCE|opendatasource)\b/gi,
    name: "EXTERNAL_ACCESS",
    description: "External data source access",
    level: SecurityLevel.CRITICAL,
    category: "SYSTEM",
  },

  // SQL Injection Patterns - Critical Risk
  {
    pattern: /(;|\s)(DROP|drop)\s+(TABLE|DATABASE)/gi,
    name: "INJECTION_DROP",
    description: "Potential SQL injection with DROP command",
    level: SecurityLevel.CRITICAL,
    category: "INJECTION",
  },
  {
    pattern: /(\s|^)(UNION|union)\s+(ALL\s+)?(SELECT|select)/gi,
    name: "UNION_INJECTION",
    description: "Potential UNION-based SQL injection",
    level: SecurityLevel.CRITICAL,
    category: "INJECTION",
  },
  {
    pattern: /'(\s*)(OR|or|AND|and)(\s*)(\d+\s*=\s*\d+|'\s*=\s*')/gi,
    name: "BOOLEAN_INJECTION",
    description: "Potential boolean-based SQL injection",
    level: SecurityLevel.CRITICAL,
    category: "INJECTION",
  },
  {
    pattern: /(\/\*|\*\/|--|\||&)/g,
    name: "COMMENT_INJECTION",
    description: "Potential comment-based injection or evasion",
    level: SecurityLevel.HIGH_RISK,
    category: "INJECTION",
  },
  {
    pattern: /\b(WAITFOR|waitfor)\s+(DELAY|delay|TIME|time)/gi,
    name: "TIME_INJECTION",
    description: "Potential time-based SQL injection",
    level: SecurityLevel.CRITICAL,
    category: "INJECTION",
  },
];

// Safe operations that are allowed without warnings
const SAFE_OPERATIONS = [
  /^\s*(SELECT|select)\b/,
  /^\s*(WITH|with)\b/,
  /^\s*(EXPLAIN|explain)\b/,
  /^\s*(DESCRIBE|describe)\b/,
  /^\s*(DESC|desc)\b/,
  /^\s*(SHOW|show)\b/,
  /^\s*(PRAGMA|pragma)\b/,
];

/**
 * Normalizes a SQL query by removing comments and extra whitespace
 * @param query - Raw SQL query
 * @returns Cleaned query string
 */
const normalizeQuery = (query: string): string => {
  if (!query || typeof query !== "string") {
    return "";
  }

  return query
    .replace(/--[^\r\n]*/g, "") // Remove single line comments
    .replace(/\/\*[\s\S]*?\*\//g, "") // Remove multi-line comments
    .replace(/\s+/g, " ") // Normalize whitespace
    .trim();
};

/**
 * Checks if a query contains only safe read operations
 * @param query - Normalized SQL query
 * @returns true if query is read-only and safe
 */
const isReadOnlyQuery = (query: string): boolean => {
  if (!query) return true;

  return SAFE_OPERATIONS.some((pattern) => pattern.test(query));
};

/**
 * Generates security recommendations based on detected threats
 * @param threats - Array of detected security threats
 * @param isSelectOnly - Whether query is read-only
 * @returns Array of recommendation strings
 */
const generateRecommendations = (
  threats: QueryAnalysis["threats"],
  isSelectOnly: boolean,
): string[] => {
  const recommendations: string[] = [];

  if (isSelectOnly) {
    recommendations.push(
      "✅ Query appears to be read-only and safe to execute",
    );
    return recommendations;
  }

  if (threats.length === 0) {
    recommendations.push("✅ No obvious security threats detected");
    return recommendations;
  }

  // Category-specific recommendations
  const categories = [...new Set(threats.map((t) => t.category))];

  categories.forEach((category) => {
    switch (category) {
      case "DML":
        recommendations.push(
          "⚠️ Data modification detected - verify query intent and backup data if necessary",
        );
        break;
      case "DDL":
        recommendations.push(
          "🚨 Structure modification detected - this could permanently alter your database schema",
        );
        break;
      case "DCL":
        recommendations.push(
          "🚨 Permission changes detected - this could affect database security",
        );
        break;
      case "INJECTION":
        recommendations.push(
          "🚨 CRITICAL: Potential SQL injection pattern detected - DO NOT EXECUTE",
        );
        break;
      case "ADMIN":
        recommendations.push(
          "🚨 Administrative operation detected - requires elevated privileges",
        );
        break;
      case "SYSTEM":
        recommendations.push(
          "🚨 CRITICAL: System-level operation detected - could compromise server security",
        );
        break;
    }
  });

  // Critical threat recommendations
  const criticalThreats = threats.filter(
    (t) => t.level === SecurityLevel.CRITICAL,
  );
  if (criticalThreats.length > 0) {
    recommendations.push(
      "🛑 STOP: Critical security threats detected - manual review required",
    );
    recommendations.push(
      "💡 Consider using parameterized queries or stored procedures instead",
    );
  }

  // High risk recommendations
  const highRiskThreats = threats.filter(
    (t) => t.level === SecurityLevel.HIGH_RISK,
  );
  if (highRiskThreats.length > 0) {
    recommendations.push(
      "⚠️ High-risk operations detected - ensure you have proper backups",
    );
    recommendations.push("💡 Test on a development environment first");
  }

  return recommendations;
};

/**
 * Analyzes SQL query for security threats and provides comprehensive safety assessment
 * @param query - The SQL query to analyze
 * @returns Detailed security analysis
 */
export const analyzeQuerySecurity = (query: string): QueryAnalysis => {
  const cleanQuery = normalizeQuery(query);

  if (!cleanQuery) {
    return {
      securityLevel: SecurityLevel.SAFE,
      isDangerous: false,
      isSelectOnly: true,
      threats: [],
      recommendations: ["Query is empty or contains only comments"],
      allowExecution: true,
    };
  }

  const threats: QueryAnalysis["threats"] = [];
  let highestSecurityLevel = SecurityLevel.SAFE;

  // Check for security threats
  SECURITY_THREATS.forEach((threat) => {
    const matches = cleanQuery.match(threat.pattern);
    if (matches) {
      threats.push({
        name: threat.name,
        description: threat.description,
        level: threat.level,
        category: threat.category,
      });

      // Update highest security level
      const levels = [
        SecurityLevel.SAFE,
        SecurityLevel.LOW_RISK,
        SecurityLevel.MEDIUM_RISK,
        SecurityLevel.HIGH_RISK,
        SecurityLevel.CRITICAL,
      ];
      const currentIndex = levels.indexOf(threat.level);
      const highestIndex = levels.indexOf(highestSecurityLevel);
      if (currentIndex > highestIndex) {
        highestSecurityLevel = threat.level;
      }
    }
    // Reset regex lastIndex to avoid issues with global flags
    threat.pattern.lastIndex = 0;
  });

  const isSelectOnly = isReadOnlyQuery(cleanQuery) && threats.length === 0;
  const isDangerous = threats.length > 0;

  // Generate recommendations based on analysis
  const recommendations = generateRecommendations(threats, isSelectOnly);

  // Determine if execution should be allowed
  const allowExecution =
    highestSecurityLevel === SecurityLevel.SAFE ||
    highestSecurityLevel === SecurityLevel.LOW_RISK ||
    isSelectOnly;

  return {
    securityLevel: highestSecurityLevel,
    isDangerous,
    isSelectOnly,
    threats,
    recommendations,
    allowExecution,
  };
};

/**
 * Enhanced function to check if query needs user confirmation
 * @param query - The SQL query to check
 * @returns Object with confirmation details
 */
export const needsConfirmation = (query: string): ConfirmationResult => {
  const analysis = analyzeQuerySecurity(query);

  if (analysis.securityLevel === SecurityLevel.SAFE || analysis.isSelectOnly) {
    return {
      required: false,
      level: SecurityLevel.SAFE,
      reason: "Query is safe to execute",
    };
  }

  const levelMessages = {
    [SecurityLevel.LOW_RISK]: "Query contains low-risk operations",
    [SecurityLevel.MEDIUM_RISK]: "Query contains data modification operations",
    [SecurityLevel.HIGH_RISK]:
      "Query contains high-risk operations that could affect database structure",
    [SecurityLevel.CRITICAL]:
      "Query contains critical security threats - execution not recommended",
  };

  return {
    required: true,
    level: analysis.securityLevel,
    reason: levelMessages[analysis.securityLevel] || "Unknown security level",
  };
};

/**
 * Gets security level color for UI display
 * @param level - Security level
 * @returns Color code for UI
 */
export const getSecurityLevelColor = (level: SecurityLevel): string => {
  switch (level) {
    case SecurityLevel.SAFE:
      return "#4caf50"; // Green
    case SecurityLevel.LOW_RISK:
      return "#8bc34a"; // Light Green
    case SecurityLevel.MEDIUM_RISK:
      return "#ff9800"; // Orange
    case SecurityLevel.HIGH_RISK:
      return "#f44336"; // Red
    case SecurityLevel.CRITICAL:
      return "#9c27b0"; // Purple
    default:
      return "#757575"; // Grey
  }
};

/**
 * Validates query against specific security policies
 * @param query - SQL query to validate
 * @param allowedOperations - Array of allowed operation types
 * @returns Validation result
 */
export const validateQueryAgainstPolicy = (
  query: string,
  allowedOperations: string[] = [
    "SELECT",
    "WITH",
    "EXPLAIN",
    "DESCRIBE",
    "SHOW",
  ],
): PolicyValidationResult => {
  const analysis = analyzeQuerySecurity(query);
  const violations: string[] = [];

  // Check if any detected threats are not in allowed operations
  analysis.threats.forEach((threat) => {
    if (!allowedOperations.includes(threat.name)) {
      violations.push(
        `Operation '${threat.name}' is not allowed by current security policy`,
      );
    }
  });

  // Additional policy checks
  if (analysis.securityLevel === SecurityLevel.CRITICAL) {
    violations.push("Critical security threats are not allowed");
  }

  const injectionThreats = analysis.threats.filter(
    (t) => t.category === "INJECTION",
  );
  if (injectionThreats.length > 0) {
    violations.push("SQL injection patterns are strictly forbidden");
  }

  return {
    isValid: violations.length === 0,
    violations,
    analysis,
  };
};

/**
 * Quick safety check for simple use cases
 * @param query - SQL query to check
 * @returns true if query is safe to execute
 */
export const isQuerySafe = (query: string): boolean => {
  const analysis = analyzeQuerySecurity(query);
  return analysis.allowExecution;
};

/**
 * Gets a human-readable security summary
 * @param query - SQL query to analyze
 * @returns Summary string
 */
export const getQuerySecuritySummary = (query: string): string => {
  const analysis = analyzeQuerySecurity(query);

  if (analysis.isSelectOnly) {
    return "Safe read-only query";
  }

  if (analysis.threats.length === 0) {
    return "No security threats detected";
  }

  const threatCounts = analysis.threats.reduce(
    (acc, threat) => {
      acc[threat.level] = (acc[threat.level] || 0) + 1;
      return acc;
    },
    {} as Record<SecurityLevel, number>,
  );

  const summaryParts = [];
  if (threatCounts[SecurityLevel.CRITICAL]) {
    summaryParts.push(
      `${threatCounts[SecurityLevel.CRITICAL]} critical threat(s)`,
    );
  }
  if (threatCounts[SecurityLevel.HIGH_RISK]) {
    summaryParts.push(
      `${threatCounts[SecurityLevel.HIGH_RISK]} high-risk operation(s)`,
    );
  }
  if (threatCounts[SecurityLevel.MEDIUM_RISK]) {
    summaryParts.push(
      `${threatCounts[SecurityLevel.MEDIUM_RISK]} medium-risk operation(s)`,
    );
  }

  return summaryParts.join(", ") || "Low security risk";
};

/**
 * Main class for SQL query safety checking
 */
export class SQLQuerySafetyChecker {
  /**
   * Analyze a SQL query for security threats
   * @param query - SQL query to analyze
   * @returns Comprehensive security analysis
   */
  analyzeQuery(query: string): QueryAnalysis {
    return analyzeQuerySecurity(query);
  }

  /**
   * Quick safety check for a SQL query
   * @param query - SQL query to check
   * @returns Basic safety result
   */
  checkQuerySafety(query: string): QuerySafetyResult {
    const analysis = this.analyzeQuery(query);
    const dangerousOperations = analysis.threats
      .filter(
        (threat) =>
          threat.level === SecurityLevel.HIGH_RISK ||
          threat.level === SecurityLevel.CRITICAL,
      )
      .map((threat) => threat.name);

    return {
      isDangerous: analysis.isDangerous,
      dangerousOperations,
      isSelectOnly: analysis.isSelectOnly,
    };
  }

  /**
   * Check if a query is read-only (SELECT only)
   * @param query - SQL query to check
   * @returns true if query is SELECT only
   */
  isSelectOnlyQuery(query: string): boolean {
    const analysis = this.analyzeQuery(query);
    return analysis.isSelectOnly;
  }

  /**
   * Check if a query requires user confirmation before execution
   * @param query - SQL query to check
   * @returns Confirmation requirement details
   */
  requiresConfirmation(query: string): ConfirmationResult {
    return needsConfirmation(query);
  }
  /**
   * Validate a query against a security policy
   * @param query - SQL query to validate
   * @param policy - Security policy to validate against
   * @returns Policy validation result
   */
  validateAgainstPolicy(
    query: string,
    policy: SecurityPolicy,
  ): PolicyValidationResult {
    return validateQueryAgainstPolicy(query, policy.allowedOperations);
  }

  /**
   * Get a human-readable security summary
   * @param query - SQL query to analyze
   * @returns Summary string
   */
  getSecuritySummary(query: string): string {
    return getQuerySecuritySummary(query);
  }

  /**
   * Check if a query is safe to execute
   * @param query - SQL query to check
   * @returns true if safe to execute
   */
  isSafe(query: string): boolean {
    return isQuerySafe(query);
  }
}

/**
 * Create a new instance of SQLQuerySafetyChecker
 * @returns New SQLQuerySafetyChecker instance
 */
export const createSafetyChecker = (): SQLQuerySafetyChecker => {
  return new SQLQuerySafetyChecker();
};
