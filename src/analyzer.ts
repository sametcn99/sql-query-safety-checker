import {
  SecurityLevel,
  QueryAnalysis,
  ConfirmationResult,
  PolicyValidationResult,
} from "./types";
import { SECURITY_THREATS } from "./constants";
import { normalizeQuery, isReadOnlyQuery } from "./utils";
import { generateRecommendations } from "./recommendations";

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

  const summaryParts: string[] = [];
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
