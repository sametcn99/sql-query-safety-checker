import {
  QuerySafetyResult,
  ConfirmationResult,
  PolicyValidationResult,
  SecurityPolicy,
  SecurityLevel,
  QueryAnalysis,
} from "./types";
import {
  analyzeQuerySecurity,
  needsConfirmation,
  validateQueryAgainstPolicy,
  isQuerySafe,
  getQuerySecuritySummary,
} from "./analyzer";

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
