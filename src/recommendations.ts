import { SecurityLevel, QueryAnalysis } from "./types";

/**
 * Generates security recommendations based on detected threats
 * @param threats - Array of detected security threats
 * @param isSelectOnly - Whether query is read-only
 * @returns Array of recommendation strings
 */
export const generateRecommendations = (
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
