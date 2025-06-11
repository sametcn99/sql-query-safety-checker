import { SecurityLevel } from "./types";

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
