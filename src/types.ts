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
