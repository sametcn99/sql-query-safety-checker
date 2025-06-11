import { SecurityLevel, SecurityThreat } from "./types";

export const SECURITY_THREATS: SecurityThreat[] = [
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
export const SAFE_OPERATIONS: RegExp[] = [
  /^\s*(SELECT|select)\b/,
  /^\s*(WITH|with)\b/,
  /^\s*(EXPLAIN|explain)\b/,
  /^\s*(DESCRIBE|describe)\b/,
  /^\s*(DESC|desc)\b/,
  /^\s*(SHOW|show)\b/,
  /^\s*(PRAGMA|pragma)\b/,
];
