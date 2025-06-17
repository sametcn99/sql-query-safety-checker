import { Request, Response, NextFunction } from "express";
import { SQLQuerySafetyChecker } from "./checker";
import { SecurityLevel, QueryAnalysis } from "./types";

export interface SQLSafetyMiddlewareOptions {
  /**
   * Maximum allowed security level for queries
   * @default SecurityLevel.MEDIUM_RISK
   */
  maxRiskLevel?: SecurityLevel;

  /**
   * Whether to block queries with injection patterns
   * @default true
   */
  blockInjectionPatterns?: boolean;

  /**
   * List of allowed SQL operations
   * @default ["SELECT", "WITH", "EXPLAIN", "DESCRIBE", "SHOW"]
   */
  allowedOperations?: string[];

  /**
   * Custom error handler function
   */
  onError?: (
    error: SQLSecurityError,
    req: Request,
    res: Response,
    next: NextFunction,
  ) => void;

  /**
   * Custom warning handler function
   */
  onWarning?: (
    warning: SQLSecurityWarning,
    req: Request,
    res: Response,
    next: NextFunction,
  ) => void;

  /**
   * Function to extract SQL query from request
   * @default extracts from req.body.query
   */
  extractQuery?: (req: Request) => string | string[];

  /**
   * Whether to log security checks
   * @default false
   */
  enableLogging?: boolean;

  /**
   * Whether to add security analysis to request object
   * @default true
   */
  attachAnalysis?: boolean;
}

export interface SQLSecurityError {
  type: "security_violation";
  message: string;
  analysis: QueryAnalysis;
  query: string;
}

export interface SQLSecurityWarning {
  type: "security_warning";
  message: string;
  analysis: QueryAnalysis;
  query: string;
}

// Extend Express Request interface to include SQL analysis
declare global {
  namespace Express {
    interface Request {
      sqlAnalysis?: QueryAnalysis | QueryAnalysis[];
    }
  }
}

/**
 * Default query extractor - gets query from request body
 */
const defaultQueryExtractor = (req: Request): string | string[] => {
  if (req.body?.query) {
    return req.body.query;
  }

  if (req.body?.queries) {
    return req.body.queries;
  }

  // Check for common SQL query parameters
  if (req.body?.sql) {
    return req.body.sql;
  }

  return "";
};

/**
 * Default error handler
 */
const defaultErrorHandler = (
  error: SQLSecurityError,
  req: Request,
  res: Response,
  next: NextFunction,
) => {
  res.status(403).json({
    error: "SQL Security Violation",
    message: error.message,
    securityLevel: error.analysis.securityLevel,
    threats: error.analysis.threats,
    recommendations: error.analysis.recommendations,
  });
};

/**
 * Default warning handler
 */
const defaultWarningHandler = (
  warning: SQLSecurityWarning,
  req: Request,
  res: Response,
  next: NextFunction,
) => {
  // Log warning but continue execution
  console.warn("SQL Security Warning:", warning.message);
  next();
};

/**
 * Express middleware for SQL query safety checking
 * @param options - Middleware configuration options
 * @returns Express middleware function
 */
export const sqlSafetyMiddleware = (
  options: SQLSafetyMiddlewareOptions = {},
): ((req: Request, res: Response, next: NextFunction) => void) => {
  const {
    maxRiskLevel = SecurityLevel.MEDIUM_RISK,
    blockInjectionPatterns = true,
    allowedOperations = ["SELECT", "WITH", "EXPLAIN", "DESCRIBE", "SHOW"],
    onError = defaultErrorHandler,
    onWarning = defaultWarningHandler,
    extractQuery = defaultQueryExtractor,
    enableLogging = false,
    attachAnalysis = true,
  } = options;

  const checker = new SQLQuerySafetyChecker();

  return (req: Request, res: Response, next: NextFunction) => {
    try {
      const queries = extractQuery(req);

      if (!queries) {
        // No SQL query found, continue
        return next();
      }

      const queryArray = Array.isArray(queries) ? queries : [queries];
      const analyses: QueryAnalysis[] = [];

      for (const query of queryArray) {
        if (!query || typeof query !== "string") {
          continue;
        }

        const analysis = checker.analyzeQuery(query);
        analyses.push(analysis);

        if (enableLogging) {
          console.log(
            `SQL Security Check: ${analysis.securityLevel} - ${query.substring(0, 100)}...`,
          );
        }

        // Check for injection patterns
        if (blockInjectionPatterns) {
          const injectionThreats = analysis.threats.filter(
            (t) => t.category === "INJECTION",
          );
          if (injectionThreats.length > 0) {
            const error: SQLSecurityError = {
              type: "security_violation",
              message: "SQL injection pattern detected",
              analysis,
              query,
            };
            return onError(error, req, res, next);
          }
        }

        // Check risk level
        const riskLevels = [
          SecurityLevel.SAFE,
          SecurityLevel.LOW_RISK,
          SecurityLevel.MEDIUM_RISK,
          SecurityLevel.HIGH_RISK,
          SecurityLevel.CRITICAL,
        ];

        const maxRiskIndex = riskLevels.indexOf(maxRiskLevel);
        const queryRiskIndex = riskLevels.indexOf(analysis.securityLevel);

        if (queryRiskIndex > maxRiskIndex) {
          const error: SQLSecurityError = {
            type: "security_violation",
            message: `Query security level (${analysis.securityLevel}) exceeds maximum allowed (${maxRiskLevel})`,
            analysis,
            query,
          };
          return onError(error, req, res, next);
        }

        // Check allowed operations
        const detectedOperations = analysis.threats.map((t) => t.name);
        const forbiddenOperations = detectedOperations.filter(
          (op) => !allowedOperations.includes(op),
        );

        if (forbiddenOperations.length > 0) {
          const error: SQLSecurityError = {
            type: "security_violation",
            message: `Forbidden operations detected: ${forbiddenOperations.join(", ")}`,
            analysis,
            query,
          };
          return onError(error, req, res, next);
        }

        // Issue warnings for medium risk queries
        if (
          analysis.securityLevel === SecurityLevel.MEDIUM_RISK &&
          analysis.threats.length > 0
        ) {
          const warning: SQLSecurityWarning = {
            type: "security_warning",
            message: `Medium risk SQL operation detected: ${analysis.threats.map((t) => t.name).join(", ")}`,
            analysis,
            query,
          };
          onWarning(warning, req, res, next);
        }
      }

      // Attach analysis to request if enabled
      if (attachAnalysis) {
        req.sqlAnalysis = analyses.length === 1 ? analyses[0] : analyses;
      }

      next();
    } catch (error) {
      console.error("SQL Safety Middleware Error:", error);
      const sqlError: SQLSecurityError = {
        type: "security_violation",
        message: "Internal security check error",
        analysis: {
          securityLevel: SecurityLevel.CRITICAL,
          isDangerous: true,
          isSelectOnly: false,
          threats: [],
          recommendations: ["Internal error during security check"],
          allowExecution: false,
        },
        query: "",
      };
      onError(sqlError, req, res, next);
    }
  };
};

/**
 * Preset configurations for common use cases
 */
export const sqlSafetyPresets = {
  /**
   * Strict security - only read operations allowed
   */
  readOnly: (): SQLSafetyMiddlewareOptions => ({
    maxRiskLevel: SecurityLevel.LOW_RISK,
    allowedOperations: ["SELECT", "WITH", "EXPLAIN", "DESCRIBE", "SHOW"],
    blockInjectionPatterns: true,
    enableLogging: true,
  }),

  /**
   * Moderate security - allows data modifications but blocks structure changes
   */
  moderate: (): SQLSafetyMiddlewareOptions => ({
    maxRiskLevel: SecurityLevel.MEDIUM_RISK,
    allowedOperations: [
      "SELECT",
      "INSERT",
      "UPDATE",
      "DELETE",
      "WITH",
      "EXPLAIN",
      "DESCRIBE",
      "SHOW",
    ],
    blockInjectionPatterns: true,
    enableLogging: false,
  }),

  /**
   * Permissive security - allows most operations but blocks injections
   */
  permissive: (): SQLSafetyMiddlewareOptions => ({
    maxRiskLevel: SecurityLevel.HIGH_RISK,
    blockInjectionPatterns: true,
    enableLogging: false,
  }),

  /**
   * Development mode - logs everything but doesn't block
   */
  development: (): SQLSafetyMiddlewareOptions => ({
    maxRiskLevel: SecurityLevel.CRITICAL,
    blockInjectionPatterns: false,
    enableLogging: true,
    onError: (error, req, res, next) => {
      console.warn("SQL Security Issue (Development Mode):", error.message);
      next(); // Continue execution in development
    },
  }),
};

/**
 * Express router factory with built-in SQL safety
 * @param options - SQL safety middleware options
 * @returns Express router with SQL safety middleware applied
 */
export const createSecureRouter = (
  options?: SQLSafetyMiddlewareOptions,
): any => {
  const express = require("express");
  const router = express.Router();

  // Apply SQL safety middleware to all routes
  router.use(sqlSafetyMiddleware(options));

  return router;
};
