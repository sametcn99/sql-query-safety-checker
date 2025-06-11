import { SAFE_OPERATIONS } from "./constants";

/**
 * Normalizes a SQL query by removing comments and extra whitespace
 * @param query - Raw SQL query
 * @returns Cleaned query string
 */
export const normalizeQuery = (query: string): string => {
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
export const isReadOnlyQuery = (query: string): boolean => {
  if (!query) return true;

  return SAFE_OPERATIONS.some((pattern) => pattern.test(query));
};
