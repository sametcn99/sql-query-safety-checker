import { expect } from "bun:test";

// Extend the expect interface to include custom matchers
declare module "bun:test" {
  interface Matchers<T> {
    toBeOneOf(expected: T[]): void;
  }
}

// Add the custom matcher
expect.extend({
  toBeOneOf(received: any, expected: any[]) {
    const pass = expected.includes(received);

    if (pass) {
      return {
        message: () =>
          `expected ${received} not to be one of ${expected.join(", ")}`,
        pass: true,
      };
    } else {
      return {
        message: () =>
          `expected ${received} to be one of ${expected.join(", ")}`,
        pass: false,
      };
    }
  },
});
