import { describe, it, expect, beforeEach } from "bun:test";
import {
  sqlSafetyMiddleware,
  sqlSafetyPresets,
  SQLSafetyMiddlewareOptions,
} from "../src/middleware/express";
import { SecurityLevel } from "../src/types";
import express, { Request, Response, NextFunction } from "express";
import supertest from "supertest";

// Mock functions for testing
const createMockRequest = (body: any = {}): Partial<Request> => ({
  body,
  headers: {},
  method: "POST",
  url: "/test",
});

const createMockResponse = (): Partial<Response> => {
  const res: any = {
    status: () => res,
    json: () => res,
    send: () => res,
    statusCode: 200,
    locals: {},
  };
  return res;
};

const createMockNext = (): NextFunction => {
  const next = () => {};
  return next;
};

describe("SQL Safety Middleware", () => {
  describe("Basic Functionality", () => {
    it("should create middleware function", () => {
      const middleware = sqlSafetyMiddleware();
      expect(typeof middleware).toBe("function");
    });

    it("should work with default options", () => {
      const middleware = sqlSafetyMiddleware();
      expect(middleware).toBeDefined();
    });

    it("should work with custom options", () => {
      const options: SQLSafetyMiddlewareOptions = {
        maxRiskLevel: SecurityLevel.LOW_RISK,
        enableLogging: true,
      };
      const middleware = sqlSafetyMiddleware(options);
      expect(middleware).toBeDefined();
    });
  });

  describe("Preset Configurations", () => {
    it("should create readOnly preset", () => {
      const options = sqlSafetyPresets.readOnly();
      expect(options.maxRiskLevel).toBe(SecurityLevel.LOW_RISK);
      expect(options.enableLogging).toBe(true);
    });

    it("should create moderate preset", () => {
      const options = sqlSafetyPresets.moderate();
      expect(options.maxRiskLevel).toBe(SecurityLevel.MEDIUM_RISK);
      expect(options.allowedOperations).toContain("SELECT");
      expect(options.allowedOperations).toContain("INSERT");
      expect(options.allowedOperations).toContain("UPDATE");
    });

    it("should create permissive preset", () => {
      const options = sqlSafetyPresets.permissive();
      expect(options.maxRiskLevel).toBe(SecurityLevel.HIGH_RISK);
      expect(options.blockInjectionPatterns).toBe(true);
    });

    it("should create development preset", () => {
      const options = sqlSafetyPresets.development();
      expect(options.maxRiskLevel).toBe(SecurityLevel.CRITICAL);
      expect(options.enableLogging).toBe(true);
    });
  });

  describe("Middleware Options", () => {
    it("should accept maxRiskLevel option", () => {
      const options: SQLSafetyMiddlewareOptions = {
        maxRiskLevel: SecurityLevel.MEDIUM_RISK,
      };
      const middleware = sqlSafetyMiddleware(options);
      expect(middleware).toBeDefined();
    });

    it("should accept allowedOperations option", () => {
      const options: SQLSafetyMiddlewareOptions = {
        allowedOperations: ["SELECT", "INSERT"],
      };
      const middleware = sqlSafetyMiddleware(options);
      expect(middleware).toBeDefined();
    });

    it("should accept custom error handler", () => {
      const options: SQLSafetyMiddlewareOptions = {
        onError: (error, req, res, next) => {
          res.status(400).json({ error: "Custom error" });
        },
      };
      const middleware = sqlSafetyMiddleware(options);
      expect(middleware).toBeDefined();
    });
  });

  describe("Express Integration Tests", () => {
    let app: express.Application;

    beforeEach(() => {
      app = express();
      app.use(express.json());
    });

    it("should allow safe SQL queries", (done) => {
      app.use(sqlSafetyMiddleware());

      app.post("/query", (req: Request, res: Response) => {
        res.json({ success: true, analysis: req.sqlAnalysis });
      });

      supertest(app)
        .post("/query")
        .send({ query: "SELECT * FROM users WHERE id = 1" })
        .expect(200)
        .end((err, res) => {
          if (err) return done(err);
          expect(res.body.success).toBe(true);
          expect(res.body.analysis).toBeDefined();
          done();
        });
    });
    it("should block dangerous SQL queries", (done) => {
      app.use(sqlSafetyMiddleware({ maxRiskLevel: SecurityLevel.LOW_RISK }));

      app.post("/query", (req: Request, res: Response) => {
        res.json({ success: true });
      });

      supertest(app)
        .post("/query")
        .send({ query: "SELECT * FROM users WHERE id = 1' OR 1=1" })
        .expect(403)
        .end((err, res) => {
          if (err) return done(err);
          expect(res.body.error).toBe("SQL Security Violation");
          expect(res.body.securityLevel).toBe("critical");
          expect(res.body.threats).toBeDefined();
          expect(res.body.threats.length).toBeGreaterThan(0);
          done();
        });
    });

    it("should handle multiple queries", (done) => {
      app.use(sqlSafetyMiddleware());

      app.post("/query", (req: Request, res: Response) => {
        res.json({ success: true, analysis: req.sqlAnalysis });
      });

      supertest(app)
        .post("/query")
        .send({
          queries: [
            "SELECT * FROM users WHERE id = 1",
            "SELECT * FROM products WHERE active = 1",
          ],
        })
        .expect(200)
        .end((err, res) => {
          if (err) return done(err);
          expect(res.body.success).toBe(true);
          expect(Array.isArray(res.body.analysis)).toBe(true);
          done();
        });
    });

    it("should use custom error handler", (done) => {
      const customErrorHandler = (
        error: any,
        req: Request,
        res: Response,
        next: NextFunction,
      ) => {
        res.status(400).json({
          customError: true,
          message: "Custom security error",
          originalMessage: error.message,
        });
      };

      app.use(
        sqlSafetyMiddleware({
          maxRiskLevel: SecurityLevel.LOW_RISK,
          onError: customErrorHandler,
        }),
      );

      app.post("/query", (req: Request, res: Response) => {
        res.json({ success: true });
      });

      supertest(app)
        .post("/query")
        .send({ query: "DELETE FROM users; DROP TABLE users;" })
        .expect(400)
        .end((err, res) => {
          if (err) return done(err);
          expect(res.body.customError).toBe(true);
          expect(res.body.message).toBe("Custom security error");
          done();
        });
    });

    it("should handle custom query extraction", (done) => {
      const customExtractor = (req: Request) => req.body.sqlCommand;

      app.use(sqlSafetyMiddleware({ extractQuery: customExtractor }));

      app.post("/query", (req: Request, res: Response) => {
        res.json({ success: true, analysis: req.sqlAnalysis });
      });

      supertest(app)
        .post("/query")
        .send({ sqlCommand: "SELECT COUNT(*) FROM users" })
        .expect(200)
        .end((err, res) => {
          if (err) return done(err);
          expect(res.body.success).toBe(true);
          expect(res.body.analysis).toBeDefined();
          done();
        });
    });

    it("should work with readOnly preset", (done) => {
      app.use(sqlSafetyMiddleware(sqlSafetyPresets.readOnly()));

      app.post("/query", (req: Request, res: Response) => {
        res.json({ success: true });
      });

      // Should allow SELECT
      supertest(app)
        .post("/query")
        .send({ query: "SELECT * FROM users" })
        .expect(200)
        .end((err, res) => {
          if (err) return done(err);

          // Should block INSERT
          supertest(app)
            .post("/query")
            .send({ query: 'INSERT INTO users (name) VALUES ("test")' })
            .expect(403)
            .end((err2, res2) => {
              if (err2) return done(err2);
              expect(res2.body.error).toBe("SQL Security Violation");
              done();
            });
        });
    });

    it("should handle empty or missing queries", (done) => {
      app.use(sqlSafetyMiddleware());

      app.post("/query", (req: Request, res: Response) => {
        res.json({ success: true, analysis: req.sqlAnalysis });
      });

      supertest(app)
        .post("/query")
        .send({})
        .expect(200)
        .end((err, res) => {
          if (err) return done(err);
          expect(res.body.success).toBe(true);
          done();
        });
    });

    it("should enable logging when configured", (done) => {
      const consoleSpy = {
        logs: [] as string[],
        log: (...args: any[]) => {
          consoleSpy.logs.push(args.join(" "));
        },
      };

      const originalLog = console.log;
      console.log = consoleSpy.log;

      app.use(sqlSafetyMiddleware({ enableLogging: true }));

      app.post("/query", (req: Request, res: Response) => {
        res.json({ success: true });
      });

      supertest(app)
        .post("/query")
        .send({ query: "SELECT * FROM users" })
        .expect(200)
        .end((err, res) => {
          console.log = originalLog;
          if (err) return done(err);
          expect(res.body.success).toBe(true);
          done();
        });
    });
  });

  describe("Middleware Function Tests", () => {
    it("should call next() for safe queries", () => {
      const middleware = sqlSafetyMiddleware();
      const req = createMockRequest({
        query: "SELECT * FROM users",
      }) as Request;
      const res = createMockResponse() as Response;
      const next = createMockNext();

      let nextCalled = false;
      const mockNext = () => {
        nextCalled = true;
      };

      middleware(req, res, mockNext);
      expect(nextCalled).toBe(true);
    });
    it("should not call next() for dangerous queries", () => {
      const middleware = sqlSafetyMiddleware({
        maxRiskLevel: SecurityLevel.LOW_RISK,
      });
      const req = createMockRequest({
        query: "SELECT * FROM users WHERE id = 1' OR 1=1",
      }) as Request;
      const res = createMockResponse() as Response;

      let nextCalled = false;
      let statusCalled = false;
      let jsonCalled = false;

      const mockNext = () => {
        nextCalled = true;
      };
      const mockRes = {
        ...res,
        status: (code: number) => {
          statusCalled = true;
          expect(code).toBe(403);
          return mockRes;
        },
        json: (data: any) => {
          jsonCalled = true;
          expect(data.error).toBe("SQL Security Violation");
          expect(data.message).toBe("SQL injection pattern detected");
          expect(data.securityLevel).toBe("critical");
          return mockRes;
        },
      } as Response;

      middleware(req, mockRes, mockNext);
      expect(nextCalled).toBe(false);
      expect(statusCalled).toBe(true);
      expect(jsonCalled).toBe(true);
    });

    it("should attach analysis to request when enabled", () => {
      const middleware = sqlSafetyMiddleware({ attachAnalysis: true });
      const req = createMockRequest({
        query: "SELECT * FROM users",
      }) as Request;
      const res = createMockResponse() as Response;
      const next = createMockNext();

      middleware(req, res, next);
      expect(req.sqlAnalysis).toBeDefined();
    });

    it("should not attach analysis to request when disabled", () => {
      const middleware = sqlSafetyMiddleware({ attachAnalysis: false });
      const req = createMockRequest({
        query: "SELECT * FROM users",
      }) as Request;
      const res = createMockResponse() as Response;
      const next = createMockNext();

      middleware(req, res, next);
      expect(req.sqlAnalysis).toBeUndefined();
    });
  });
});
