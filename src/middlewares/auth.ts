import { Request, Response, NextFunction } from 'express';

/**
 * Production-grade API Key Authentication Middleware.
 * 
 * Extracts the `x-api-key` header (or standard `Authorization` header)
 * and compares it securely against `process.env.API_KEY`.
 */
export function auth(req: Request, res: Response, next: NextFunction): void {
  const apiKey = req.headers['x-api-key'] || req.headers.authorization;
  const expectedKey = process.env.API_KEY;

  if (!apiKey) {
    res.status(401).json({ error: "Missing API Key" });
    return;
  }

  if (apiKey !== expectedKey) {
    res.status(401).json({ error: "Invalid API Key" });
    return;
  }

  next();
}
