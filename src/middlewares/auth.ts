import { Request, Response, NextFunction } from 'express';

/**
 * Authentication middleware stub.
 * 
 * TODO: In the future, this will verify Google Workspace ID Tokens (JWT)
 * using the `google-auth-library`.
 * 
 * For now, it just logs the Authorization header if present and proceeds
 * without blocking, allowing for local testing.
 */
export function auth(req: Request, res: Response, next: NextFunction): void {
  const authHeader = req.headers.authorization;
  if (authHeader) {
    console.log(`[auth] Authorization header present: ${authHeader.substring(0, 20)}...`);
  } else {
    console.log('[auth] No Authorization header present.');
  }
  next();
}
