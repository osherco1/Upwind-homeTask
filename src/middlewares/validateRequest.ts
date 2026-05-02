import { Request, Response, NextFunction } from 'express';

/**
 * Placeholder validation middleware.
 *
 * In a future iteration this will enforce the exact JSON schema
 * defined in the Request Payload Contract (DESIGN.md §2).
 * For now it logs receipt and passes control to the next handler.
 */
export function validateRequest(req: Request, res: Response, next: NextFunction): void {
  console.log(`[validateRequest] Received ${req.method} ${req.originalUrl} — payload size: ${JSON.stringify(req.body).length} bytes`);
  next();
}
