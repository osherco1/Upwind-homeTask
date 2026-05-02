import { Request, Response, NextFunction } from 'express';

/**
 * Strict input validation middleware.
 *
 * Enforces the exact JSON schema defined in the Request Payload Contract (DESIGN.md §2).
 */
export function validateRequest(req: Request, res: Response, next: NextFunction): void {
  const { body, headers, attachments } = req.body;

  const errors: string[] = [];

  if (typeof body !== 'string') {
    errors.push("'body' must exist and be a string.");
  }

  if (!headers || typeof headers !== 'object' || Array.isArray(headers)) {
    errors.push("'headers' must exist and be an object.");
  } else if (typeof headers.from !== 'string') {
    errors.push("'headers.from' must exist and be a string.");
  }

  if (attachments !== undefined && !Array.isArray(attachments)) {
    errors.push("'attachments', if present, must be an array.");
  }

  if (errors.length > 0) {
    res.status(400).json({ error: "Bad Request", details: errors });
    return;
  }

  next();
}
