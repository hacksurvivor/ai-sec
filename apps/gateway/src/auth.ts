import type { NextFunction, Request, Response } from "express";
import type { PrincipalRole } from "./config.js";

const roleWeight: Record<PrincipalRole, number> = {
  ingest: 1,
  analyst: 2,
  admin: 3
};

export interface AuthPrincipal {
  role: PrincipalRole;
}

interface AuthenticateOptions {
  allowAnonymous?: boolean;
  anonymousRole?: PrincipalRole;
}

function extractBearerToken(authorizationHeader: string | undefined): string | undefined {
  if (!authorizationHeader) {
    return undefined;
  }

  const trimmed = authorizationHeader.trim();
  const match = /^Bearer\s+(.+)$/i.exec(trimmed);
  if (!match) {
    return undefined;
  }

  const token = match[1].trim();
  if (!token || token.includes(",")) {
    return undefined;
  }

  return token;
}

export function authenticateRequest(tokenMap: Map<string, PrincipalRole>, options: AuthenticateOptions = {}) {
  const anonymousRole = options.anonymousRole ?? "admin";
  return (req: Request, res: Response, next: NextFunction): void => {
    const token = extractBearerToken(req.header("authorization"));
    if (!token) {
      if (options.allowAnonymous) {
        res.locals.principal = { role: anonymousRole } satisfies AuthPrincipal;
        next();
        return;
      }
      res.status(401).json({ error: "unauthorized", message: "Missing bearer token" });
      return;
    }

    const role = tokenMap.get(token);
    if (!role) {
      res.status(401).json({ error: "unauthorized", message: "Invalid bearer token" });
      return;
    }

    res.locals.principal = { role } satisfies AuthPrincipal;
    next();
  };
}

export function requireRole(minimumRole: PrincipalRole) {
  return (_req: Request, res: Response, next: NextFunction): void => {
    const principal = res.locals.principal as AuthPrincipal | undefined;
    if (!principal) {
      res.status(401).json({ error: "unauthorized" });
      return;
    }

    if (roleWeight[principal.role] < roleWeight[minimumRole]) {
      res.status(403).json({ error: "forbidden", message: "Insufficient role" });
      return;
    }

    next();
  };
}
