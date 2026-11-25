import type { Request, Response, NextFunction } from "express";
import jwt from "jsonwebtoken";
import type { JwtPayload, VerifyErrors } from "jsonwebtoken"
import createError from "http-errors";

interface AccessTokenPayload extends JwtPayload {
    id: string; // Change to `number` if your Prisma User ID is an Int
}

// Verify Bearer access token in Authorization header and attach user ID to request
export function accessVerification(req: Request, _res: Response, next: NextFunction): void {
    const [scheme, token] = (req.headers.authorization ?? "").split(" ");
    if (scheme !== "Bearer" || !token) {
        return next(createError(401, "token not found"));
    }

    const secret = process.env.ACCESS_TOKEN_SECRET;
    if (!secret) {
        return next(createError(500, "ACCESS_TOKEN_SECRET is not configured"));
    }

    jwt.verify(
        token,
        secret,
        (err: VerifyErrors | null, payload: string | JwtPayload | undefined) => {
            if (err) {
                const expired = err.name === "TokenExpiredError";
                return next(createError(401, expired ? "token expired" : "token was invalid"));
            }

            if (!payload || typeof payload === "string" || !("id" in payload)) {
                return next(createError(401, "token was invalid"));
            }

            req.id = (payload as AccessTokenPayload).id;
            next();
        }
    );
}

// Verify Bearer access token if provided, allowing guest access when omitted
export function optionalAccessVerification(
    req: Request,
    res: Response,
    next: NextFunction
): void {
    if (!req.headers.authorization) {
        return next();
    }
    return accessVerification(req, res, next);
}