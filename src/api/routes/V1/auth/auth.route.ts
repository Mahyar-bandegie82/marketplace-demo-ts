import express from "express";
import type { Request, Response, CookieOptions, Router } from "express"
import {
    signUpSchema,
    loginSchema,
    changeCredentialsSchema,
    verifyOtpSchema,
} from "../../../../validation/auth/auth.validation.js";
import { accessVerification, optionalAccessVerification } from "../../../middleware/authMiddleware.js";
import { connectRedis } from "../../../../loader/redis.loader.js";
import createError from "http-errors";
import jwt from "jsonwebtoken";
import type { JwtPayload } from "jsonwebtoken";
import {
    consumeRefreshToken,
    revokeAllForUser,
    revokeFamily,
    saveRefreshToken,
} from "../../../../services/redis/refreshToken.service.js";
import {
    changeUserInfo,
    getProfile,
    login,
    sanitizeUser,
    signUp,
    markOtpVerified,
    unverifyUser,
} from "../../../../services/auth/auth.services.js";
import crypto from "crypto";
import { redisSaveOtp, verifyOtp } from "../../../../services/redis/otp.service.js";

// Extend Express Request to include `id` attached by auth middleware.
// Move this block into a shared `src/types/express.d.ts` file if preferred.
declare global {
    namespace Express {
        interface Request {
            id?: string; // Change to `number` if your Prisma User ID is an Int
        }
    }
}

interface RefreshTokenPayload extends JwtPayload {
    id: string;
    familyId: string;
}

interface VerifyOtpBody {
    otp: string;
}

interface ChangeCredentialsBody {
    changes: {
        email?: string;
        password?: string;
        [key: string]: unknown;
    };
}

connectRedis().catch((err: unknown) => {
    const message = err instanceof Error ? err.message : String(err);
    console.warn("Initial Redis connection skipped:", message);
});

const REFRESH_COOKIE_OPTIONS: CookieOptions = {
    httpOnly: true,
    secure: true,
    sameSite: "strict",
    maxAge: 7 * 24 * 60 * 60 * 1000,
};

const { maxAge: _maxAge, ...CLEAR_COOKIE_OPTIONS } = REFRESH_COOKIE_OPTIONS;

const router: Router = express.Router();

router.use(optionalAccessVerification, attachAbility);

function getRefreshTokenSecret(): string {
    const secret = process.env.REFRESH_TOKEN_SECRET;
    if (!secret) {
        throw createError(500, "REFRESH_TOKEN_SECRET is not configured");
    }
    return secret;
}

// Mask the local portion of an email address for privacy
function maskEmail(email: string): string {
    const [local = "", domain = ""] = email.split("@");
    return `${local.slice(0, 3)}${"*".repeat(Math.max(local.length - 3, 0))}@${domain}`;
}

// Fetch current authenticated user profile
router.get("/me", async (req: Request, res: Response) => {
    if (!req.id) throw createError(401, "token not found");

    const user = await prismaPool.user.findUnique({
        where: { id: req.id },
        select: {
            id: true,
            userName: true,
            phoneNumber: true,
            email: true,
            otpVerified: true,
            dateCreated: true,
            admin: { select: { id: true } },
            client: { select: { id: true } },
            seller: { select: { id: true, verified: true, trusted: true, storeName: true } },
        },
    });
    if (!user) throw createError(404, "user not found");

    return res.status(200).json({ user });
});

// Generate and send an OTP code for signup email verification
router.get("/signup/reciveOtp", async (req: Request, res: Response) => {
    if (!req.id) throw createError(401, "token not found");

    const user = await getProfile(req.id);
    if (user.otpVerified) throw createError(409, "account already verified");

    const otp = await generateOtp(user.email);
    await redisSaveOtp(otp, user.email, "signup");
    // await sendOtp(user.email, otp);

    return res.status(200).json({
        message: `otp was successfully sent to your email with the address of ${maskEmail(user.email)}`,
    });
});

// Generate and send an OTP code for credential change verification
router.get("/credentialChange/reciveOtp", async (req: Request, res: Response) => {
    if (!req.id) throw createError(401, "token not found");

    const user = await getProfile(req.id);
    if (user.otpVerified) throw createError(409, "account already verified");

    const otp = await generateOtp(user.email);
    await redisSaveOtp(otp, user.email, "passwordChange");
    // await sendOtp(user.email, otp);

    return res.status(200).json({
        message: `otp was successfully sent to your email with the address of ${maskEmail(user.email)}`,
    });
});

// Register a new user account, issue authentication tokens, and set refresh cookie
router.post("/signup", async (req: Request, res: Response) => {
    const body = await joiValidator(signUpSchema, req.body);
    const user = await signUp(body);

    return res.status(201).json({
        value: sanitizeUser(user),
        message: "Signed up successfully",
    });
});

// Authenticate user credentials, issue authentication tokens, and set refresh cookie
router.post("/login", async (req: Request, res: Response) => {
    const body = await joiValidator(loginSchema, req.body);
    const user = await login(body);
    const familyId = crypto.randomUUID();

    const accessToken = generateAccessToken(user.id);
    const refreshToken = generateRefreshToken(user.id, familyId);
    await saveRefreshToken(refreshToken, user.id, familyId);

    res.cookie("refreshToken", refreshToken, REFRESH_COOKIE_OPTIONS);
    return res.status(200).json({
        value: sanitizeUser(user),
        message: "Logged in successfully",
        accessToken,
    });
});

// Revoke user refresh token family and clear authentication cookie
router.post("/logout", async (req: Request, res: Response) => {
    res.clearCookie("refreshToken", CLEAR_COOKIE_OPTIONS);
    const refreshToken: string | undefined = req.cookies?.refreshToken;
    if (!refreshToken) throw createError(401, "no token provided");

    const decoded = jwt.verify(refreshToken, getRefreshTokenSecret(), {
        algorithms: ["HS256"],
    }) as RefreshTokenPayload;

    if (decoded.familyId) await revokeFamily(decoded.familyId);
    res.status(200).json({ message: "Logged out successfully" });
});

// Rotate refresh token and issue a new access token
router.put("/refresh", async (req: Request, res: Response) => {
    const token: string | undefined = req.cookies?.refreshToken;
    if (!token) throw createError(401, "no token provided");

    const decoded = jwt.verify(token, getRefreshTokenSecret(), {
        algorithms: ["HS256"],
    }) as RefreshTokenPayload;

    const storedToken = await consumeRefreshToken(token);
    if (!storedToken) {
        await revokeFamily(decoded.familyId);
        res.clearCookie("refreshToken", CLEAR_COOKIE_OPTIONS);
        throw createError(401, "invalid or expired token");
    }

    const refreshToken = generateRefreshToken(decoded.id, decoded.familyId);
    const accessToken = generateAccessToken(decoded.id);
    await saveRefreshToken(refreshToken, decoded.id, decoded.familyId);

    res.cookie("refreshToken", refreshToken, REFRESH_COOKIE_OPTIONS);
    return res.status(200).json({ accessToken });
});

// Access verification middleware for protected routes
router.use(accessVerification, attachAbility);

// Verify OTP code submitted for signup verification
router.post("/signup/verify-otp", async (req: Request, res: Response) => {
    if (!req.id) throw createError(401, "token not found");

    const { otp } = (await joiValidator(verifyOtpSchema, req.body)) as VerifyOtpBody;
    const user = await getProfile(req.id);
    if (user.otpVerified) throw createError(409, "account already verified");

    await verifyOtp(otp, user.email, "signup");
    const updated = await markOtpVerified(user.id);

    const familyId = crypto.randomUUID();
    const accessToken = generateAccessToken(user.id);
    const refreshToken = generateRefreshToken(user.id, familyId);
    await saveRefreshToken(refreshToken, user.id, familyId);
    res.cookie("refreshToken", refreshToken, REFRESH_COOKIE_OPTIONS);

    return res.status(200).json({
        message: "account verified successfully",
        accessToken,
        value: sanitizeUser(updated),
    });
});

// Verify OTP code submitted for credential change
router.post("/credentialChange/verify-otp", async (req: Request, res: Response) => {
    if (!req.id) throw createError(401, "token not found");

    const { otp } = (await joiValidator(verifyOtpSchema, req.body)) as VerifyOtpBody;
    const user = await getProfile(req.id);
    if (user.otpVerified) throw createError(409, "account already verified");

    await verifyOtp(otp, user.email, "passwordChange");
    const updated = await markOtpVerified(user.id);

    const familyId = crypto.randomUUID();
    const accessToken = generateAccessToken(user.id);
    const refreshToken = generateRefreshToken(user.id, familyId);
    await saveRefreshToken(refreshToken, user.id, familyId);
    res.cookie("refreshToken", refreshToken, REFRESH_COOKIE_OPTIONS);

    return res.status(200).json({
        message: "account verified successfully",
        accessToken,
        value: sanitizeUser(updated),
    });
});

// Update user credentials such as email or password and revoke active sessions if needed
router.put("/editinfo", authorize("update", "User"), async (req: Request, res: Response) => {
    if (!req.id) throw createError(401, "token not found");

    const body = (await joiValidator(changeCredentialsSchema, req.body)) as ChangeCredentialsBody;
    const changedPassword = body.changes.password;
    const changedEmail = body.changes.email;

    if (changedPassword || changedEmail) {
        await unverifyUser(req.id);
        await revokeAllForUser(req.id);
        res.clearCookie("refreshToken", CLEAR_COOKIE_OPTIONS);
    }

    const changed = await changeUserInfo(req.id, body.changes);

    let message = "updated credentials successfully";
    if (changedEmail) message = "email updated, please log in again and verify your new email";
    else if (changedPassword) message = "password updated, please log in again";

    return res.status(200).json({
        message,
        newInfo: sanitizeUser(changed),
    });
});

export default router;