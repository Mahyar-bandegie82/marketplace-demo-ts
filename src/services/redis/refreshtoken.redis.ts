import crypto from "crypto";
import redis from "../../loader/redis.loader.js";

const TTL = 7 * 24 * 60 * 60;

export interface StoredRefreshToken {
    userId: string; // Change to `number` if your Prisma User ID is an Int
    familyId: string;
}

// Compute SHA-256 hash digest of a token string
const sha256 = (v: string): string => crypto.createHash("sha256").update(v).digest("hex");

const tokenKey = (hash: string): string => `rt:${hash}`;
const familyKey = (fid: string): string => `rt:family:${fid}`;
const userKey = (id: string): string => `rt:user:${id}`;

// Store hashed refresh token, family association, and user mapping in Redis
export async function saveRefreshToken(
    token: string,
    userId: string,
    familyId: string
): Promise<void> {
    const hash = sha256(token);
    const payload: StoredRefreshToken = { userId, familyId };

    await redis
        .multi()
        .set(tokenKey(hash), JSON.stringify(payload), { EX: TTL })
        .set(familyKey(familyId), hash, { EX: TTL })
        .sAdd(userKey(userId), familyId)
        .expire(userKey(userId), TTL)
        .exec();
}

// Atomically read and delete a refresh token from Redis
export async function consumeRefreshToken(token: string): Promise<StoredRefreshToken | null> {
    const raw = await redis.getDel(tokenKey(sha256(token)));
    return raw ? (JSON.parse(raw) as StoredRefreshToken) : null;
}

// Revoke an entire refresh token family upon detection of reuse
export async function revokeFamily(familyId: string): Promise<void> {
    const hash = await redis.getDel(familyKey(familyId));
    if (hash) await redis.del(tokenKey(hash));
}

// Revoke all active refresh token families for a specified user
export async function revokeAllForUser(userId: string): Promise<void> {
    const families = await redis.sMembers(userKey(userId));
    await Promise.all(families.map(revokeFamily));
    await redis.del(userKey(userId));
}