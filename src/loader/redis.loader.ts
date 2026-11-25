import dotenv from "dotenv";
dotenv.config();
import { createClient } from "redis";
import type {SetOptions} from "redis"

interface MemoryEntry {
    value: string;
    expiresAt: number | null;
}

type MultiOp =
    | { type: "set"; args: [key: string, value: string | number, options?: SetOptions] }
    | { type: "sAdd"; args: [key: string, member: string] }
    | { type: "expire"; args: [key: string, seconds: number] };

export interface RedisMulti {
    set(key: string, value: string | number, options?: SetOptions): RedisMulti;
    sAdd(key: string, member: string): RedisMulti;
    expire(key: string, seconds: number): RedisMulti;
    exec(): Promise<unknown[]>;
}

// In-memory fallback store used automatically if Redis is unreachable
const memoryStore = new Map<string, MemoryEntry>();
const memorySets = new Map<string, Set<string>>();

function resolveRedisUrl(): string | null {
    const candidates = [
        process.env.REDIS_URL_REDIS_URL,
        process.env.REDIS_URL_KV_URL,
        process.env.REDIS_URL,
        process.env.KV_URL,
        process.env.STORAGE_REDIS_URL,
        process.env.STORAGE_KV_URL,
        ...Object.entries(process.env)
            .filter(
                (entry): entry is [string, string] =>
                    typeof entry[1] === "string" &&
                    (entry[1].startsWith("redis://") || entry[1].startsWith("rediss://")) &&
                    (entry[0].includes("REDIS") ||
                        entry[0].includes("KV") ||
                        entry[0].endsWith("_URL"))
            )
            .map(([, v]) => v),
    ].filter((v): v is string => typeof v === "string" && v.trim().length > 0);

    const cloudCandidate = candidates.find(
        (v) => !v.includes("localhost") && !v.includes("127.0.0.1")
    );

    return cloudCandidate ?? candidates[0] ?? null;
}

const resolvedRedisUrl = resolveRedisUrl();

const rawClient = resolvedRedisUrl
    ? createClient({
          url: resolvedRedisUrl,
          socket: {
              connectTimeout: 5000,
              reconnectStrategy: (retries: number) => (retries < 2 ? 250 : false),
          },
      })
    : null;

if (rawClient) {
    rawClient.on("error", (err: unknown) => {
        const message = err instanceof Error ? err.message : String(err);
        console.warn("redis warning:", message);
    });
}

let connectingPromise: Promise<boolean> | null = null;

// Connect the Redis client if configured and not already open
const connectRedis = async (): Promise<boolean> => {
    if (!rawClient) return false;
    if (rawClient.isOpen) return true;
    if (connectingPromise) return connectingPromise;

    connectingPromise = rawClient
        .connect()
        .then(() => {
            console.log("redis has been connected");
            return true;
        })
        .catch((err: unknown) => {
            const message = err instanceof Error ? err.message : String(err);
            console.warn("Redis unavailable, using in-memory fallback:", message);
            return false;
        })
        .finally(() => {
            connectingPromise = null;
        });

    return connectingPromise;
};

// Disconnect the Redis client if currently connected
const disconnectRedis = async (): Promise<void> => {
    if (rawClient && rawClient.isOpen) {
        await rawClient.quit();
        console.log("redis has been disconnected");
    }
};

const isReady = (): boolean => Boolean(rawClient && rawClient.isOpen);

const ensureReady = async (): Promise<boolean> => {
    if (isReady()) return true;
    return connectRedis();
};

const redisClient = {
    get isOpen(): boolean {
        return isReady();
    },

    async get(key: string): Promise<string | null> {
        if (rawClient && (await ensureReady())) return rawClient.get(key);
        const entry = memoryStore.get(key);
        if (!entry) return null;
        if (entry.expiresAt && Date.now() > entry.expiresAt) {
            memoryStore.delete(key);
            return null;
        }
        return entry.value;
    },

    async set(
        key: string,
        value: string | number,
        options: SetOptions = {}
    ): Promise<string | null> {
        const serialized = String(value);
        if (rawClient && (await ensureReady())) {
            return rawClient.set(key, serialized, options);
        }
        if (options.NX) {
            const existing = await this.get(key);
            if (existing !== null) return null;
        }
        const expiresAt = options.EX ? Date.now() + options.EX * 1000 : null;
        memoryStore.set(key, { value: serialized, expiresAt });
        return "OK";
    },

    async getDel(key: string): Promise<string | null> {
        if (rawClient && (await ensureReady())) return rawClient.getDel(key);
        const val = await this.get(key);
        memoryStore.delete(key);
        return val;
    },

    async del(keys: string | string[]): Promise<number> {
        if (rawClient && (await ensureReady())) return rawClient.del(keys);
        const list = Array.isArray(keys) ? keys : [keys];
        for (const k of list) {
            memoryStore.delete(k);
            memorySets.delete(k);
        }
        return list.length;
    },

    async incr(key: string): Promise<number> {
        if (rawClient && (await ensureReady())) return rawClient.incr(key);
        const current = Number((await this.get(key)) || 0) + 1;
        const existing = memoryStore.get(key);
        memoryStore.set(key, {
            value: String(current),
            expiresAt: existing?.expiresAt ?? null,
        });
        return current;
    },

    async expire(key: string, seconds: number): Promise<number | boolean> {
        if (rawClient && (await ensureReady())) return rawClient.expire(key, seconds);
        const existing = memoryStore.get(key);
        if (existing) {
            existing.expiresAt = Date.now() + seconds * 1000;
        }
        return 1;
    },

    async sAdd(key: string, member: string): Promise<number> {
        if (rawClient && (await ensureReady())) return rawClient.sAdd(key, member);
        let set = memorySets.get(key);
        if (!set) {
            set = new Set<string>();
            memorySets.set(key, set);
        }
        set.add(String(member));
        return 1;
    },

    async sMembers(key: string): Promise<string[]> {
        if (rawClient && (await ensureReady())) return rawClient.sMembers(key);
        return Array.from(memorySets.get(key) ?? []);
    },

    multi(): RedisMulti {
        const ops: MultiOp[] = [];
        return {
            set(k: string, v: string | number, opts?: SetOptions): RedisMulti {
                ops.push({ type: "set", args: [k, v, opts] });
                return this;
            },
            sAdd(k: string, m: string): RedisMulti {
                ops.push({ type: "sAdd", args: [k, m] });
                return this;
            },
            expire(k: string, s: number): RedisMulti {
                ops.push({ type: "expire", args: [k, s] });
                return this;
            },
            async exec(): Promise<unknown[]> {
                if (rawClient && (await ensureReady())) {
                    const m = rawClient.multi();
                    for (const op of ops) {
                        switch (op.type) {
                            case "set":
                                m.set(op.args[0], String(op.args[1]), op.args[2]);
                                break;
                            case "sAdd":
                                m.sAdd(op.args[0], op.args[1]);
                                break;
                            case "expire":
                                m.expire(op.args[0], op.args[1]);
                                break;
                        }
                    }
                    return m.exec();
                }

                const results: unknown[] = [];
                for (const op of ops) {
                    switch (op.type) {
                        case "set":
                            results.push(await redisClient.set(...op.args));
                            break;
                        case "sAdd":
                            results.push(await redisClient.sAdd(...op.args));
                            break;
                        case "expire":
                            results.push(await redisClient.expire(...op.args));
                            break;
                    }
                }
                return results;
            },
        };
    },
};

export default redisClient;
export { connectRedis, disconnectRedis };