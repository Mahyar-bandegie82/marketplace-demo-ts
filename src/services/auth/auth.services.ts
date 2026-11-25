import "dotenv/config";
import createError from "http-errors";
import bcrypt from 'bcrypt';
import { PrismaPg } from "@prisma/adapter-pg";
import { PrismaClient } from "../../generated/prisma/client.js";
import type { Prisma, User } from "../../generated/prisma/client.js";

const adapter = new PrismaPg({ connectionString: process.env["DATABASE_URL"]! });

export const prisma = new PrismaClient({ adapter });

const hashPassword = (password: string) => bcrypt.hash(password, 10);

export interface SignUpInput {
    userName: string;
    password: string;
    phoneNumber: string;
    email: string;
}

export interface LoginInput {
    userName: string;
    phoneNumber: string;
    password: string;
}

export interface ChangeUserInfoInput {
    userName?: string;
    phoneNumber?: string;
    email?: string;
    password?: string;
}

// Remove sensitive credentials like passwords from user object before returning to client
export function sanitizeUser<T extends { password?: unknown; refreshToken?: unknown }>(
    user: T
): Omit<T, "password" | "refreshToken"> {
    const { password: _password, refreshToken: _refreshToken, ...safeUser } = user;
    return safeUser;
}

// Fetch user profile by ID
export async function getProfile(id: number) {
    const user = await prisma.user.findUnique({ where: { id } });
    if (!user) throw createError(404, "user not found");
    return user;
}

// Register a new user, create client profile, and initialize an empty shopping cart
export async function signUp(json: SignUpInput) {
    const existing = await prisma.user.findFirst({
        where: { OR: [{ phoneNumber: json.phoneNumber }, { email: json.email }] },
    });
    if (existing) throw createError(409, "user already exists");

    const hashedPassword = await bcrypt.hash(json.password, 10);
    return prisma.$transaction(async (tx: Prisma.TransactionClient) => {
        const newUser = await tx.user.create({
            data: {
                userName: json.userName,
                password: hashedPassword,
                phoneNumber: json.phoneNumber,
                email: json.email,
            },
        });
        const client = await tx.client.create({
            data: {
                userId: newUser.id,
            },
        });
        await tx.shoppingCart.create({
            data: { clientId: client.id },
        });
        return newUser;
    });
}

// Authenticate user credentials and return user with associated roles
export async function login(json: LoginInput) {
    const user = await prisma.user.findUnique({
        where: { phoneNumber: json.phoneNumber },
        include: {
            admin: { select: { id: true } },
            seller: { select: { id: true, verified: true, storeName: true } },
            client: { select: { id: true } },
        },
    });

    if (
        !user ||
        json.userName !== user.userName ||
        !(await bcrypt.compare(json.password, user.password))
    ) {
        throw createError(401, "invalid username or password");
    }

    return user;
}

// Update user account details such as username, email, phone, or password
export async function changeUserInfo(userId: User["id"], json: ChangeUserInfoInput): Promise<User> {
    const data: Prisma.UserUpdateInput = {};
    if (json.userName) data.userName = json.userName;
    if (json.phoneNumber) data.phoneNumber = json.phoneNumber;
    if (json.email) data.email = json.email;
    if (json.password) data.password = await hashPassword(json.password);

    return prisma.user.update({ where: { id: userId }, data });
}

// Mark a user account as OTP verified
export async function markOtpVerified(userId: User["id"]) {
    return prisma.user.update({
        where: { id: userId },
        data: { otpVerified: true },
        include: {
            admin: { select: { id: true } },
            seller: { select: { id: true, verified: true, trusted: true, storeName: true } },
            client: { select: { id: true } },
        },
    });
}

// Set user account verification status to false
export async function unverifyUser(userId: User["id"]): Promise<User> {
    return prisma.user.update({ where: { id: userId }, data: { otpVerified: false } });
}