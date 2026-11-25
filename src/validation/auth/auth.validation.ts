import Joi from "joi";
import type { ObjectSchema, StringSchema } from "joi"

const PHONE_REGEX = /^09\d{9}$/;
const PASSWORD_REGEX = /^(?=(?:.*[A-Z]){2})(?=.*[^A-Za-z0-9])(?=(?:.*\d){2})[\x21-\x7E]{9,72}$/;
const USERNAME_REGEX = /^[A-Za-z0-9_.-]{3,30}$/;

export interface SignUpPayload {
    userName: string;
    password: string;
    phoneNumber: string;
    email: string;
}

export interface LoginPayload {
    userName: string;
    password: string;
    phoneNumber: string;
}

export interface ChangeCredentialsPayload {
    phoneNumber: string;
    changes: {
        userName?: string;
        phoneNumber?: string;
        password?: string;
        email?: string;
    };
}

export interface VerifyOtpPayload {
    otp: string;
}

const userName: StringSchema = Joi.string()
    .trim()
    .min(4)
    .max(20)
    .pattern(USERNAME_REGEX)
    .messages({
        "string.pattern.base":
            "userName must be 3-30 characters: letters, numbers, '_', '.' or '-'",
    });

const phoneNumber: StringSchema = Joi.string()
    .trim()
    .pattern(PHONE_REGEX)
    .messages({
        "string.pattern.base": "phoneNumber must look like 0918 885 1694",
    });

const email: StringSchema = Joi.string()
    .trim()
    .lowercase()
    .email()
    .max(254)
    .messages({
        "string.email": "email is not a valid email address",
    });

const newPassword: StringSchema = Joi.string()
    .pattern(PASSWORD_REGEX)
    .messages({
        "string.pattern.base":
            "password must be 9-72 characters with at least 2 capital letters, 2 numbers and 1 special character (e.g. @), and no spaces",
    });

const currentPassword: StringSchema = Joi.string().max(72);

const signUpSchema: ObjectSchema<SignUpPayload> = Joi.object<SignUpPayload>({
    userName: userName.required(),
    password: newPassword.required(),
    phoneNumber: phoneNumber.required(),
    email: email.required(),
});

const loginSchema: ObjectSchema<LoginPayload> = Joi.object<LoginPayload>({
    userName: userName.required(),
    password: currentPassword.required(),
    phoneNumber: phoneNumber.required(),
});

const changeCredentialsSchema: ObjectSchema<ChangeCredentialsPayload> =
    Joi.object<ChangeCredentialsPayload>({
        phoneNumber: phoneNumber.required(),
        changes: Joi.object<ChangeCredentialsPayload["changes"]>({
            userName,
            phoneNumber,
            password: newPassword,
            email,
        })
            .min(1)
            .required()
            .messages({
                "object.min":
                    "changes must contain at least one of: userName, phoneNumber, password",
            }),
    });

export const verifyOtpSchema: ObjectSchema<VerifyOtpPayload> = Joi.object<VerifyOtpPayload>({
    otp: Joi.string().trim().required().min(6).max(6),
});

export { loginSchema, changeCredentialsSchema, signUpSchema };