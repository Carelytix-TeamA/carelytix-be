import {z} from "zod";

export const registerSchema = z.object({
  name: z
    .string()
    .min(2, {message: "Name must be at least 2 characters long"})
    .max(50, {message: "Name must be at most 50 characters long"}),

  email: z.string().email({message: "Invalid email address"}),

  password: z
    .string()
    .min(8, {message: "Password must be at least 8 characters long"})
    .max(100, {message: "Password must be at most 100 characters long"}),
});
export const loginSchema = z.object({
  email: z
    .string()
    .regex(/^[^\s@]+@[^\s@]+\.[^\s@]+$/, "Invalid email address"),
  password: z.string(),
});
