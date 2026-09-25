import { z } from "zod";

const emailSchema = z.string().trim().email().max(254);
const passwordSchema = z.string().min(12).max(256);
const clientIdSchema = z.string().trim().min(3).max(128);
const audienceSchema = z.string().trim().min(2).max(128);

export const registerRequestSchema = z.object({
  email: emailSchema,
  password: passwordSchema,
  client_id: clientIdSchema,
  audience: audienceSchema.optional(),
  scope: z.array(z.string().trim().min(1).max(64)).max(20).optional()
});

export const loginRequestSchema = z.object({
  email: emailSchema,
  password: z.string().min(1).max(256),
  client_id: clientIdSchema,
  audience: audienceSchema.optional(),
  scope: z.array(z.string().trim().min(1).max(64)).max(20).optional()
});

export const refreshRequestSchema = z.object({
  refresh_token: z.string().trim().min(32).max(4096),
  client_id: clientIdSchema,
  audience: audienceSchema.optional(),
  scope: z.array(z.string().trim().min(1).max(64)).max(20).optional()
});

export const introspectRequestSchema = z.object({
  token: z.string().trim().min(32).max(8192)
});

export const revokeRequestSchema = z.object({
  refresh_token: z.string().trim().min(32).max(4096),
  client_id: clientIdSchema
});
