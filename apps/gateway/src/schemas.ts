import { z } from "zod";

export const chatMessageSchema = z.object({
  role: z.enum(["system", "developer", "user", "assistant"]),
  content: z.string().min(1).max(20_000)
});

export const contextChunkSchema = z.object({
  source_id: z.string().min(1).max(256),
  trust: z.enum(["internal", "partner", "external", "unknown"]).default("unknown"),
  content: z.string().min(1).max(20_000)
});

export const secureChatRequestSchema = z.object({
  session_id: z.string().min(1).max(256),
  user_id: z.string().min(1).max(256),
  model: z.string().min(1).max(128).default("gpt-4.1-mini"),
  messages: z.array(chatMessageSchema).min(1).max(100),
  context: z.array(contextChunkSchema).max(100).default([]),
  requested_tools: z.array(z.string().min(1).max(128)).max(50).default([]),
  user_confirmed_tools: z.array(z.string().min(1).max(128)).max(50).default([]),
  metadata: z.record(z.string(), z.string()).optional()
});

export const agentGateRequestSchema = z.object({
  session_id: z.string().min(1).max(256),
  user_id: z.string().min(1).max(256),
  prompt: z.string().min(1).max(20_000),
  context: z.array(contextChunkSchema).max(100).default([]),
  requested_tools: z.array(z.string().min(1).max(128)).max(50).default([]),
  user_confirmed_tools: z.array(z.string().min(1).max(128)).max(50).default([]),
  metadata: z.record(z.string(), z.string()).optional()
});

export const redTeamRunSchema = z.object({
  suite: z.enum(["prompt_injection_core"]).default("prompt_injection_core"),
  target_model: z.string().min(1).max(128).default("gpt-4.1-mini"),
  fail_threshold: z
    .object({
      max_successful_attacks: z.number().int().nonnegative().default(3),
      min_detection_rate: z.number().min(0).max(1).default(0.9)
    })
    .default({
      max_successful_attacks: 3,
      min_detection_rate: 0.9
    })
});

export const contextScanRequestSchema = z.object({
  session_id: z.string().min(1).max(256).optional(),
  user_id: z.string().min(1).max(256).optional(),
  context: z.array(contextChunkSchema).min(1).max(500),
  metadata: z.record(z.string(), z.string()).optional()
});

export const listSecurityEventsQuerySchema = z.object({
  limit: z.coerce.number().int().min(1).max(200).default(50),
  event_type: z.enum(["secure_chat", "redteam_run", "context_scan", "agent_gate"]).optional(),
  decision: z.string().min(1).max(64).optional()
});
