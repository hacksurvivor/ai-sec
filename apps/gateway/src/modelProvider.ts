import type { z } from "zod";
import type { secureChatRequestSchema } from "./schemas.js";
import { config } from "./config.js";

type SecureChatRequest = z.infer<typeof secureChatRequestSchema>;

function generateMockResponse(request: SecureChatRequest): string {
  const lastUserMessage = [...request.messages].reverse().find((message) => message.role === "user")?.content ?? "";
  const compact = lastUserMessage.replace(/\s+/g, " ").trim().slice(0, 300);

  return `Request received. Safe summary: ${compact}`;
}

function buildPrompt(messages: SecureChatRequest["messages"]): string {
  return messages
    .slice(-12)
    .map((message) => `${message.role.toUpperCase()}: ${message.content}`)
    .join("\n\n");
}

async function generateWithOllama(request: SecureChatRequest): Promise<string> {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), config.modelTimeoutMs);

  try {
    const response = await fetch(`${config.ollamaBaseUrl.replace(/\/$/, "")}/api/generate`, {
      method: "POST",
      headers: {
        "content-type": "application/json"
      },
      body: JSON.stringify({
        model: config.ollamaModel,
        prompt: buildPrompt(request.messages),
        stream: false
      }),
      signal: controller.signal
    });

    if (!response.ok) {
      throw new Error(`Ollama request failed with status ${response.status}`);
    }

    const payload = (await response.json()) as { response?: string };
    const text = payload.response?.trim();
    if (!text) {
      throw new Error("Ollama returned empty response");
    }

    return text.slice(0, 8000);
  } finally {
    clearTimeout(timeout);
  }
}

export async function generateModelResponse(request: SecureChatRequest): Promise<string> {
  if (config.modelProvider === "mock") {
    return generateMockResponse(request);
  }

  if (config.modelProvider === "ollama") {
    return generateWithOllama(request);
  }

  return generateMockResponse(request);
}
