// Chatterbox — AI support-desk backend
// Vercel Serverless Function
//
// This keeps the AI API key on the server instead of exposing it
// in the browser.
//
// Expected request:
// POST /api/chat
// {
//   "messages": [...],
//   "system": "..."
// }
//
// Environment variable:
// ANTHROPIC_API_KEY
//
// Optional:
// ANTHROPIC_MODEL

function json(res, status, body) {
  res.status(status).setHeader(
    "Content-Type",
    "application/json; charset=utf-8"
  );

  res.setHeader("Cache-Control", "no-store");

  return res.end(JSON.stringify(body));
}

function getBody(req) {
  if (!req.body) return {};

  if (typeof req.body === "object") {
    return req.body;
  }

  try {
    return JSON.parse(req.body);
  } catch {
    return {};
  }
}

function cleanMessages(messages) {
  if (!Array.isArray(messages)) return [];

  return messages
    .filter(
      m =>
        m &&
        typeof m === "object" &&
        (m.role === "user" || m.role === "assistant")
    )
    .map(m => ({
      role: m.role,
      content:
        typeof m.content === "string"
          ? m.content.slice(0, 100000)
          : String(m.content || "")
    }))
    .filter(m => m.content.trim());
}

async function handler(req, res) {
  if (req.method !== "POST") {
    return json(res, 405, {
      error: "POST only."
    });
  }

  const apiKey = process.env.ANTHROPIC_API_KEY;

  if (!apiKey) {
    return json(res, 500, {
      error:
        "ANTHROPIC_API_KEY is not configured on the server."
    });
  }

  try {
    const body = getBody(req);

    const system =
      typeof body.system === "string"
        ? body.system.slice(0, 100000)
        : "";

    const messages = cleanMessages(body.messages);

    if (!messages.length) {
      return json(res, 400, {
        error: "At least one message is required."
      });
    }

    const model =
      process.env.ANTHROPIC_MODEL ||
      "claude-sonnet-4-5";

    const response = await fetch(
      "https://api.anthropic.com/v1/messages",
      {
        method: "POST",

        headers: {
          "Content-Type": "application/json",
          "x-api-key": apiKey,
          "anthropic-version": "2023-06-01"
        },

        body: JSON.stringify({
          model,

          max_tokens: 4000,

          ...(system
            ? {
                system
              }
            : {}),

          messages
        })
      }
    );

    const raw = await response.text();

    let data;

    try {
      data = JSON.parse(raw);
    } catch {
      data = {
        error: raw
      };
    }

    if (!response.ok) {
      return json(res, response.status, {
        error:
          data?.error?.message ||
          data?.message ||
          "The AI service returned an error."
      });
    }

    const text = Array.isArray(data.content)
      ? data.content
          .filter(block => block && block.type === "text")
          .map(block => block.text || "")
          .join("\n")
          .trim()
      : "";

    return json(res, 200, {
      ok: true,
      text,
      usage: data.usage || null
    });

  } catch (err) {
    console.error("Chatterbox AI error:", err);

    return json(res, 500, {
      error:
        err?.message ||
        "Unable to contact the AI service."
    });
  }
}

module.exports = handler;
