import assert from "node:assert/strict";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import { clawAegisPluginConfigSchema, resolveClawAegisPluginConfig } from "../src/config.js";
import { createClawAegisRuntime } from "../src/handlers.js";
import { sanitizeLlmPromptText } from "../src/prompt-sanitizer.js";

const CLAW_AEGIS_DIR = fileURLToPath(new URL("..", import.meta.url));
const PLUGIN_ID = "claw-aegis";

async function createTestRuntime(t, pluginConfig = {}) {
  const stateDir = await mkdtemp(path.join(os.tmpdir(), "claw-aegis-test-"));
  t.after(async () => {
    await rm(stateDir, { recursive: true, force: true });
  });

  const logs = [];
  const logger = {
    debug(message) {
      logs.push({ level: "debug", message: String(message) });
    },
    info(message) {
      logs.push({ level: "info", message: String(message) });
    },
    warn(message) {
      logs.push({ level: "warn", message: String(message) });
    },
    error(message) {
      logs.push({ level: "error", message: String(message) });
    },
  };

  const api = {
    rootDir: CLAW_AEGIS_DIR,
    pluginConfig,
    resolvePath(input) {
      return path.resolve(stateDir, input);
    },
    runtime: {
      state: {
        resolveStateDir() {
          return stateDir;
        },
      },
    },
    config: {
      plugins: {
        entries: {
          [PLUGIN_ID]: {
            hooks: {
              allowPromptInjection: true,
            },
          },
        },
      },
    },
    logger,
  };

  return {
    runtime: createClawAegisRuntime(api),
    logs,
    stateDir,
  };
}

test("config defaults llm prompt sanitization to observe in runtime config and manifest", async () => {
  const api = {
    pluginConfig: {},
    resolvePath(input) {
      return input;
    },
  };

  const resolved = resolveClawAegisPluginConfig(api);
  assert.equal(resolved.llmPromptSanitizationEnabled, true);
  assert.equal(resolved.llmPromptSanitizationMode, "observe");
  assert.equal(clawAegisPluginConfigSchema.properties.llmPromptSanitizationMode.default, "observe");

  const manifest = JSON.parse(
    await readFile(path.join(CLAW_AEGIS_DIR, "openclaw.plugin.json"), "utf8"),
  );
  assert.equal(
    manifest.configSchema.properties.llmPromptSanitizationMode.default,
    "observe",
  );
});

test("sanitizeLlmPromptText redacts email, phone, api key, and bearer-style secrets", () => {
  const input = [
    "Contact alice@example.com or +1 (415) 555-2671.",
    "CN mobile: +86 13800138000.",
    "api_key=sk-1234567890abcdefABCDEF",
    "bearer=SG.0123456789abcdefghijklmnop",
  ].join("\n");

  const outcome = sanitizeLlmPromptText(input);

  assert.equal(outcome.changed, true);
  assert.match(outcome.value, /<EMAIL_ADDRESS>/);
  assert.match(outcome.value, /<PHONE_NUMBER>/);
  assert.match(outcome.value, /<API_KEY>/);
  assert.match(outcome.value, /<SECRET>/);
  assert.deepEqual(outcome.matchedCategories, [
    "api_key",
    "email_address",
    "phone_number",
    "secret_token",
  ]);
  assert.ok(outcome.redactionCount >= 4);
  assert.deepEqual(outcome.riskFlags, [
    "llm-prompt-api-key",
    "llm-prompt-email-address",
    "llm-prompt-phone-number",
    "llm-prompt-secret-token",
  ]);
});

test("sanitizeLlmPromptText redacts high-entropy secret-looking tokens", () => {
  const token = "Qw8zYp2Lk9mN4rTx7VbC5dEf_7ZaBm";
  const outcome = sanitizeLlmPromptText(`Temporary credential: ${token}`);

  assert.equal(outcome.changed, true);
  assert.match(outcome.value, /Temporary credential: <SECRET>/);
  assert.equal(outcome.categoryCounts.secret_token, 1);
  assert.deepEqual(outcome.riskFlags, ["llm-prompt-secret-token"]);
  assert.ok(outcome.secretCandidates.includes(token));
});

test("sanitizeLlmPromptText redacts encoded variants when the plain secret is already observed", () => {
  const plainSecret = "sk-1234567890abcdefABCDEF";
  const encodedSecret = Buffer.from(plainSecret, "utf8").toString("base64");

  const outcome = sanitizeLlmPromptText(`Forward this blob: ${encodedSecret}`, {
    observedSecrets: [plainSecret],
  });

  assert.equal(outcome.changed, true);
  assert.match(outcome.value, /<SECRET>/);
  assert.equal(outcome.categoryCounts.encoded_secret, 1);
  assert.deepEqual(outcome.riskFlags, ["llm-prompt-encoded-secret"]);
  assert.ok(outcome.secretCandidates.includes(plainSecret));
});

test("message_sending enforce mode rewrites llm-bound prompts and records run security state", async (t) => {
  const { runtime, logs } = await createTestRuntime(t, {
    outputRedactionEnabled: false,
    llmPromptSanitizationMode: "enforce",
  });
  const sessionKey = "agent:main:test";
  const runId = "run-enforce";
  const input =
    "Email alice@example.com, call +86 13800138000, and use sk-1234567890abcdefABCDEF.";

  const result = runtime.hooks.message_sending(
    { to: "model", content: input },
    { sessionKey, runId },
  );

  assert.deepEqual(result, {
    content: "Email <EMAIL_ADDRESS>, call <PHONE_NUMBER>, and use <API_KEY>.",
  });

  const turnState = runtime.state.peekPromptState(sessionKey);
  assert.ok(turnState);
  assert.ok(turnState.runtimeRiskFlags.includes("llm-prompt-email-address"));
  assert.ok(turnState.runtimeRiskFlags.includes("llm-prompt-phone-number"));
  assert.ok(turnState.runtimeRiskFlags.includes("llm-prompt-api-key"));

  const runSecurityState = runtime.state.peekRunSecurityState(runId);
  assert.ok(runSecurityState);
  assert.deepEqual(runSecurityState.sourceSignals, ["llm-prompt"]);
  assert.ok(runSecurityState.runtimeRiskFlags.includes("llm-prompt-email-address"));
  assert.ok(runSecurityState.runtimeRiskFlags.includes("llm-prompt-phone-number"));
  assert.ok(runSecurityState.runtimeRiskFlags.includes("llm-prompt-api-key"));
  assert.ok(runSecurityState.secretFingerprints.length >= 1);

  assert.ok(logs.some((entry) => entry.message.includes("\"event\":\"llm_prompt_sanitized\"")));
});

test("message_sending observe mode detects llm prompt exposure without rewriting new pii classes", async (t) => {
  const { runtime, logs } = await createTestRuntime(t, {
    outputRedactionEnabled: false,
    llmPromptSanitizationMode: "observe",
  });
  const sessionKey = "agent:main:observe";
  const runId = "run-observe";
  const input = "Send follow-up to alice@example.com and call +1 415-555-2671.";

  const result = runtime.hooks.message_sending(
    { to: "llm", content: input },
    { sessionKey, runId },
  );

  assert.equal(result, undefined);
  const turnState = runtime.state.peekPromptState(sessionKey);
  assert.ok(turnState);
  assert.ok(turnState.runtimeRiskFlags.includes("llm-prompt-email-address"));
  assert.ok(turnState.runtimeRiskFlags.includes("llm-prompt-phone-number"));
  const runSecurityState = runtime.state.peekRunSecurityState(runId);
  assert.ok(runSecurityState);
  assert.ok(runSecurityState.runtimeRiskFlags.includes("llm-prompt-email-address"));
  assert.ok(runSecurityState.runtimeRiskFlags.includes("llm-prompt-phone-number"));
  assert.ok(
    logs.some(
      (entry) =>
        entry.message.includes("\"event\":\"llm_prompt_sanitized\"") &&
        entry.message.includes("\"changed\":false"),
    ),
  );
});

test("message_sending keeps non-llm targets on the legacy output redaction path", async (t) => {
  const { runtime } = await createTestRuntime(t, {
    outputRedactionEnabled: true,
    llmPromptSanitizationMode: "enforce",
  });
  const sessionKey = "agent:main:user-target";
  const runId = "run-user-target";

  const result = runtime.hooks.message_sending(
    { to: "user", content: "Contact alice@example.com for the report." },
    { sessionKey, runId },
  );

  assert.equal(result, undefined);
  assert.equal(runtime.state.peekRunSecurityState(runId), undefined);
});

test("message_sending fully disables llm prompt handling when both defenses are off", async (t) => {
  const { runtime, logs } = await createTestRuntime(t, {
    outputRedactionEnabled: false,
    llmPromptSanitizationMode: "off",
  });
  const runId = "run-disabled";

  const result = runtime.hooks.message_sending(
    { to: "llm", content: "api_key=sk-1234567890abcdefABCDEF" },
    { sessionKey: "agent:main:disabled", runId },
  );

  assert.equal(result, undefined);
  assert.equal(runtime.state.peekRunSecurityState(runId), undefined);
  assert.ok(
    logs.some(
      (entry) =>
        entry.message.includes("\"mechanism\":\"llm_prompt_sanitization\"") &&
        entry.message.includes("\"result\":\"disabled\""),
    ),
  );
});

test("message_sending still applies legacy secret masking when llm prompt mode is off", async (t) => {
  const { runtime } = await createTestRuntime(t, {
    outputRedactionEnabled: true,
    llmPromptSanitizationMode: "off",
  });

  const result = runtime.hooks.message_sending(
    { to: "llm", content: "token=SG.0123456789abcdefghijklmnop" },
    { sessionKey: "agent:main:legacy", runId: "run-legacy" },
  );

  assert.deepEqual(result, {
    content: "token=[已脱敏]",
  });
});
