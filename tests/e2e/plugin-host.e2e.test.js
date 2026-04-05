import assert from "node:assert/strict";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import path from "node:path";
import test from "node:test";

import defaultPlugin from "../../index.js";
import { createClawAegisRuntime } from "../../src/handlers.js";
import {
  CLAW_AEGIS_HOOK_NAMES,
  createPluginHostHarness,
  createRuntimeHooks,
} from "./plugin-host-harness.js";

test("plugin entry registers every expected hook with the host harness", async (t) => {
  const harness = await createPluginHostHarness(t);
  await harness.registerPluginEntry(defaultPlugin);

  assert.equal(defaultPlugin.id, "claw-aegis");
  assert.equal(defaultPlugin.name, "Claw Aegis");
  assert.deepEqual(harness.listRegisteredHooks(), [...CLAW_AEGIS_HOOK_NAMES].sort());
  for (const hookName of CLAW_AEGIS_HOOK_NAMES) {
    assert.equal(harness.registeredHandlerCount(hookName), 1);
  }
});

test("gateway_start persists self-integrity state in the plugin state directory", async (t) => {
  const harness = await createPluginHostHarness(t, {
    pluginConfig: {
      startupSkillScan: false,
    },
  });
  await harness.registerClawAegis();

  const dispatchResult = await harness.dispatch("gateway_start", {}, {});

  assert.equal(dispatchResult.result, undefined);
  const integrityRecord = await harness.readPluginStateJson("self-integrity.json");
  assert.equal(integrityRecord.pluginId, "claw-aegis");
  assert.ok(Array.isArray(integrityRecord.protectedRoots));
  assert.ok(integrityRecord.protectedRoots.length >= 1);
  assert.equal(typeof integrityRecord.fingerprints["src/prompt-sanitizer.ts"], "string");
  assert.ok(
    harness.findLogs(/"event":"self_integrity_refreshed"/).length >= 1,
  );
});

test("gateway_start reconciles managed overlays and persists managed-overlay-state", async (t) => {
  const harness = await createPluginHostHarness(t, {
    pluginConfig: {
      startupSkillScan: false,
      managedOverlays: [
        {
          id: "main-models",
          authorityPath: "authority/models.json",
          livePath: "live/agents/main/agent/models.json",
          reconcileMode: "enforce",
        },
      ],
    },
  });

  const authorityPath = path.join(harness.stateRoot, "authority", "models.json");
  const livePath = path.join(harness.stateRoot, "live", "agents", "main", "agent", "models.json");
  await mkdir(path.dirname(authorityPath), { recursive: true });
  await writeFile(authorityPath, '{ "model": "deepseek-chat" }\n', "utf8");

  await harness.registerClawAegis();
  await harness.dispatch("gateway_start", {}, {});

  const overlayState = await harness.readPluginStateJson("managed-overlay-state.json");
  assert.equal(await readFile(livePath, "utf8"), '{ "model": "deepseek-chat" }\n');
  assert.equal(overlayState.version, 1);
  assert.equal(overlayState.records[0].id, "main-models");
  assert.equal(overlayState.records[0].lastAction, "copied_to_live");
  assert.ok(harness.findLogs(/"event":"managed_overlays_reconciled"/).length >= 1);
});

test("fail-open wrapper returns undefined and logs an error when a hook handler throws", async (t) => {
  const harness = await createPluginHostHarness(t);
  await harness.registerClawAegis(() =>
    createRuntimeHooks({
      message_sending() {
        throw new Error("boom from test");
      },
    }),
  );

  const dispatchResult = await harness.dispatch(
    "message_sending",
    { to: "llm", content: "hello" },
    { sessionKey: "agent:main:e2e", runId: "run-fail-open" },
  );

  assert.equal(dispatchResult.result, undefined);
  assert.ok(
    harness.findLogs(/\[claw-aegis\] message_sending failed; fail-open keeps OpenClaw running/).length >=
      1,
  );
});

test("multi-hook flow propagates runtime risk into prompt guard context and cleanup resets state", async (t) => {
  const harness = await createPluginHostHarness(t, {
    pluginConfig: {
      outputRedactionEnabled: false,
      llmPromptSanitizationMode: "observe",
      startupSkillScan: false,
    },
  });
  await harness.registerClawAegis((api) => createClawAegisRuntime(api));

  const cleanPrompt = await harness.dispatch(
    "before_prompt_build",
    { prompt: "Summarize the market close." },
    { sessionKey: "agent:main:clean" },
  );

  await harness.dispatch(
    "message_sending",
    {
      to: "llm",
      content: "Email alice@example.com and call +86 13800138000 about sk-1234567890abcdefABCDEF.",
    },
    { sessionKey: "agent:main:risk", runId: "run-risk" },
  );

  const riskPrompt = await harness.dispatch(
    "before_prompt_build",
    { prompt: "Summarize the market close." },
    { sessionKey: "agent:main:risk" },
  );

  assert.equal(typeof cleanPrompt.result?.prependSystemContext, "string");
  assert.equal(typeof riskPrompt.result?.prependSystemContext, "string");
  assert.notEqual(riskPrompt.result.prependSystemContext, cleanPrompt.result.prependSystemContext);
  assert.ok(
    riskPrompt.result.prependSystemContext.length > cleanPrompt.result.prependSystemContext.length,
  );
  assert.ok(harness.runtime.state.peekRunSecurityState("run-risk"));
  assert.ok(harness.runtime.state.peekPromptState("agent:main:risk") === undefined);

  const riskPromptAfterConsume = await harness.dispatch(
    "before_prompt_build",
    { prompt: "Summarize again." },
    { sessionKey: "agent:main:risk" },
  );
  assert.equal(
    riskPromptAfterConsume.result.prependSystemContext,
    cleanPrompt.result.prependSystemContext,
  );

  await harness.dispatch(
    "message_sending",
    {
      to: "llm",
      content: "Call +1 415-555-2671 tomorrow.",
    },
    { sessionKey: "agent:main:cleanup", runId: "run-cleanup" },
  );
  assert.ok(harness.runtime.state.peekPromptState("agent:main:cleanup"));
  assert.ok(harness.runtime.state.peekRunSecurityState("run-cleanup"));

  await harness.dispatch("session_end", {}, { sessionKey: "agent:main:cleanup" });
  assert.equal(harness.runtime.state.peekPromptState("agent:main:cleanup"), undefined);
  assert.equal(harness.runtime.state.peekRunSecurityState("run-cleanup"), undefined);

  await harness.dispatch("agent_end", {}, { sessionKey: "agent:main:risk", runId: "run-risk" });
  assert.equal(harness.runtime.state.peekRunSecurityState("run-risk"), undefined);
  assert.equal(harness.runtime.state.peekPromptState("agent:main:risk"), undefined);
});
