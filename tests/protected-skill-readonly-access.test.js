import assert from "node:assert/strict";
import { mkdtemp, mkdir, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import { BLOCK_REASON_PROTECTED_PATH } from "../src/config.js";
import { createClawAegisRuntime } from "../src/handlers.js";

const CLAW_AEGIS_DIR = fileURLToPath(new URL("..", import.meta.url));
const PLUGIN_ID = "claw-aegis";

async function createTestRuntime(t, pluginConfig = {}) {
  const stateDir = await mkdtemp(path.join(os.tmpdir(), "skill-readonly-test-"));
  t.after(async () => {
    await rm(stateDir, { recursive: true, force: true });
  });

  const logger = {
    debug() {},
    info() {},
    warn() {},
    error() {},
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
    stateDir,
  };
}

test("protected skill directories remain readable while writes and deletes stay blocked", async (t) => {
  const { runtime, stateDir } = await createTestRuntime(t, {
    startupSkillScan: false,
    protectedSkills: ["agent-browser"],
    protectedPaths: ["protected/config.json"],
  });

  const skillFile = path.join(stateDir, "skills", "agent-browser", "SKILL.md");
  const protectedFile = path.join(stateDir, "protected", "config.json");
  await mkdir(path.dirname(skillFile), { recursive: true });
  await mkdir(path.dirname(protectedFile), { recursive: true });
  await writeFile(skillFile, "# agent-browser\n", "utf8");
  await writeFile(protectedFile, '{ "secret": true }\n', "utf8");

  await runtime.hooks.gateway_start();

  assert.equal(
    runtime.hooks.before_tool_call(
      { toolName: "read", params: { path: skillFile } },
      { sessionKey: "agent:main:skill-readonly", runId: "run-read-skill" },
    ),
    undefined,
  );

  assert.equal(
    runtime.hooks.before_tool_call(
      { toolName: "exec", params: { command: `cat "${skillFile}"` } },
      { sessionKey: "agent:main:skill-readonly", runId: "run-cat-skill" },
    ),
    undefined,
  );

  assert.equal(
    runtime.hooks.before_tool_call(
      { toolName: "exec", params: { command: `sed -n '1,5p' "${skillFile}"` } },
      { sessionKey: "agent:main:skill-readonly", runId: "run-sed-skill" },
    ),
    undefined,
  );

  assert.deepEqual(
    runtime.hooks.before_tool_call(
      {
        toolName: "edit",
        params: {
          path: skillFile,
          oldText: "agent-browser",
          newText: "patched",
        },
      },
      { sessionKey: "agent:main:skill-readonly", runId: "run-edit-skill" },
    ),
    {
      block: true,
      blockReason: BLOCK_REASON_PROTECTED_PATH,
    },
  );

  assert.deepEqual(
    runtime.hooks.before_tool_call(
      { toolName: "exec", params: { command: `rm -f "${skillFile}"` } },
      { sessionKey: "agent:main:skill-readonly", runId: "run-rm-skill" },
    ),
    {
      block: true,
      blockReason: BLOCK_REASON_PROTECTED_PATH,
    },
  );

  assert.deepEqual(
    runtime.hooks.before_tool_call(
      { toolName: "read", params: { path: protectedFile } },
      { sessionKey: "agent:main:skill-readonly", runId: "run-read-config" },
    ),
    {
      block: true,
      blockReason: BLOCK_REASON_PROTECTED_PATH,
    },
  );
});

test("protected skill helper scripts can execute only when every path candidate stays inside the skill root", async (t) => {
  const { runtime, stateDir } = await createTestRuntime(t, {
    startupSkillScan: false,
    protectedSkills: ["hkex-stock-summary"],
  });

  const helperFile = path.join(
    stateDir,
    "skills",
    "hkex-stock-summary",
    "scripts",
    "extract-hkex-quote.mjs",
  );
  const outsideFile = path.join(stateDir, "workspace", "outside.json");
  await mkdir(path.dirname(helperFile), { recursive: true });
  await mkdir(path.dirname(outsideFile), { recursive: true });
  await writeFile(helperFile, "console.log('ok');\n", "utf8");

  await runtime.hooks.gateway_start();

  assert.equal(
    runtime.hooks.before_tool_call(
      { toolName: "exec", params: { command: `node "${helperFile}" 2` } },
      { sessionKey: "agent:main:helper-exec", runId: "run-helper-allowed" },
    ),
    undefined,
  );

  assert.deepEqual(
    runtime.hooks.before_tool_call(
      { toolName: "exec", params: { command: `node "${helperFile}" "${outsideFile}"` } },
      { sessionKey: "agent:main:helper-exec", runId: "run-helper-blocked" },
    ),
    {
      block: true,
      blockReason: BLOCK_REASON_PROTECTED_PATH,
    },
  );
});
