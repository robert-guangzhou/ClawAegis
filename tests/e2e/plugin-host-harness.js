import { mkdir, mkdtemp, readFile, rm } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

import defaultPlugin, { registerClawAegisPlugin } from "../../index.js";
import { createClawAegisRuntime } from "../../src/handlers.js";

export const CLAW_AEGIS_PLUGIN_ID = "claw-aegis";
export const CLAW_AEGIS_HOOK_NAMES = [
  "gateway_start",
  "message_received",
  "message_sending",
  "before_prompt_build",
  "before_tool_call",
  "after_tool_call",
  "before_message_write",
  "agent_end",
  "session_end",
];

const CLAW_AEGIS_DIR = fileURLToPath(new URL("../..", import.meta.url));

function createLogger(logs) {
  return {
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
}

export function createRuntimeHooks(overrides = {}) {
  const noop = () => undefined;
  return {
    hooks: {
      gateway_start: noop,
      message_received: noop,
      message_sending: noop,
      before_prompt_build: noop,
      before_tool_call: noop,
      after_tool_call: noop,
      before_message_write: noop,
      agent_end: noop,
      session_end: noop,
      ...overrides,
    },
  };
}

export async function createPluginHostHarness(t, options = {}) {
  const stateRoot = await mkdtemp(path.join(os.tmpdir(), "claw-aegis-e2e-"));
  const workspaceRoot = path.join(stateRoot, "workspace");
  await mkdir(workspaceRoot, { recursive: true });

  const logs = [];
  const handlers = new Map();
  const pluginEntryConfig = options.pluginEntryConfig ?? {
    plugins: {
      entries: {
        [CLAW_AEGIS_PLUGIN_ID]: {
          hooks: {
            allowPromptInjection: options.allowPromptInjection ?? true,
          },
        },
      },
    },
  };

  const api = {
    rootDir: options.rootDir ?? CLAW_AEGIS_DIR,
    pluginConfig: options.pluginConfig ?? {},
    resolvePath(input) {
      return path.resolve(stateRoot, input);
    },
    runtime: {
      state: {
        resolveStateDir() {
          return stateRoot;
        },
      },
    },
    config: pluginEntryConfig,
    logger: createLogger(logs),
    on(hookName, handler) {
      const nextHandlers = handlers.get(hookName) ?? [];
      nextHandlers.push(handler);
      handlers.set(hookName, nextHandlers);
    },
  };

  const harness = {
    api,
    logs,
    handlers,
    stateRoot,
    workspaceRoot,
    pluginStateDir: path.join(stateRoot, "plugins", CLAW_AEGIS_PLUGIN_ID),
    runtime: undefined,
    async registerPluginEntry(pluginEntry = defaultPlugin) {
      await pluginEntry.register(api);
      return harness;
    },
    async registerClawAegis(createRuntime = createClawAegisRuntime) {
      registerClawAegisPlugin(api, (hookApi) => {
        const runtime = createRuntime(hookApi);
        harness.runtime = runtime;
        return runtime;
      });
      return harness;
    },
    listRegisteredHooks() {
      return [...handlers.keys()].sort();
    },
    registeredHandlerCount(hookName) {
      return handlers.get(hookName)?.length ?? 0;
    },
    async dispatch(hookName, event = {}, ctx = {}) {
      const hookHandlers = handlers.get(hookName) ?? [];
      const results = [];
      for (const handler of hookHandlers) {
        results.push(await handler(event, ctx));
      }
      return {
        hookName,
        handlerCount: hookHandlers.length,
        results,
        result: results.at(-1),
      };
    },
    findLogs(pattern) {
      if (pattern instanceof RegExp) {
        return logs.filter((entry) => pattern.test(entry.message));
      }
      return logs.filter((entry) => entry.message.includes(String(pattern)));
    },
    async readPluginStateJson(filename) {
      const filePath = path.join(harness.pluginStateDir, filename);
      return JSON.parse(await readFile(filePath, "utf8"));
    },
    async dispose() {
      await harness.runtime?.scanService?.stop?.().catch(() => undefined);
      await rm(stateRoot, { recursive: true, force: true });
    },
  };

  if (t?.after) {
    t.after(async () => {
      await harness.dispose();
    });
  }

  return harness;
}
