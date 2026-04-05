#!/usr/bin/env node

import path from "node:path";
import { promises as fs } from "node:fs";

import {
  normalizeManagedOverlayConfigEntries,
  persistManagedOverlayStateFile,
  reconcileManagedOverlays,
} from "../src/managed-overlays.js";

function usage(message) {
  if (message) {
    console.error(message);
    console.error("");
  }
  console.error(
    "Usage: node scripts/managed-overlays-bootstrap.mjs --openclaw-config <path> [--plugin-id claw-aegis] [--state-file <path>]",
  );
  console.error(
    "   or: node scripts/managed-overlays-bootstrap.mjs --overlays-json '<json-array>' [--state-file <path>]",
  );
  process.exit(1);
}

function parseArgs(argv) {
  const options = {
    pluginId: "claw-aegis",
    openclawConfig: "",
    overlaysJson: "",
    stateFile: "",
  };

  for (let index = 0; index < argv.length; index += 1) {
    const arg = argv[index];
    if (arg === "--plugin-id") {
      options.pluginId = argv[index + 1] ?? "";
      index += 1;
      continue;
    }
    if (arg === "--openclaw-config") {
      options.openclawConfig = argv[index + 1] ?? "";
      index += 1;
      continue;
    }
    if (arg === "--overlays-json") {
      options.overlaysJson = argv[index + 1] ?? "";
      index += 1;
      continue;
    }
    if (arg === "--state-file") {
      options.stateFile = argv[index + 1] ?? "";
      index += 1;
      continue;
    }
    if (arg === "--help" || arg === "-h") {
      usage();
    }
    usage(`Unknown argument: ${arg}`);
  }

  if (!options.openclawConfig && !options.overlaysJson) {
    usage("Either --openclaw-config or --overlays-json is required.");
  }

  return options;
}

function createConsoleLogger() {
  return {
    info(message, meta) {
      console.error(`${message}${meta ? ` ${JSON.stringify(meta)}` : ""}`);
    },
    warn(message, meta) {
      console.error(`${message}${meta ? ` ${JSON.stringify(meta)}` : ""}`);
    },
    error(message, meta) {
      console.error(`${message}${meta ? ` ${JSON.stringify(meta)}` : ""}`);
    },
  };
}

async function loadRawOverlayConfig(options) {
  if (options.overlaysJson) {
    return JSON.parse(options.overlaysJson);
  }

  const openclawConfigPath = path.resolve(options.openclawConfig);
  const raw = JSON.parse(await fs.readFile(openclawConfigPath, "utf8"));
  return raw?.plugins?.entries?.[options.pluginId]?.config?.managedOverlays ?? [];
}

async function main() {
  const options = parseArgs(process.argv.slice(2));
  const openclawConfigPath = options.openclawConfig
    ? path.resolve(options.openclawConfig)
    : undefined;
  const resolveRelativeTo = openclawConfigPath ? path.dirname(openclawConfigPath) : process.cwd();
  const rawOverlayConfig = await loadRawOverlayConfig(options);
  const overlays = normalizeManagedOverlayConfigEntries(rawOverlayConfig, (input) =>
    path.isAbsolute(input) ? input : path.resolve(resolveRelativeTo, input),
  );

  const summary = await reconcileManagedOverlays({
    overlays,
    logger: createConsoleLogger(),
  });

  if (options.stateFile) {
    await persistManagedOverlayStateFile(path.resolve(options.stateFile), summary.records);
  }

  process.stdout.write(
    `${JSON.stringify(
      {
        ok: summary.errorCount === 0,
        overlayCount: overlays.length,
        copiedCount: summary.copiedCount,
        inSyncCount: summary.inSyncCount,
        observedDriftCount: summary.observedDriftCount,
        errorCount: summary.errorCount,
        records: summary.records,
      },
      null,
      2,
    )}\n`,
  );

  process.exit(summary.errorCount === 0 ? 0 : 1);
}

main().catch((error) => {
  console.error(error instanceof Error ? error.message : String(error));
  process.exit(1);
});
