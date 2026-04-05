import assert from "node:assert/strict";
import { execFile as execFileCallback } from "node:child_process";
import { mkdtemp, mkdir, readFile, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { promisify } from "node:util";

import {
  normalizeManagedOverlayConfigEntries,
  reconcileManagedOverlays,
} from "../src/managed-overlays.js";

const execFile = promisify(execFileCallback);

test("reconcileManagedOverlays copies authority into a missing live file in enforce mode", async (t) => {
  const tempRoot = await mkdtemp(path.join(os.tmpdir(), "claw-aegis-overlay-"));
  t.after(async () => {
    await rm(tempRoot, { recursive: true, force: true });
  });

  const authorityPath = path.join(tempRoot, "authority", "models.json");
  const livePath = path.join(tempRoot, "live", "models.json");
  await mkdir(path.dirname(authorityPath), { recursive: true });
  await writeFile(authorityPath, '{ "model": "deepseek-chat" }\n', "utf8");

  const overlays = normalizeManagedOverlayConfigEntries([
    {
      id: "main-models",
      authorityPath,
      livePath,
      reconcileMode: "enforce",
    },
  ]);

  const summary = await reconcileManagedOverlays({ overlays });

  assert.equal(summary.copiedCount, 1);
  assert.equal(summary.errorCount, 0);
  assert.equal(summary.records[0].lastAction, "copied_to_live");
  assert.equal(await readFile(livePath, "utf8"), '{ "model": "deepseek-chat" }\n');
});

test("reconcileManagedOverlays only observes drift in observe mode", async (t) => {
  const tempRoot = await mkdtemp(path.join(os.tmpdir(), "claw-aegis-overlay-"));
  t.after(async () => {
    await rm(tempRoot, { recursive: true, force: true });
  });

  const authorityPath = path.join(tempRoot, "authority", "models.json");
  const livePath = path.join(tempRoot, "live", "models.json");
  await mkdir(path.dirname(authorityPath), { recursive: true });
  await mkdir(path.dirname(livePath), { recursive: true });
  await writeFile(authorityPath, '{ "model": "deepseek-chat" }\n', "utf8");
  await writeFile(livePath, '{ "model": "glm-5" }\n', "utf8");

  const overlays = normalizeManagedOverlayConfigEntries([
    {
      id: "main-models",
      authorityPath,
      livePath,
      reconcileMode: "observe",
    },
  ]);

  const summary = await reconcileManagedOverlays({ overlays });

  assert.equal(summary.copiedCount, 0);
  assert.equal(summary.observedDriftCount, 1);
  assert.equal(summary.records[0].lastAction, "drift_observed");
  assert.equal(await readFile(livePath, "utf8"), '{ "model": "glm-5" }\n');
});

test("managed-overlays bootstrap reads OpenClaw config and persists managed-overlay-state", async (t) => {
  const tempRoot = await mkdtemp(path.join(os.tmpdir(), "claw-aegis-bootstrap-"));
  t.after(async () => {
    await rm(tempRoot, { recursive: true, force: true });
  });

  const authorityPath = path.join(tempRoot, "authority", "models.json");
  const livePath = path.join(tempRoot, "live", "models.json");
  const stateFile = path.join(tempRoot, "state", "managed-overlay-state.json");
  const openclawConfigPath = path.join(tempRoot, "openclaw.json");

  await mkdir(path.dirname(authorityPath), { recursive: true });
  await writeFile(authorityPath, '{ "model": "deepseek-chat" }\n', "utf8");
  await writeFile(
    openclawConfigPath,
    JSON.stringify(
      {
        plugins: {
          entries: {
            "claw-aegis": {
              config: {
                managedOverlays: [
                  {
                    id: "main-models",
                    authorityPath,
                    livePath,
                    reconcileMode: "enforce",
                  },
                ],
              },
            },
          },
        },
      },
      null,
      2,
    ),
    "utf8",
  );

  const bootstrapPath = path.resolve(
    "E:\\codexworkspace\\openclaw\\ClawAegis\\scripts\\managed-overlays-bootstrap.mjs",
  );
  const { stdout } = await execFile(process.execPath, [
    bootstrapPath,
    "--openclaw-config",
    openclawConfigPath,
    "--state-file",
    stateFile,
  ]);

  const output = JSON.parse(stdout);
  const persistedState = JSON.parse(await readFile(stateFile, "utf8"));

  assert.equal(output.ok, true);
  assert.equal(output.copiedCount, 1);
  assert.equal(await readFile(livePath, "utf8"), '{ "model": "deepseek-chat" }\n');
  assert.equal(persistedState.version, 1);
  assert.equal(persistedState.records[0].id, "main-models");
  assert.equal(persistedState.records[0].lastAction, "copied_to_live");
});
