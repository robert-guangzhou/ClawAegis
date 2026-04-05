import assert from "node:assert/strict";
import { cp, mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";

const CLAW_AEGIS_DIR = fileURLToPath(new URL("../..", import.meta.url));
const DEFAULT_DOCKER_IMAGE = process.env.CLAW_AEGIS_DOCKER_IMAGE ?? "ghcr.io/openclaw/openclaw:2026.3.23";
const SHOULD_PULL_IMAGE = process.env.CLAW_AEGIS_DOCKER_PULL !== "0";

function createMinimalOpenClawConfig() {
  return {
    plugins: {
      allow: ["claw-aegis"],
      load: {
        paths: ["/home/node/.openclaw/workspace/ClawAegis"],
      },
      entries: {
        "claw-aegis": {
          enabled: true,
          config: {
            startupSkillScan: false,
            skillScanEnabled: false,
            toolResultScanEnabled: false,
          },
        },
      },
    },
  };
}

function runProcess(command, args, options = {}) {
  return new Promise((resolve) => {
    const child = spawn(command, args, {
      cwd: options.cwd,
      env: options.env ?? process.env,
      stdio: ["ignore", "pipe", "pipe"],
      windowsHide: true,
    });
    let stdout = "";
    let stderr = "";
    child.stdout.on("data", (chunk) => {
      stdout += String(chunk);
    });
    child.stderr.on("data", (chunk) => {
      stderr += String(chunk);
    });
    child.on("close", (code) => {
      resolve({
        code: code ?? 1,
        stdout,
        stderr,
      });
    });
    child.on("error", (error) => {
      resolve({
        code: 1,
        stdout,
        stderr: `${stderr}${error instanceof Error ? error.message : String(error)}`,
      });
    });
  });
}

export async function dockerCliAvailable() {
  const result = await runProcess("docker", ["version"]);
  return result.code === 0;
}

async function ensureDockerImage(image) {
  const inspectResult = await runProcess("docker", ["image", "inspect", image]);
  if (inspectResult.code === 0) {
    return;
  }
  if (!SHOULD_PULL_IMAGE) {
    throw new Error(`Docker image not found locally: ${image}`);
  }
  const pullResult = await runProcess("docker", ["pull", image]);
  if (pullResult.code !== 0) {
    throw new Error(
      `Failed to pull Docker image ${image}\nSTDOUT:\n${pullResult.stdout}\nSTDERR:\n${pullResult.stderr}`,
    );
  }
}

async function prepareDockerSmokeFixture() {
  const tempRoot = await mkdtemp(path.join(os.tmpdir(), "claw-aegis-docker-smoke-"));
  const stateDir = path.join(tempRoot, "state");
  const pluginDir = path.join(tempRoot, "ClawAegis");
  const dirsToCreate = [
    stateDir,
    path.join(stateDir, "workspace"),
    path.join(stateDir, "skills"),
    path.join(stateDir, "extensions"),
    path.join(stateDir, "plugins"),
    path.join(stateDir, "cron"),
    path.join(stateDir, "agents", "main", "agent"),
    path.join(stateDir, "agents", "main", "sessions"),
  ];
  for (const dir of dirsToCreate) {
    await mkdir(dir, { recursive: true });
  }
  await cp(CLAW_AEGIS_DIR, pluginDir, { recursive: true });
  await writeFile(
    path.join(stateDir, "openclaw.json"),
    `${JSON.stringify(createMinimalOpenClawConfig(), null, 2)}\n`,
    "utf8",
  );
  return {
    tempRoot,
    stateDir,
    pluginDir,
    async dispose() {
      await rm(tempRoot, { recursive: true, force: true });
    },
  };
}

async function runDockerCommand(image, stateDir, pluginDir, commandArgs) {
  return await runProcess("docker", [
    "run",
    "--rm",
    "-v",
    `${stateDir}:/home/node/.openclaw`,
    "-v",
    `${pluginDir}:/home/node/.openclaw/workspace/ClawAegis:ro`,
    image,
    ...commandArgs,
  ]);
}

export async function runClawAegisDockerSmoke(options = {}) {
  const image = options.image ?? DEFAULT_DOCKER_IMAGE;
  await ensureDockerImage(image);
  const fixture = await prepareDockerSmokeFixture();

  try {
    const listResult = await runDockerCommand(image, fixture.stateDir, fixture.pluginDir, [
      "openclaw",
      "plugins",
      "list",
    ]);
    if (listResult.code !== 0) {
      throw new Error(
        `openclaw plugins list failed\nSTDOUT:\n${listResult.stdout}\nSTDERR:\n${listResult.stderr}`,
      );
    }

    assert.match(listResult.stdout, /Claw Aegis/);
    assert.match(listResult.stdout, /claw-\s*aegis|claw-aegis/);
    assert.match(listResult.stdout, /loaded/);

    const stateConfig = JSON.parse(
      await readFile(path.join(fixture.stateDir, "openclaw.json"), "utf8"),
    );
    return {
      image,
      listOutput: listResult.stdout,
      config: stateConfig,
    };
  } finally {
    await fixture.dispose();
  }
}
