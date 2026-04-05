import assert from "node:assert/strict";
import test from "node:test";

import { dockerCliAvailable, runClawAegisDockerSmoke } from "./docker-smoke-runner.js";

test("docker smoke loads ClawAegis inside a real OpenClaw container", async (t) => {
  if (!(await dockerCliAvailable())) {
    t.skip("Docker CLI is unavailable in the current environment.");
    return;
  }

  const outcome = await runClawAegisDockerSmoke();

  assert.equal(outcome.config.plugins.entries["claw-aegis"].enabled, true);
  assert.ok(outcome.listOutput.includes("Claw Aegis"));
  assert.ok(outcome.listOutput.includes("loaded"));
});
