# ClawAegis Testing Plan

## Layers

1. Unit tests
   - Location: `tests/*.test.js`
   - Goal: validate pure helpers and single-hook behavior with minimal scaffolding.

2. Host-simulated E2E
   - Location: `tests/e2e/`
   - Goal: register the plugin against a lightweight in-process OpenClaw host harness, then replay real hook lifecycles end to end.
   - Coverage: plugin registration, fail-open wrappers, hook dispatch, temporary state directories, cross-hook state propagation, prompt guard injection, cleanup behavior.

3. Docker smoke E2E
   - Status: planned
   - Goal: load ClawAegis inside a real OpenClaw container and verify plugin loading plus a few high-value flows.
   - Scope: intentionally small, focused on runtime compatibility instead of exhaustive behavior checks.

## Current Commands

- `npm test`
  - Runs all tests.
- `npm run test:unit`
  - Runs the unit-level suite.
- `npm run test:e2e`
  - Runs the host-simulated E2E suite.
- `npm run test:e2e:docker`
  - Runs the Docker smoke E2E suite.
  - If Docker CLI is unavailable, the test skips cleanly.

## Design Notes

- Prefer reusing real JS entrypoints such as `index.js` and `src/handlers.js`.
- Keep E2E tests deterministic by using temporary state directories and in-process hook dispatch.
- Reserve Docker-based coverage for compatibility smoke tests, not detailed rule-by-rule assertions.

## Docker Smoke Env Vars

- `CLAW_AEGIS_DOCKER_IMAGE`
  - Override the OpenClaw image used for smoke tests.
  - Default: `ghcr.io/openclaw/openclaw:2026.3.23`
- `CLAW_AEGIS_DOCKER_PULL`
  - When not set to `0`, the smoke runner will try to pull the image if it is missing locally.
