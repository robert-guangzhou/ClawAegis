import { createHash } from "node:crypto";
import { promises as fs } from "node:fs";
import path from "node:path";

import type {
  AegisLogger,
  ManagedOverlayConfigEntry,
  ManagedOverlayReconcileMode,
  ManagedOverlayStateRecord,
} from "./types.js";

export const MANAGED_OVERLAY_RECONCILE_MODES = ["off", "observe", "enforce"] as const;

type ManagedOverlayLogger = Pick<AegisLogger, "info" | "warn" | "error">;

export type ManagedOverlayReconcileSummary = {
  records: ManagedOverlayStateRecord[];
  copiedCount: number;
  inSyncCount: number;
  observedDriftCount: number;
  errorCount: number;
};

function normalizeOverlayId(value: string): string {
  const normalized = value.trim().normalize("NFKC").toLowerCase();
  return normalized.replace(/[^a-z0-9._-]+/g, "-").replace(/^-+|-+$/g, "");
}

function deriveManagedOverlayId(authorityPath: string, livePath: string): string {
  const authorityBase = path.basename(authorityPath, path.extname(authorityPath)) || "authority";
  const liveBase = path.basename(livePath, path.extname(livePath)) || "live";
  const suffix = createHash("sha256").update(`${authorityPath}\0${livePath}`).digest("hex").slice(0, 8);
  return normalizeOverlayId(`${liveBase}-${authorityBase}-${suffix}`);
}

function isManagedOverlayReconcileMode(value: unknown): value is ManagedOverlayReconcileMode {
  return (
    typeof value === "string" &&
    (MANAGED_OVERLAY_RECONCILE_MODES as readonly string[]).includes(value)
  );
}

export function normalizeManagedOverlayConfigEntries(
  value: unknown,
  resolvePath: (input: string) => string = (input) => input,
): ManagedOverlayConfigEntry[] {
  if (!Array.isArray(value)) {
    return [];
  }

  const byId = new Map<string, ManagedOverlayConfigEntry>();
  const seenLivePaths = new Set<string>();

  for (const entry of value) {
    if (!entry || typeof entry !== "object") {
      continue;
    }
    const raw = entry as Record<string, unknown>;
    if (typeof raw.authorityPath !== "string" || typeof raw.livePath !== "string") {
      continue;
    }

    const authorityPath = path.resolve(resolvePath(raw.authorityPath.trim()));
    const livePath = path.resolve(resolvePath(raw.livePath.trim()));
    if (!authorityPath || !livePath) {
      continue;
    }

    const reconcileMode = isManagedOverlayReconcileMode(raw.reconcileMode)
      ? raw.reconcileMode
      : isManagedOverlayReconcileMode(raw.mode)
        ? raw.mode
        : "enforce";
    if (reconcileMode === "off") {
      continue;
    }

    const explicitId = typeof raw.id === "string" ? normalizeOverlayId(raw.id) : "";
    const id = explicitId || deriveManagedOverlayId(authorityPath, livePath);
    if (!id || seenLivePaths.has(livePath) || byId.has(id)) {
      continue;
    }

    const normalizedEntry: ManagedOverlayConfigEntry = {
      id,
      authorityPath,
      livePath,
      reconcileMode,
    };
    byId.set(id, normalizedEntry);
    seenLivePaths.add(livePath);
  }

  return [...byId.values()].sort((left, right) => left.id.localeCompare(right.id));
}

export function collectManagedOverlayProtectedRoots(
  overlays: readonly ManagedOverlayConfigEntry[],
): string[] {
  const roots = new Set<string>();
  for (const overlay of overlays) {
    roots.add(path.resolve(overlay.authorityPath));
    roots.add(path.resolve(path.dirname(overlay.authorityPath)));
    roots.add(path.resolve(overlay.livePath));
    roots.add(path.resolve(path.dirname(overlay.livePath)));
  }
  return [...roots].sort((left, right) => left.localeCompare(right));
}

async function writeJsonAtomically(filePath: string, value: unknown): Promise<void> {
  await fs.mkdir(path.dirname(filePath), { recursive: true });
  const tempPath = `${filePath}.${process.pid}.${Date.now()}.tmp`;
  try {
    await fs.writeFile(tempPath, `${JSON.stringify(value, null, 2)}\n`, "utf8");
    await fs.rename(tempPath, filePath);
  } finally {
    await fs.rm(tempPath, { force: true }).catch(() => undefined);
  }
}

async function readFileFingerprint(filePath: string): Promise<{
  hash: string;
  size: number;
}> {
  const content = await fs.readFile(filePath);
  return {
    hash: createHash("sha256").update(content).digest("hex"),
    size: content.length,
  };
}

async function copyAuthorityToLive(authorityPath: string, livePath: string): Promise<void> {
  await fs.mkdir(path.dirname(livePath), { recursive: true });
  const tempPath = `${livePath}.${process.pid}.${Date.now()}.overlay.tmp`;
  const authorityStat = await fs.stat(authorityPath);
  try {
    await fs.copyFile(authorityPath, tempPath);
    await fs.chmod(tempPath, authorityStat.mode);
    await fs.rename(tempPath, livePath);
  } finally {
    await fs.rm(tempPath, { force: true }).catch(() => undefined);
  }
}

async function tryReadFingerprint(filePath: string): Promise<{
  hash: string;
  size: number;
} | null> {
  try {
    return await readFileFingerprint(filePath);
  } catch {
    return null;
  }
}

export async function persistManagedOverlayStateFile(
  filePath: string,
  records: readonly ManagedOverlayStateRecord[],
): Promise<void> {
  await writeJsonAtomically(filePath, {
    version: 1,
    records,
  });
}

export async function reconcileManagedOverlays(params: {
  overlays: readonly ManagedOverlayConfigEntry[];
  logger?: ManagedOverlayLogger;
  now?: () => number;
}): Promise<ManagedOverlayReconcileSummary> {
  const logger = params.logger;
  const now = params.now ?? Date.now;
  const summary: ManagedOverlayReconcileSummary = {
    records: [],
    copiedCount: 0,
    inSyncCount: 0,
    observedDriftCount: 0,
    errorCount: 0,
  };

  for (const overlay of params.overlays) {
    const record: ManagedOverlayStateRecord = {
      id: overlay.id,
      authorityPath: overlay.authorityPath,
      livePath: overlay.livePath,
      reconcileMode: overlay.reconcileMode,
      lastAction: "error",
      updatedAt: now(),
    };

    try {
      const authority = await readFileFingerprint(overlay.authorityPath);
      record.authorityHash = authority.hash;
      record.authoritySize = authority.size;

      let live = await tryReadFingerprint(overlay.livePath);
      if (!live) {
        if (overlay.reconcileMode === "enforce") {
          await copyAuthorityToLive(overlay.authorityPath, overlay.livePath);
          live = await readFileFingerprint(overlay.livePath);
          record.lastAction = "copied_to_live";
          record.lastNote = "Live overlay was missing and was restored from authority.";
          summary.copiedCount += 1;
          logger?.warn("claw-aegis: restored missing managed overlay", {
            event: "managed_overlay_restored",
            overlayId: overlay.id,
            reason: "missing_live",
          });
        } else {
          record.lastAction = "missing_live";
          record.lastNote = "Live overlay file is missing.";
          summary.observedDriftCount += 1;
          logger?.warn("claw-aegis: observed missing managed overlay live file", {
            event: "managed_overlay_missing_live",
            overlayId: overlay.id,
          });
        }
      } else if (live.hash !== authority.hash) {
        if (overlay.reconcileMode === "enforce") {
          await copyAuthorityToLive(overlay.authorityPath, overlay.livePath);
          live = await readFileFingerprint(overlay.livePath);
          record.lastAction = "copied_to_live";
          record.lastNote = "Live overlay drifted and was reconciled from authority.";
          summary.copiedCount += 1;
          logger?.warn("claw-aegis: reconciled managed overlay drift", {
            event: "managed_overlay_reconciled",
            overlayId: overlay.id,
          });
        } else {
          record.lastAction = "drift_observed";
          record.lastNote = "Live overlay hash drift observed.";
          summary.observedDriftCount += 1;
          logger?.warn("claw-aegis: observed managed overlay drift", {
            event: "managed_overlay_drift_observed",
            overlayId: overlay.id,
          });
        }
      } else {
        record.lastAction = "in_sync";
        record.lastNote = "Authority and live overlay hashes match.";
        summary.inSyncCount += 1;
        logger?.info("claw-aegis: managed overlay already in sync", {
          event: "managed_overlay_in_sync",
          overlayId: overlay.id,
        });
      }

      if (live) {
        record.liveHash = live.hash;
        record.liveSize = live.size;
      }
    } catch (error) {
      record.lastAction =
        error instanceof Error && error.message.includes("ENOENT") ? "authority_missing" : "error";
      record.lastNote = error instanceof Error ? error.message : String(error);
      summary.errorCount += 1;
      logger?.error("claw-aegis: managed overlay reconcile failed", {
        event: "managed_overlay_reconcile_failed",
        overlayId: overlay.id,
        reason: record.lastNote,
      });
    }

    record.updatedAt = now();
    summary.records.push(record);
  }

  return summary;
}
