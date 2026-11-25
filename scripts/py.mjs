#!/usr/bin/env node
// Runs Python 3.10+ with the given arguments: `python3` where it exists (Linux, macOS), else `python` (Windows).
import { spawnSync } from "node:child_process";

const args = process.argv.slice(2);
for (const exe of ["python3", "python"]) {
  const probe = spawnSync(exe, ["-c", "import sys; sys.exit(0 if sys.version_info >= (3, 10) else 1)"], { stdio: "ignore" });
  if (probe.status !== 0) continue;
  const run = spawnSync(exe, args, { stdio: "inherit" });
  process.exit(run.status ?? 1);
}
console.error("Python 3.10 or later is required (python3 or python on PATH).");
process.exit(1);
