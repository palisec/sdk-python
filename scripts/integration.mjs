#!/usr/bin/env node
/**
 * Runs the served Python wheel against a live Palisec server with a database:
 *   BASE_URL=http://localhost:3000 node packages/sdk-python/scripts/integration.mjs
 * Node signs in with throwaway wallets and sets up the policy, agent and key, then starts
 * integration.py. When Python prints "HELD <id>", Node approves it with an EIP-712 signature,
 * exactly as an approver does in the console. Nothing is broadcast.
 */
import { spawn, spawnSync } from "node:child_process";
import { createInterface } from "node:readline";
import { fileURLToPath } from "node:url";
import { generatePrivateKey, privateKeyToAccount } from "viem/accounts";

const BASE = process.env.BASE_URL ?? "http://localhost:3000";

async function call(method, path, { cookie, body } = {}) {
  const headers = { origin: BASE };
  if (body !== undefined) headers["content-type"] = "application/json";
  if (cookie) headers.cookie = cookie;
  const res = await fetch(`${BASE}/api/v1${path}`, { method, headers, body: body === undefined ? undefined : JSON.stringify(body) });
  return { status: res.status, body: await res.json().catch(() => ({})), headers: res.headers };
}

const owner = privateKeyToAccount(generatePrivateKey());
const agent = privateKeyToAccount(generatePrivateKey());
const token = privateKeyToAccount(generatePrivateKey()).address;
const c = await call("POST", "/auth/challenges", { body: { address: owner.address, chain_id: 46630 } });
const v = await call("POST", "/auth/verify", { body: { nonce: c.body.nonce, signature: await owner.signMessage({ message: c.body.message }) } });
const cookie = (v.headers.get("set-cookie") ?? "").split(";")[0];

const p = await call("POST", "/policies", { cookie, body: { name: "Python SDK test", policy_key: "py_sdk_test", chain_id: 46630, account: agent.address } });
const draft = {
  ...p.body.draft,
  limits: { ...p.body.draft.limits, max_price_age_seconds: 120, max_pending_operations: 10 },
  cooldowns: { identical_calldata_seconds: 0, identical_intent_seconds: 0 },
  contracts: { default: "deny", allowlist: [{ address: token, selectors: ["0xa9059cbb"], require_verified_code: false }], denylist: [] },
  human_approval: { usd_threshold_micros: "1000000000", require_for_unknown_methods: true },
};
const saved = await call("PUT", `/policies/${p.body.id}`, { cookie, body: { document: draft } });
await call("POST", `/policies/${p.body.id}/activate`, { cookie, body: { confirm: true, draft_hash: saved.body.draft_hash } });
const a = await call("POST", "/agents", { cookie, body: { name: "Python agent", chain_id: 46630, account: agent.address, policy_id: p.body.id } });
const key = (await call("POST", `/agents/${a.body.id}/credentials`, { cookie, body: { label: "python" } })).body.secret;
if (!/^ps_test_[0-9a-f]{48}$/.test(key ?? "")) {
  console.error("setup failed: no agent key", key);
  process.exit(1);
}

async function approve(operationId) {
  const list = await call("GET", "/approvals", { cookie });
  const t = list.body.approvals.find((x) => x.operation_id === operationId).typed_data;
  const message = { ...t.message };
  for (const k of ["chainId", "valueWei", "policyVersion", "expiresAt"]) message[k] = BigInt(message[k]);
  const signature = await owner.signTypedData({ domain: t.domain, types: { OperationApproval: t.types.OperationApproval }, primaryType: t.primaryType, message });
  const r = await call("POST", `/approvals/${operationId}/approve`, { cookie, body: { signature } });
  console.log(`${r.status === 200 ? "PASS" : "FAIL"}  console: approver signs the exact operation`);
  return r.status === 200;
}

const python = ["python3", "python"].find((exe) => spawnSync(exe, ["--version"]).status === 0);
const script = fileURLToPath(new URL("./integration.py", import.meta.url));
const child = spawn(python, [script], {
  env: { ...process.env, BASE_URL: BASE, PALISEC_KEY: key, TOKEN: token, OWNER: owner.address, AGENT_ACCOUNT: agent.address },
  stdio: ["ignore", "pipe", "inherit"],
});
let approvedOk = true;
for await (const line of createInterface({ input: child.stdout })) {
  if (line.startsWith("HELD ")) approvedOk = await approve(line.slice(5).trim());
  else console.log(line);
}
const code = await new Promise((resolve) => child.on("close", resolve));
process.exit(code === 0 && approvedOk ? 0 : 1);
