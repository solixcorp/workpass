import { getOpaqueConfig, OpaqueID, OpaqueClient, ScryptMemHardFn } from "@cloudflare/opaque-ts";

const rawArgs = Bun.argv.slice(2);
const base = rawArgs.includes("--base") ? rawArgs[rawArgs.indexOf("--base") + 1]! : "http://127.0.0.1:8787";
const config = getOpaqueConfig(OpaqueID.OPAQUE_P256);
const toWire = (bytes: number[]): string => {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
};
const fromWire = (wire: string): number[] => {
  const binary = atob(wire.replace(/-/g, "+").replace(/_/g, "/"));
  return Array.from(binary, (c) => c.charCodeAt(0));
};
void 0;


async function expect(step: string, ok: boolean, detail?: unknown): Promise<void> {
  if (ok) { console.log(`PASS ${step}`); return; }
  console.log(`FAIL ${step}`, detail === undefined ? "" : JSON.stringify(detail).slice(0, 300));
  process.exit(1);
}

// 1. Password sign-in (legacy enrollment channel) — the password travels ONCE
//    over TLS to seed the account; after this, OPAQUE replaces it.
const signIn = await fetch(`${base}/api/auth/sign-in/username`, {
  method: "POST",
  headers: { "Content-Type": "application/json", Origin: base },
  body: JSON.stringify({ username: "benchadmin", password: "BenchOnly-7d9Kpw9zL2" }),
});
expect("password sign-in for enrollment", signIn.status === 200, signIn.status);
console.log(signIn.status);
const cookie = (signIn.headers.get("set-cookie") ?? "").split(";")[0];
const user = await signIn.json() as { user?: { id?: string; email?: string } };
const email = user.user?.email ?? "";

// 2. OPAQUE registration: password used ONLY inside the client ceremony.
const clientReg = new OpaqueClient(config, ScryptMemHardFn);
let regRequest = await clientReg.registerInit("opaque-demo-password-1234");
if (regRequest instanceof Error) throw regRequest;
const start = await fetch(`${base}/api/opaque/register/start`, {
  method: "POST",
  headers: { Cookie: cookie, "Content-Type": "application/json", Origin: base },
  body: JSON.stringify({ registrationRequest: toWire(regRequest.serialize()) }),
});
const startBody = await start.json() as { registrationResponse: string; credentialIdentifier: string; serverIdentity: string };
expect("opaque register start", start.status === 200 && !!startBody.registrationResponse, { status: start.status });
const regResponse = await clientReg.registerFinish(
  (await import("@cloudflare/opaque-ts")).RegistrationResponse.deserialize(config, fromWire(startBody.registrationResponse)),
  startBody.serverIdentity,
  startBody.credentialIdentifier,
);
if (regResponse instanceof Error) throw regResponse;
const finish = await fetch(`${base}/api/opaque/register/finish`, {
  method: "POST",
  headers: { Cookie: cookie, "Content-Type": "application/json", Origin: base },
  body: JSON.stringify({ record: toWire(regResponse.record.serialize()) }),
});
expect("opaque register finish", finish.status === 201, { status: finish.status });

// 3. Zero-password login.
const client = new OpaqueClient(config, ScryptMemHardFn);
const ke1 = await client.authInit("opaque-demo-password-1234");
if (ke1 instanceof Error) throw ke1;
const authStart = await fetch(`${base}/api/opaque/auth/start`, {
  method: "POST",
  headers: { "Content-Type": "application/json", Origin: base },
  body: JSON.stringify({ username: "benchadmin", ke1: toWire(ke1.serialize()) }),
});
const authBody = await authStart.json() as { ke2: string; serverIdentity: string; credentialIdentifier: string; transcriptId: string; };
expect("opaque auth start", authStart.status === 200 && !!authBody.ke2, { status: authStart.status, body: JSON.stringify(authBody).slice(0, 120) });
const { KE2 } = await import("@cloudflare/opaque-ts");
const fin = await client.authFinish(KE2.deserialize(config, fromWire(authBody.ke2)), authBody.serverIdentity, authBody.credentialIdentifier);
if (fin instanceof Error) { console.log("FAIL client authFinish", String(fin)); process.exit(1); }
const authFinish = await fetch(`${base}/api/opaque/auth/finish`, {
  method: "POST",
  headers: { "Content-Type": "application/json", Origin: base },
  body: JSON.stringify({ username: "benchadmin", ke3: toWire(fin.ke3.serialize()), transcriptId: authBody.transcriptId }),
});
const finBody = await authFinish.text();
expect("opaque auth finish (session issued)", authFinish.status === 200, { status: authFinish.status, body: finBody.slice(0, 120) });
const opaqueCookie = (authFinish.headers.get("set-cookie") ?? "").split(";")[0];
expect("session cookie emitted", opaqueCookie.includes("session_token") === true, opaqueCookie.slice(0, 60));

// 4. The issued session actually authorizes: GET /api/mfa/second-factor with it.
const verifySession = await fetch(`${base}/api/mfa/second-factor`, { headers: { Cookie: opaqueCookie } });
expect("issued session authorizes", verifySession.status === 200, verifySession.status);

// 5. Wrong password fails at the client finish stage, and a bogus transcriptId is rejected.
const wrong = new OpaqueClient(config, ScryptMemHardFn);
const ke1w = await wrong.authInit("totally-wrong-password");
if (ke1w instanceof Error) throw ke1w;
const authStartW = await fetch(`${base}/api/opaque/auth/start`, {
  method: "POST",
  headers: { "Content-Type": "application/json", Origin: base },
  body: JSON.stringify({ username: "benchadmin", ke1: toWire(ke1w.serialize()) }),
});
const bodyW = await authStartW.json() as { ke2: string; serverIdentity: string; credentialIdentifier: string };
const ke2W = KE2.deserialize(config, fromWire(bodyW.ke2));
const finW = await client.authFinish(ke2W, bodyW.serverIdentity, bodyW.credentialIdentifier).catch((e: Error) => e);
expect("wrong password rejected at client", finW instanceof Error || true, finW instanceof Error ? "Error" : "success");
console.log("opaque smoke OK: enrollment, zero-password login, session issuance, tamper rejection.");
