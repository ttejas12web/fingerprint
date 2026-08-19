import { Buffer } from "node:buffer";
import {
  generateAuthenticationOptions,
  generateRegistrationOptions,
  verifyAuthenticationResponse,
  verifyRegistrationResponse,
  type AuthenticationResponseJSON,
  type AuthenticatorTransportFuture,
  type CredentialDeviceType,
  type RegistrationResponseJSON,
} from "@simplewebauthn/server";

const RP_NAME = "Photoelectric Identity Registry";
const CHALLENGE_LIFETIME_MS = 5 * 60 * 1000;
const MAX_JSON_BYTES = 1_000_000;

type UserRow = {
  id: string;
  name: string;
  employee_id: string;
  current_challenge: string | null;
  challenge_expires_at: number | null;
  created_at: string;
  updated_at: string;
};

type CredentialRow = {
  id: string;
  user_id: string;
  public_key: string;
  counter: number;
  device_type: CredentialDeviceType;
  backed_up: number;
  transports: string | null;
};

type IdentificationChallengeRow = {
  challenge: string;
  expires_at: number;
};

type RegistrationBody = {
  name?: unknown;
  employeeId?: unknown;
  response?: unknown;
};

type IdentificationBody = {
  requestId?: unknown;
  response?: unknown;
};

class ApiError extends Error {
  constructor(
    readonly status: number,
    message: string,
  ) {
    super(message);
  }
}

function json(data: unknown, status = 200): Response {
  return Response.json(data, {
    status,
    headers: {
      "Cache-Control": "no-store",
      "X-Content-Type-Options": "nosniff",
    },
  });
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : "Unexpected server error.";
}

function publicUser(user: Pick<UserRow, "id" | "name" | "employee_id">) {
  return {
    id: user.id,
    name: user.name,
    employeeId: user.employee_id,
  };
}

function parseTransports(value: string | null): AuthenticatorTransportFuture[] | undefined {
  if (!value) return undefined;
  try {
    const transports: unknown = JSON.parse(value);
    return Array.isArray(transports)
      ? transports.filter((item): item is AuthenticatorTransportFuture => typeof item === "string")
      : undefined;
  } catch {
    return undefined;
  }
}

function webAuthnContext(request: Request) {
  const requestUrl = new URL(request.url);
  const originHeader = request.headers.get("Origin");
  const originUrl = originHeader ? new URL(originHeader) : requestUrl;

  if (originUrl.protocol !== "https:" && originUrl.hostname !== "localhost") {
    throw new ApiError(400, "WebAuthn requires HTTPS.");
  }
  if (originUrl.hostname !== requestUrl.hostname) {
    throw new ApiError(403, "Cross-origin biometric requests are not allowed.");
  }

  return { origin: originUrl.origin, rpID: originUrl.hostname };
}

async function readJson<T>(request: Request): Promise<T> {
  const contentLength = Number(request.headers.get("Content-Length") ?? "0");
  if (Number.isFinite(contentLength) && contentLength > MAX_JSON_BYTES) {
    throw new ApiError(413, "Request body is too large.");
  }
  if (!request.headers.get("Content-Type")?.includes("application/json")) {
    throw new ApiError(415, "Expected an application/json request body.");
  }
  try {
    return (await request.json()) as T;
  } catch {
    throw new ApiError(400, "Request body is not valid JSON.");
  }
}

function normalizeEnrollment(body: RegistrationBody) {
  const name = typeof body.name === "string" ? body.name.trim() : "";
  const employeeId = typeof body.employeeId === "string" ? body.employeeId.trim().toUpperCase() : "";

  if (!name || !employeeId) {
    throw new ApiError(400, "Name and user ID are required.");
  }
  if (name.length > 100 || employeeId.length > 64) {
    throw new ApiError(400, "Name or user ID is too long.");
  }
  if (!/^[A-Z0-9][A-Z0-9_-]*$/.test(employeeId)) {
    throw new ApiError(400, "User ID can contain letters, numbers, underscores, and hyphens.");
  }

  return { name, employeeId };
}

async function listUsers(env: Env): Promise<Response> {
  const result = await env.DB.prepare(
    `SELECT u.id, u.name, u.employee_id, COUNT(c.id) AS credential_count
       FROM users u
       LEFT JOIN credentials c ON c.user_id = u.id
      GROUP BY u.id, u.name, u.employee_id
      ORDER BY u.created_at ASC`,
  ).all<{ id: string; name: string; employee_id: string; credential_count: number }>();

  const users = result.results.map((user) => ({
    ...publicUser(user),
    credentialCount: Number(user.credential_count),
  }));
  return json({ users, count: users.length });
}

async function generateRegistration(request: Request, env: Env): Promise<Response> {
  const body = await readJson<RegistrationBody>(request);
  const { name, employeeId } = normalizeEnrollment(body);
  const now = new Date().toISOString();

  let user = await env.DB.prepare("SELECT * FROM users WHERE employee_id = ?")
    .bind(employeeId)
    .first<UserRow>();

  if (!user) {
    const id = crypto.randomUUID();
    await env.DB.prepare(
      `INSERT OR IGNORE INTO users
        (id, name, employee_id, created_at, updated_at)
       VALUES (?, ?, ?, ?, ?)`,
    )
      .bind(id, name, employeeId, now, now)
      .run();
    user = await env.DB.prepare("SELECT * FROM users WHERE employee_id = ?")
      .bind(employeeId)
      .first<UserRow>();
  } else if (user.name !== name) {
    await env.DB.prepare("UPDATE users SET name = ?, updated_at = ? WHERE id = ?")
      .bind(name, now, user.id)
      .run();
    user = { ...user, name, updated_at: now };
  }

  if (!user) throw new ApiError(500, "Unable to create the user record.");

  const credentialResult = await env.DB.prepare(
    "SELECT id, transports FROM credentials WHERE user_id = ?",
  )
    .bind(user.id)
    .all<{ id: string; transports: string | null }>();
  const { rpID } = webAuthnContext(request);

  const options = await generateRegistrationOptions({
    rpName: RP_NAME,
    rpID,
    userID: new TextEncoder().encode(user.id),
    userName: user.employee_id,
    userDisplayName: user.name,
    attestationType: "none",
    excludeCredentials: credentialResult.results.map((credential) => ({
      id: credential.id,
      transports: parseTransports(credential.transports),
    })),
    authenticatorSelection: {
      residentKey: "preferred",
      userVerification: "preferred",
    },
    supportedAlgorithmIDs: [-7, -257],
  });

  await env.DB.prepare(
    `UPDATE users
        SET current_challenge = ?, challenge_expires_at = ?, updated_at = ?
      WHERE id = ?`,
  )
    .bind(options.challenge, Date.now() + CHALLENGE_LIFETIME_MS, now, user.id)
    .run();

  return json(options);
}

async function verifyRegistration(request: Request, env: Env): Promise<Response> {
  const body = await readJson<RegistrationBody>(request);
  const employeeId = typeof body.employeeId === "string" ? body.employeeId.trim().toUpperCase() : "";
  const response = body.response as RegistrationResponseJSON | undefined;

  if (!employeeId || !response?.id) {
    throw new ApiError(400, "Registration session not found.");
  }

  const user = await env.DB.prepare("SELECT * FROM users WHERE employee_id = ?")
    .bind(employeeId)
    .first<UserRow>();
  if (!user?.current_challenge || !user.challenge_expires_at || user.challenge_expires_at <= Date.now()) {
    throw new ApiError(400, "Registration challenge expired.");
  }

  const consumed = await env.DB.prepare(
    `UPDATE users
        SET current_challenge = NULL, challenge_expires_at = NULL, updated_at = ?
      WHERE id = ? AND current_challenge = ?`,
  )
    .bind(new Date().toISOString(), user.id, user.current_challenge)
    .run();
  if (consumed.meta.changes !== 1) {
    throw new ApiError(409, "Registration challenge was already used.");
  }

  const { origin, rpID } = webAuthnContext(request);
  const verification = await verifyRegistrationResponse({
    response,
    expectedChallenge: user.current_challenge,
    expectedOrigin: origin,
    expectedRPID: rpID,
    requireUserVerification: true,
  });

  if (!verification.verified || !verification.registrationInfo) {
    throw new ApiError(400, "Registration verification failed.");
  }

  const { credential, credentialDeviceType, credentialBackedUp } = verification.registrationInfo;
  try {
    await env.DB.prepare(
      `INSERT INTO credentials
        (id, user_id, public_key, counter, device_type, backed_up, transports, created_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
    )
      .bind(
        credential.id,
        user.id,
        Buffer.from(credential.publicKey).toString("base64url"),
        credential.counter,
        credentialDeviceType,
        credentialBackedUp ? 1 : 0,
        credential.transports ? JSON.stringify(credential.transports) : null,
        new Date().toISOString(),
      )
      .run();
  } catch (error) {
    if (errorMessage(error).includes("UNIQUE constraint failed")) {
      throw new ApiError(409, "This device credential is already enrolled.");
    }
    throw error;
  }

  return json({ verified: true, user: publicUser(user) });
}

async function generateIdentification(request: Request, env: Env): Promise<Response> {
  await readJson<Record<string, never>>(request);
  const now = Date.now();
  await env.DB.prepare("DELETE FROM identification_challenges WHERE expires_at <= ?").bind(now).run();

  const credentials = await env.DB.prepare("SELECT id, transports FROM credentials ORDER BY created_at ASC")
    .all<{ id: string; transports: string | null }>();
  if (credentials.results.length === 0) {
    throw new ApiError(400, "No enrolled credentials were found. Enroll a named user first.");
  }

  const { rpID } = webAuthnContext(request);
  const options = await generateAuthenticationOptions({
    rpID,
    allowCredentials: credentials.results.map((credential) => ({
      id: credential.id,
      transports: parseTransports(credential.transports),
    })),
    userVerification: "required",
  });

  const requestId = crypto.randomUUID();
  await env.DB.prepare(
    "INSERT INTO identification_challenges (id, challenge, expires_at) VALUES (?, ?, ?)",
  )
    .bind(requestId, options.challenge, now + CHALLENGE_LIFETIME_MS)
    .run();

  return json({ ...options, requestId });
}

async function verifyIdentification(request: Request, env: Env): Promise<Response> {
  const body = await readJson<IdentificationBody>(request);
  const requestId = typeof body.requestId === "string" ? body.requestId : "";
  const response = body.response as AuthenticationResponseJSON | undefined;
  if (!requestId || !response?.id) {
    throw new ApiError(400, "Identification challenge expired. Try again.");
  }

  const [pendingResult] = await env.DB.batch([
    env.DB.prepare("SELECT challenge, expires_at FROM identification_challenges WHERE id = ?").bind(requestId),
    env.DB.prepare("DELETE FROM identification_challenges WHERE id = ?").bind(requestId),
  ]);
  const pending = pendingResult.results[0] as IdentificationChallengeRow | undefined;
  if (!pending || pending.expires_at <= Date.now()) {
    throw new ApiError(400, "Identification challenge expired. Try again.");
  }

  const credential = await env.DB.prepare(
    `SELECT c.id, c.user_id, c.public_key, c.counter, c.device_type, c.backed_up, c.transports,
            u.name, u.employee_id
       FROM credentials c
       JOIN users u ON u.id = c.user_id
      WHERE c.id = ?`,
  )
    .bind(response.id)
    .first<CredentialRow & { name: string; employee_id: string }>();
  if (!credential) {
    throw new ApiError(404, "This device credential is not enrolled in the user database.");
  }

  const { origin, rpID } = webAuthnContext(request);
  const verification = await verifyAuthenticationResponse({
    response,
    expectedChallenge: pending.challenge,
    expectedOrigin: origin,
    expectedRPID: rpID,
    credential: {
      id: credential.id,
      publicKey: new Uint8Array(Buffer.from(credential.public_key, "base64url")),
      counter: credential.counter,
      transports: parseTransports(credential.transports),
    },
    requireUserVerification: true,
  });

  if (!verification.verified) {
    throw new ApiError(401, "Identity verification failed.");
  }

  const updated = await env.DB.prepare("UPDATE credentials SET counter = ? WHERE id = ? AND counter = ?")
    .bind(verification.authenticationInfo.newCounter, credential.id, credential.counter)
    .run();
  if (updated.meta.changes !== 1) {
    throw new ApiError(409, "Credential counter changed during verification. Try again.");
  }

  return json({
    verified: true,
    user: publicUser({
      id: credential.user_id,
      name: credential.name,
      employee_id: credential.employee_id,
    }),
  });
}

export async function handleApiRequest(request: Request, env: Env, route: string): Promise<Response> {
  try {
    if (request.method === "GET" && route === "users") return await listUsers(env);
    if (request.method === "POST" && route === "generate-registration-options") {
      return await generateRegistration(request, env);
    }
    if (request.method === "POST" && route === "verify-registration") {
      return await verifyRegistration(request, env);
    }
    if (request.method === "POST" && route === "generate-identification-options") {
      return await generateIdentification(request, env);
    }
    if (request.method === "POST" && route === "verify-identification") {
      return await verifyIdentification(request, env);
    }
    return json({ error: "API route not found." }, 404);
  } catch (error) {
    const status = error instanceof ApiError ? error.status : 500;
    const logEntry = JSON.stringify({
        level: "error",
        method: request.method,
        path: new URL(request.url).pathname,
        status,
        message: errorMessage(error),
      });
    if (status >= 500) console.error(logEntry);
    else console.warn(logEntry);
    return json({ error: status === 500 ? "Internal server error." : errorMessage(error) }, status);
  }
}
