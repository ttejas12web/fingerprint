import express from "express";
import path from "path";
import { createServer as createViteServer } from "vite";
import {
  generateRegistrationOptions,
  verifyRegistrationResponse,
  generateAuthenticationOptions,
  verifyAuthenticationResponse,
} from "@simplewebauthn/server";
import crypto from "crypto";

type UserRecord = {
  id: string;
  name: string;
  employeeId: string;
  currentChallenge?: string;
  createdAt: string;
};

type StoredCredential = {
  id: string;
  userId: string;
  publicKey: Uint8Array;
  counter: number;
  credentialDeviceType: string;
  credentialBackedUp: boolean;
  transports?: string[];
};

type IdentificationChallenge = {
  challenge: string;
  expiresAt: number;
};

const usersByEmployeeId = new Map<string, UserRecord>();
const usersById = new Map<string, UserRecord>();
const credentialsById = new Map<string, StoredCredential>();
const identificationChallenges = new Map<string, IdentificationChallenge>();

const rpName = "Photoelectric Identity Registry";
const challengeLifetimeMs = 5 * 60 * 1000;

const publicUser = (user: UserRecord) => ({
  id: user.id,
  name: user.name,
  employeeId: user.employeeId,
});

const requestContext = (req: express.Request) => {
  const origin = req.get("origin") || req.protocol + "://" + req.get("host");
  return { origin, rpID: new URL(origin).hostname };
};

async function startServer() {
  const app = express();
  app.set("trust proxy", 1);
  const PORT = 3000;

  app.use(express.json({ limit: "1mb" }));

  app.get("/api/users", (_req, res) => {
    const users = Array.from(usersById.values()).map((user) => ({
      ...publicUser(user),
      credentialCount: Array.from(credentialsById.values()).filter(
        (credential) => credential.userId === user.id,
      ).length,
    }));
    res.json({ users, count: users.length });
  });

  app.post("/api/generate-registration-options", async (req, res) => {
    try {
      const name = String(req.body?.name || "").trim();
      const employeeId = String(req.body?.employeeId || "").trim().toUpperCase();
      if (!name || !employeeId) {
        return res.status(400).json({ error: "Name and user ID are required." });
      }

      let user = usersByEmployeeId.get(employeeId);
      if (!user) {
        user = {
          id: crypto.randomUUID(),
          name,
          employeeId,
          createdAt: new Date().toISOString(),
        };
        usersByEmployeeId.set(employeeId, user);
        usersById.set(user.id, user);
      } else {
        user.name = name;
      }

      const userCredentials = Array.from(credentialsById.values()).filter(
        (credential) => credential.userId === user.id,
      );
      const { rpID } = requestContext(req);

      const options = await generateRegistrationOptions({
        rpName,
        rpID,
        userID: new Uint8Array(Buffer.from(user.id)),
        userName: user.employeeId,
        userDisplayName: user.name,
        attestationType: "none",
        excludeCredentials: userCredentials.map((credential) => ({
          id: credential.id,
          transports: credential.transports as any,
        })),
        authenticatorSelection: {
          residentKey: "preferred",
          userVerification: "preferred",
        },
        supportedAlgorithmIDs: [-7, -257],
      });

      user.currentChallenge = options.challenge;
      res.json(options);
    } catch (error: any) {
      console.error(error);
      res.status(500).json({ error: error.message });
    }
  });

  app.post("/api/verify-registration", async (req, res) => {
    try {
      const employeeId = String(req.body?.employeeId || "").trim().toUpperCase();
      const response = req.body?.response;
      const user = usersByEmployeeId.get(employeeId);
      if (!user || !response) {
        return res.status(400).json({ error: "Registration session not found." });
      }
      if (!user.currentChallenge) {
        return res.status(400).json({ error: "Registration challenge expired." });
      }

      const { origin, rpID } = requestContext(req);
      const verification = await verifyRegistrationResponse({
        response,
        expectedChallenge: user.currentChallenge,
        expectedOrigin: origin,
        expectedRPID: rpID,
        requireUserVerification: true,
      });

      const { verified, registrationInfo } = verification;
      if (!verified || !registrationInfo) {
        return res.status(400).json({ error: "Registration verification failed." });
      }

      const { credential, credentialDeviceType, credentialBackedUp } = registrationInfo;
      credentialsById.set(credential.id, {
        id: credential.id,
        userId: user.id,
        publicKey: credential.publicKey,
        counter: credential.counter,
        credentialDeviceType,
        credentialBackedUp,
        transports: credential.transports,
      });
      user.currentChallenge = undefined;

      res.json({ verified: true, user: publicUser(user) });
    } catch (error: any) {
      console.error(error);
      res.status(400).json({ error: error.message });
    }
  });

  app.post("/api/generate-identification-options", async (req, res) => {
    try {
      const now = Date.now();
      for (const [id, pending] of identificationChallenges) {
        if (pending.expiresAt <= now) identificationChallenges.delete(id);
      }

      const { rpID } = requestContext(req);
      const options = await generateAuthenticationOptions({
        rpID,
        allowCredentials: Array.from(credentialsById.values()).map((credential) => ({
          id: credential.id,
          transports: credential.transports as any,
        })),
        userVerification: "required",
      });

      const requestId = crypto.randomUUID();
      identificationChallenges.set(requestId, {
        challenge: options.challenge,
        expiresAt: now + challengeLifetimeMs,
      });

      res.json({ ...options, requestId });
    } catch (error: any) {
      console.error(error);
      res.status(500).json({ error: error.message });
    }
  });

  app.post("/api/verify-identification", async (req, res) => {
    try {
      const requestId = String(req.body?.requestId || "");
      const response = req.body?.response;
      const pending = identificationChallenges.get(requestId);
      identificationChallenges.delete(requestId);

      if (!pending || pending.expiresAt <= Date.now() || !response) {
        return res.status(400).json({ error: "Identification challenge expired. Try again." });
      }

      const storedCredential = credentialsById.get(response.id);
      if (!storedCredential) {
        return res.status(404).json({ error: "This device credential is not enrolled in the user database." });
      }

      const user = usersById.get(storedCredential.userId);
      if (!user) {
        return res.status(404).json({ error: "User record not found." });
      }

      const { origin, rpID } = requestContext(req);
      const verification = await verifyAuthenticationResponse({
        response,
        expectedChallenge: pending.challenge,
        expectedOrigin: origin,
        expectedRPID: rpID,
        credential: {
          id: storedCredential.id,
          publicKey: storedCredential.publicKey,
          counter: storedCredential.counter,
          transports: storedCredential.transports as any,
        },
        requireUserVerification: true,
      });

      if (!verification.verified) {
        return res.status(401).json({ error: "Identity verification failed." });
      }

      storedCredential.counter = verification.authenticationInfo.newCounter;
      res.json({ verified: true, user: publicUser(user) });
    } catch (error: any) {
      console.error(error);
      res.status(400).json({ error: error.message });
    }
  });

  if (process.env.NODE_ENV !== "production") {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: "spa",
    });
    app.use(vite.middlewares as any);
  } else {
    const distPath = path.join(process.cwd(), "dist");
    app.use(express.static(distPath) as any);
    app.get("*", (_req, res) => {
      res.sendFile(path.join(distPath, "index.html"));
    });
  }

  app.listen(PORT, "0.0.0.0", () => {
    console.log("Server running on http://localhost:" + PORT);
  });
}

startServer();
