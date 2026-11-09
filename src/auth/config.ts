import { betterAuth } from "better-auth";
import { jwt, phoneNumber, twoFactor, username } from "better-auth/plugins";
import { admin } from "better-auth/plugins/admin";
import { adminAc, userAc } from "better-auth/plugins/admin/access";
import { passkey } from "@better-auth/passkey";
import { oauthProvider } from "@better-auth/oauth-provider";
import type { Env } from "../env";
import { verifyPassword, hashPassword } from "./password";
import { constantTimeTokenMatches } from "../security/tokens";
import { validateFingerprintConfig } from "../security/fingerprint";
import { revokeTrustedDevices } from "../security/trusted-device-store";

export type AuthInstance = ReturnType<typeof createAuth>;

export function createAuth(env: Env) {
  validateAuthEnvironment(env);
  const authBaseUrl = new URL(env.AUTH_BASE_URL);
  const baseURL = authBaseUrl.origin;

  return betterAuth({
    appName: "Internal Auth",
    baseURL,
    basePath: "/api/auth",
    secret: env.AUTH_SECRET,
    database: env.DB,
    disabledPaths: ["/token"],
    trustedOrigins: [baseURL],
    advanced: {
      useSecureCookies: authBaseUrl.protocol === "https:",
      defaultCookieAttributes: {
        sameSite: "lax",
        httpOnly: true,
        secure: authBaseUrl.protocol === "https:",
      },
    },
    rateLimit: {
      storage: "database",
      window: 60,
      max: 100,
      customRules: {
        "/sign-in/email": { window: 60, max: 5 },
        "/sign-in/username": { window: 60, max: 5 },
        "/passkey/verify-authentication": { window: 60, max: 10 },
        "/passkey/verify-registration": { window: 60, max: 5 },
        "/oauth2/token": { window: 60, max: 30 },
        "/oauth2/authorize": { window: 60, max: 30 },
        "/verify-password": { window: 60, max: 5 },
        "/oauth2/register": { window: 60, max: 3 },
        "/admin/create-user": { window: 60, max: 10 },
      },
    },
    emailAndPassword: {
      enabled: true,
      disableSignUp: true,
      password: { hash: hashPassword, verify: verifyPassword },
      revokeSessionsOnPasswordReset: true,
      onPasswordReset: async ({ user }) => {
        await revokeTrustedDevices(env, user.id);
      },
    },
    plugins: [
      username(),
      admin({
        adminRoles: ["admin"],
        roles: { admin: adminAc, user: userAc },
      }),
      jwt({
        jwt: { issuer: `${baseURL}/api/auth` },
        jwks: { keyPairConfig: { alg: "ES256" } },
      }),
      passkey({ rpID: authBaseUrl.hostname, rpName: "Internal Auth" }),
      phoneNumber({
        // sms OTP delivery: the dev/mock webhook records the code; production
        // gateways are wired through env credentials per deployment decision.
        sendOTP: async ({ phoneNumber, code }, ctx) => {
          const { sendSmsCode } = await import("../mfa/otp-senders");
          await sendSmsCode(env, { to: phoneNumber, code });
        },
        phoneNumberValidator: (phoneNumber) => /^\+[1-9][0-9]{5,14}$/.test(phoneNumber.trim()),
      }),
      twoFactor({
        issuer: authBaseUrl.hostname,
        otpOptions: {
          async sendOTP({ user, otp }, ctx) {
            // Delivery routing: a verified phone number receives the passcode by
            // SMS (Duo-free alternative is not used for SMS; this is our own
            // gateway), otherwise the code goes to the account email.
            const { sendOtpWithFallback } = await import("../mfa/otp-senders");
            await sendOtpWithFallback(env, { userId: user.id, email: user.email, otp });
          },
        },
      }),
      oauthProvider({
        loginPage: "/sign-in",
        consentPage: "/consent",
        scopes: ["openid", "profile", "email", "offline_access"],
        rateLimit: { register: { window: 60, max: 3 } },
        allowDynamicClientRegistration:
          env.ENABLE_DYNAMIC_CLIENT_REGISTRATION === "true",
        clientRegistrationDefaultScopes: ["openid", "profile", "email"],
        clientRegistrationAllowedScopes: ["offline_access"],
        clientRegistrationRequirePKCE: true,
        validateInitialAccessToken: async ({ initialAccessToken }) => {
          const expectedToken = env.CLIENT_REGISTRATION_TOKEN;
          if (
            env.ENABLE_DYNAMIC_CLIENT_REGISTRATION !== "true" ||
            !expectedToken ||
            !constantTimeTokenMatches(initialAccessToken, expectedToken)
          ) {
            return false;
          }
          return { referenceId: "operator-provisioned" };
        },
      }),
    ],
  });
}

function validateAuthEnvironment(env: Env): void {
  validateFingerprintConfig(env);
  if (!env.AUTH_SECRET || !env.AUTH_BASE_URL) {
    throw new Error("AUTH_SECRET and AUTH_BASE_URL must be configured");
  }
  if (new TextEncoder().encode(env.AUTH_SECRET).byteLength < 32) {
    throw new Error("AUTH_SECRET must contain at least 32 bytes");
  }

  for (const [enabled, token, name] of [
    [env.ENABLE_DYNAMIC_CLIENT_REGISTRATION, env.CLIENT_REGISTRATION_TOKEN, "CLIENT_REGISTRATION_TOKEN"],
    [env.ENABLE_ADMIN_BOOTSTRAP, env.ADMIN_BOOTSTRAP_TOKEN, "ADMIN_BOOTSTRAP_TOKEN"],
    [env.ENABLE_MIGRATIONS, env.MIGRATION_TOKEN, "MIGRATION_TOKEN"],
  ] as const) {
    if (enabled === "true" && (!token || new TextEncoder().encode(token).byteLength < 32)) {
      throw new Error(`${name} must be at least 32 bytes when its feature is enabled`);
    }
  }

  const authBaseUrl = new URL(env.AUTH_BASE_URL);
  const isLocalHttp = authBaseUrl.protocol === "http:" &&
    (authBaseUrl.hostname === "localhost" || authBaseUrl.hostname === "127.0.0.1");
  if (
    (authBaseUrl.protocol !== "https:" && !isLocalHttp) ||
    authBaseUrl.username !== "" ||
    authBaseUrl.password !== ""
  ) {
    throw new Error("AUTH_BASE_URL must use HTTPS outside local development and contain no credentials");
  }
  if (authBaseUrl.pathname !== "/" || authBaseUrl.search || authBaseUrl.hash) {
    throw new Error("AUTH_BASE_URL must be an origin without path, query, or fragment");
  }
}
