import { Hono } from "hono";
import {
  oauthProviderAuthServerMetadata,
  oauthProviderOpenIdConfigMetadata,
} from "@better-auth/oauth-provider";
import type { Env } from "../env";
import { createAuth } from "./config";
import { auditAuthRequest } from "../audit/auth-middleware";

export const authRoutes = new Hono<{ Bindings: Env }>();

authRoutes.get("/.well-known/openid-configuration", (context) =>
  oauthProviderOpenIdConfigMetadata(createAuth(context.env))(context.req.raw),
);

authRoutes.get("/.well-known/oauth-authorization-server/api/auth", (context) =>
  oauthProviderAuthServerMetadata(createAuth(context.env))(context.req.raw),
);

authRoutes.all("/api/auth/*", (context) =>
  auditAuthRequest(context.req.raw, context.env),
);
