import { Hono } from "hono";
import type { Env } from "../env";
import { auditRoutes } from "../audit/routes";
import { scimAdminRoutes } from "../scim/routes";

export const adminRoutes = new Hono<{ Bindings: Env }>();

adminRoutes.route("/", auditRoutes);
adminRoutes.route("/", scimAdminRoutes);
