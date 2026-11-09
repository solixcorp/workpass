import { Hono } from "hono";
import type { Env } from "../env";
import { auditRoutes } from "../audit/routes";
import { samlAdminRoutes } from "../saml/routes";
import { scimAdminRoutes } from "../scim/routes";
import { directoryRoutes } from "./directory";
import { wsfedAdminRoutes } from "../wsfed/routes";
import { swaAdminRoutes } from "../swa/routes";
import { usageRoutes } from "./usage";

export const adminRoutes = new Hono<{ Bindings: Env }>();

adminRoutes.route("/", auditRoutes);
adminRoutes.route("/", samlAdminRoutes);
adminRoutes.route("/", scimAdminRoutes);
adminRoutes.route("/", directoryRoutes);
adminRoutes.route("/", wsfedAdminRoutes);
adminRoutes.route("/", swaAdminRoutes);
adminRoutes.route("/", usageRoutes);
