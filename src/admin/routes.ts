import { Hono } from "hono";
import type { Env } from "../env";
import { auditRoutes } from "../audit/routes";
import { samlAdminRoutes } from "../saml/routes";
import { scimAdminRoutes } from "../scim/routes";
import { directoryRoutes } from "./directory";
import { wsfedAdminRoutes } from "../wsfed/routes";
import { swaAdminRoutes } from "../swa/routes";
import { accessPolicyRoutes } from "../access/routes";
import { usageRoutes } from "./usage";
import { accountAdminRoutes } from "../accounts/admin";
import { objectAttributeRoutes } from "../objects/attribute-routes";

export const adminRoutes = new Hono<{ Bindings: Env }>();

adminRoutes.route("/", auditRoutes);
adminRoutes.route("/", samlAdminRoutes);
adminRoutes.route("/", scimAdminRoutes);
adminRoutes.route("/", directoryRoutes);
adminRoutes.route("/", wsfedAdminRoutes);
adminRoutes.route("/", swaAdminRoutes);
adminRoutes.route("/", accessPolicyRoutes);
adminRoutes.route("/", usageRoutes);
adminRoutes.route("/", accountAdminRoutes);
adminRoutes.route("/", objectAttributeRoutes);
