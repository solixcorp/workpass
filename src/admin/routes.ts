import { Hono } from "hono";
import type { Env } from "../env";
import { auditRoutes } from "../audit/routes";

export const adminRoutes = new Hono<{ Bindings: Env }>();

adminRoutes.route("/", auditRoutes);
