/**
 * Step-up challenge status for the acting session: lets the sign-in surface
 * and applications learn that a risky decision requires a second factor,
 * including which factors the account can complete and until when the
 * challenge window stays open.
 */

import { Hono } from "hono";
import type { Env } from "../env";
import { createAuth } from "../auth/config";
import {
  getStepUpChallenge,
  usableSecondFactors,
  type StepUpChallenge,
} from "./step-up";
import { sessionTokenFromRequest } from "./session-geo-binding";

export const stepUpRoutes = new Hono<{ Bindings: Env }>();

const REQUEST_PATH = "/api/security/step-up/challenge";

stepUpRoutes.get("/step-up/challenge", async (context) => {
  const auth = createAuth(context.env);
  const session = await auth.api.getSession({ headers: context.req.raw.headers });
  if (!session) return context.json({ error: "Unauthorized" }, 401);
  const token = sessionTokenFromRequest(context.req.raw) ??
    (typeof (session.session as { token?: unknown } | undefined)?.token === "string"
      ? ((session.session as { token: string }).token)
      : null);
  const challenge: StepUpChallenge = await getStepUpChallenge(context.env, token ?? "");
  if (challenge.state === "none") {
    return context.json({ required: false, state: "none" });
  }
  if (challenge.state === "satisfied") {
    return context.json({
      required: false,
      state: "satisfied",
      satisfiedAt: challenge.satisfiedAt,
      satisfiedMethod: challenge.satisfiedMethod,
    });
  }
  return context.json({
    required: true,
    state: challenge.state,
    reasons: challenge.reasons,
    expiresAt: challenge.expiresAt,
    methods: await usableSecondFactors(context.env, session.user.id),
  });
});
