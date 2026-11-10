/**
 * Step-up challenge status for the acting session: lets the sign-in surface
 * and applications learn that a risky decision requires a second factor,
 * including which factors the account can complete and until when the
 * challenge window stays open.
 */

import { Hono } from "hono";
import type { Env } from "../env";
import { createAuth } from "../auth/config";
import { getSessionMfaProof } from "../mfa/second-factor";
import { workpassMfaRequired } from "../mfa/policy";
import {
  openStepUpChallenge,
  getStepUpChallenge,
  usableSecondFactors,
  type StepUpChallenge,
} from "./step-up";
import { sessionTokenFromRequest } from "./session-geo-binding";
import { stepUpUi } from "./step-up-ui";

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
  let challenge: StepUpChallenge = await getStepUpChallenge(context.env, token ?? "");
  // A required second factor opens its own challenge the first time the
  // session is looked at, whichever sign-in path created it (OPAQUE, passkey).
  if ((challenge.state === "none" || challenge.state === "expired") && token) {
    const user = session.user as { id: string; role?: unknown };
    const proven = await getSessionMfaProof(context.env, token).catch(() => null);
    if (!proven && (await workpassMfaRequired(context.env, user))) {
      const available = await usableSecondFactors(context.env, user.id);
      if (available.length > 0 && await openStepUpChallenge({
        env: context.env, sessionToken: token, userId: user.id, reasons: ["mfa_required"], requestPath: REQUEST_PATH,
      }).catch(() => false)) {
        challenge = await getStepUpChallenge(context.env, token);
      }
    }
  }
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
  const methods = await usableSecondFactors(context.env, session.user.id);
  return context.json({
    required: true,
    state: challenge.state,
    reasons: challenge.reasons,
    expiresAt: challenge.expiresAt,
    methods,
    ui: stepUpUi(methods, challenge.reasons),
  });
});
