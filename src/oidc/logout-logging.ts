/** Better Auth 1.7.18 reports back-channel failures through its logger only.
 * Emit a stable structured event without logging the request, URI or token.
 * This is failure observability, not a delivery receipt or durable queue. */
export function backchannelFailureEvent(message: string): { event: string; client_id: string | null; reason: string } | null {
  const delivery = /^back-channel logout to client (.+?) (?:returned (\d+)|failed)$/.exec(message);
  const subject = /^back-channel logout: unable to resolve subject for client (.+)$/.exec(message);
  if (delivery) return {
    event: "oidc.backchannel_logout.failure",
    client_id: delivery[1]!.slice(0, 256),
    reason: delivery[2] ? `http_${delivery[2]}` : "delivery_failed",
  };
  if (subject) return { event: "oidc.backchannel_logout.failure", client_id: subject[1]!.slice(0, 256), reason: "subject_resolution_failed" };
  if (message === "back-channel logout planning failed" || message === "Back-channel logout failed after session deletion" || message === "back-channel logout: token revocation update failed") {
    return { event: "oidc.backchannel_logout.failure", client_id: null, reason: "internal_failure" };
  }
  return null;
}
