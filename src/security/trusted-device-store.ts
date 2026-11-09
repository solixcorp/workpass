import type { Env } from "../env";

export async function revokeTrustedDevices(
  env: Env,
  userId: string,
): Promise<number> {
  const result = await env.DB.prepare(
    `UPDATE trusted_devices SET revoked_at = ?
     WHERE user_id = ? AND revoked_at IS NULL`,
  )
    .bind(new Date().toISOString(), userId)
    .run();
  return result.meta.changes;
}

export async function revokeTrustedDevice(
  env: Env,
  userId: string,
  deviceId: string,
): Promise<boolean> {
  const result = await env.DB.prepare(
    `UPDATE trusted_devices SET revoked_at = ?
     WHERE id = ? AND user_id = ? AND revoked_at IS NULL`,
  )
    .bind(new Date().toISOString(), deviceId, userId)
    .run();
  return result.meta.changes === 1;
}
