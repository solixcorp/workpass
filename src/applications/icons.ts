/**
 * Application icon uploads into Cloudflare R2. Administrators upload a small
 * image (multipart form `file` field); the bucket stores it under
 * `applications/{slug}/icon`, an overwrite-on-reupload design so the public
 * path stays stable:
 *
 *   GET /application/{slug}/icon  (public; icons are not sensitive)
 *
 * The upload must reference a registered application; a missing
 * `APPLICATION_ICONS` binding fails the whole surface closed (503), like
 * every other not-configured feature. SVG is allowed but served with a
 * restrictive CSP so no script execution context is possible.
 */

import type { Env } from "../env";
import { getApplication, type ApplicationRow } from "./store";

export const ICON_MAX_BYTES = 1024 * 1024; // 1 MiB
const SVG_CONTENT_TYPE = "image/svg+xml";

const ALLOWED_CONTENT_TYPES = new Set([
  "image/png",
  "image/jpeg",
  "image/image-placeholder", // never valid; documents the allowlist shape
  "image/webp",
  "image/gif",
  SVG_CONTENT_TYPE,
]);
ALLOWED_CONTENT_TYPES.delete("image/image-placeholder");

export function iconObjectKey(slug: string): string {
  return `applications/${slug}/icon`;
}

function contentTypeFromMagicBytes(bytes: Uint8Array): string | null {
  const startsWith = (signature: number[]) =>
    bytes.length >= signature.length && signature.every((byte, index) => bytes[index] === byte);
  if (startsWith([0x89, 0x50, 0x4e, 0x47])) return "image/png";
  if (startsWith([0xff, 0xd8, 0xff])) return "image/jpeg";
  if (startsWith([0x47, 0x49, 0x46, 0x38])) return "image/gif";
  if (bytes.length >= 12 && startsWith([0x52, 0x49, 0x46, 0x46]) &&
      [0x57, 0x45, 0x42, 0x50].every((byte, index) => bytes[index + 8] === byte)) {
    return "image/webp";
  }
  return null;
}

/**
 * Sniff the uploaded bytes: the content type comes from magic bytes, or for
 * an SVG-looking text from a minimal structural check. Returns null when
 * nothing matches the allowlist — the caller rejects, never trusting the
 * client-provided content type.
 */
export function sniffImageType(bytes: Uint8Array): { contentType: string; ext: string } | null {
  const byMagic = contentTypeFromMagicBytes(bytes);
  if (byMagic) {
    return { contentType: byMagic, ext: byMagic.split("/")[1]!.replace("jpeg", "jpg") };
  }
  // SVG: short files made of ASCII that start with an XML/svg prolog.
  if (bytes.length <= ICON_MAX_BYTES) {
    const head = new TextDecoder("utf-8", { fatal: false }).decode(bytes.slice(0, 256)).trim();
    if (head.startsWith("<") && /<svg[\s>]/i.test(head)) {
      return { contentType: SVG_CONTENT_TYPE, ext: "svg" };
    }
  }
  return null;
}

export function iconsBucket(env: Env): R2Bucket | null {
  return env.APPLICATION_ICONS ?? null;
}

export async function readIconBytes(file: Blob): Promise<Uint8Array | null> {
  if (file.size > ICON_MAX_BYTES) return null;
  return new Uint8Array(await file.arrayBuffer());
}

export async function putApplicationIcon(
  env: Env,
  application: ApplicationRow,
  bytes: Uint8Array,
): Promise<{ contentType: string } | null> {
  const bucket = iconsBucket(env);
  if (!bucket) return null;
  const sniffed = sniffImageType(bytes);
  if (!sniffed || bytes.length > ICON_MAX_BYTES) return null;
  await bucket.put(iconObjectKey(application.slug), bytes, {
    httpMetadata: { contentType: sniffed.contentType },
  });
  await env.DB.prepare(
    "UPDATE applications SET icon_key = ?, updated_at = ? WHERE slug = ?",
  ).bind(iconObjectKey(application.slug), new Date().toISOString(), application.slug).run();
  return { contentType: sniffed.contentType };
}

export async function deleteApplicationIcon(env: Env, slug: string): Promise<boolean> {
  const bucket = iconsBucket(env);
  if (!bucket) return false;
  const application = await getApplication(env, slug);
  if (!application?.iconKey) return false;
  await bucket.delete(application.iconKey);
  await env.DB.prepare(
    "UPDATE applications SET icon_key = NULL, updated_at = ? WHERE slug = ?",
  ).bind(new Date().toISOString(), application.slug).run();
  return true;
}

/** The public icon bytes for one application, or null when absent. */
export async function getApplicationIcon(
  env: Env,
  slug: string,
): Promise<{ body: ReadableStream; contentType: string } | null> {
  const bucket = iconsBucket(env);
  const application = await getApplication(env, slug);
  if (!bucket || !application?.iconKey) return null;
  const object = await bucket.get(application.iconKey);
  if (!object) return null;
  return { body: object.body, contentType: object.httpMetadata?.contentType ?? "application/octet-stream" };
}

/** The icon a user surface shows: uploaded (stable public path) or external URL. */
export function iconDisplayPath(application: Pick<ApplicationRow, "slug" | "iconKey" | "iconUrl">): string | null {
  if (application.iconKey) return `/application/${application.slug}/icon`;
  return application.iconUrl ?? null;
}
