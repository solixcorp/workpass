/** Literal-address rejection supplements, but does not replace, the operator
 * managed outbound destination approval list and network egress controls. */
export function isSafeBackchannelUri(value: string): boolean {
  if (!value || value.length > 2048 || /[\u0000-\u001f\u007f]/.test(value)) return false;
  try {
    const url = new URL(value);
    const host = url.hostname.toLowerCase().replace(/\.$/, "");
    return url.protocol === "https:" && !url.username && !url.password && !url.hash &&
      !host.includes(":") && !/^\d+(?:\.\d+)*$/.test(host) && host.includes(".") &&
      !/(?:^|\.)(?:localhost|local|internal)$/.test(host);
  } catch { return false; }
}
