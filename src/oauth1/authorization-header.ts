import type { OAuth1Parameter } from "./signature";

/** Parse an OAuth Authorization header without treating realm as a signed
 * parameter. Callers must still enforce required fields, signatures, timestamps
 * and atomic nonce consumption before accepting a request. */
export function parseOAuth1AuthorizationHeader(header: string): OAuth1Parameter[] {
  if (header.length > 8192 || !/^OAuth\s+/i.test(header)) throw new Error("Invalid OAuth authorization header");
  const input = header.replace(/^OAuth\s+/i, "");
  const result: OAuth1Parameter[] = [];
  const names = new Set<string>();
  let index = 0;
  while (index < input.length) {
    const match = /^\s*([A-Za-z0-9_~.%+-]+)\s*=\s*"([^"\\]*)"\s*/.exec(input.slice(index));
    if (!match) throw new Error("Invalid OAuth authorization parameter");
    let name: string;
    let value: string;
    try {
      name = decodeURIComponent(match[1]!);
      value = decodeURIComponent(match[2]!);
    } catch { throw new Error("Invalid OAuth percent encoding"); }
    if (names.has(name) || (name !== "realm" && !name.startsWith("oauth_"))) {
      throw new Error("Duplicate or invalid OAuth authorization parameter");
    }
    names.add(name);
    if (name !== "realm") result.push([name, value]);
    index += match[0].length;
    if (index === input.length) break;
    if (input[index] !== ",") throw new Error("Invalid OAuth authorization separator");
    index++;
    if (!input.slice(index).trim()) throw new Error("Invalid OAuth authorization separator");
  }
  if (!names.size) throw new Error("Empty OAuth authorization header");
  return result;
}
