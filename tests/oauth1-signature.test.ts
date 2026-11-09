import { expect, test } from "bun:test";
import { oauth1HmacSha1, oauth1SignatureBaseString, oauthPercentEncode } from "../src/oauth1/signature";

test("RFC 5849 section 3.4.1 example normalizes duplicate parameters", async () => {
  const base = oauth1SignatureBaseString("POST", "http://example.com/request?b5=%3D%253D&a3=a&c%40=&a2=r%20b", [
    ["oauth_consumer_key", "9djdj82h48djs9d2"], ["oauth_token", "kkk9d7dh3k39sjv7"],
    ["oauth_signature_method", "HMAC-SHA1"], ["oauth_timestamp", "137131201"],
    ["oauth_nonce", "7d8f3e4a"], ["c2", ""], ["a3", "2 q"],
  ]);
  expect(base).toBe("POST&http%3A%2F%2Fexample.com%2Frequest&a2%3Dr%2520b%26a3%3D2%2520q%26a3%3Da%26b5%3D%253D%25253D%26c%2540%3D%26c2%3D%26oauth_consumer_key%3D9djdj82h48djs9d2%26oauth_nonce%3D7d8f3e4a%26oauth_signature_method%3DHMAC-SHA1%26oauth_timestamp%3D137131201%26oauth_token%3Dkkk9d7dh3k39sjv7");
  expect(await oauth1HmacSha1(base, "j49sk3j29djd", "dh893hdasih9")).toBe("r6/TJjbCOr97/+UU0NsvSne7s5g=");
});

test("percent encoding uses RFC 5849 rules", () => {
  expect(oauthPercentEncode("!'()* ~")).toBe("%21%27%28%29%2A%20~");
  expect(oauth1SignatureBaseString("GET", "https://example.test/?realm=example", []))
    .toContain("realm%3Dexample");
});
