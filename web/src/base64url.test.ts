import { describe, expect, it } from "vitest";
import { base64UrlToBytes, bytesToBase64Url } from "./base64url";

describe("base64url", () => {
  it("round-trips bytes that include the characters base64 would pad", () => {
    const bytes = new Uint8Array([0, 255, 16, 32, 63]);
    const encoded = bytesToBase64Url(bytes);
    expect(encoded).not.toMatch(/[+/=]/);
    expect([...base64UrlToBytes(encoded)]).toEqual([...bytes]);
  });
});
