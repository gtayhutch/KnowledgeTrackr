import { describe, expect, it } from "vitest";
import { isAllowedEmbedUrl } from "./embeds";

describe("isAllowedEmbedUrl", () => {
  it("allows https YouTube embeds", () => {
    expect(isAllowedEmbedUrl("https://www.youtube.com/embed/abc")).toBe(true);
  });

  it("rejects non-allowlisted hosts and http", () => {
    expect(isAllowedEmbedUrl("https://evil.example/x")).toBe(false);
    expect(isAllowedEmbedUrl("http://www.youtube.com/embed/abc")).toBe(false);
  });
});
