import type { JSONContent } from "@tiptap/core";

/** Empty TipTap document. */
export const emptyDoc: JSONContent = {
  type: "doc",
  content: [{ type: "paragraph" }],
};

/** Wraps legacy plain text into a TipTap document (ADR 0011). */
export function docFromPlainText(body: string): JSONContent {
  if (!body.trim()) return emptyDoc;
  return {
    type: "doc",
    content: [
      {
        type: "paragraph",
        content: [{ type: "text", text: body }],
      },
    ],
  };
}
