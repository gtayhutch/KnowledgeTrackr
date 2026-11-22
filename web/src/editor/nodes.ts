import { mergeAttributes, Node } from "@tiptap/core";
import { isAllowedEmbedUrl } from "./embeds";

/** Callout / admonition block. */
export const Callout = Node.create({
  name: "callout",
  group: "block",
  content: "block+",
  defining: true,
  addAttributes() {
    return {
      variant: {
        default: "note",
        parseHTML: (element) => element.getAttribute("data-variant") ?? "note",
        renderHTML: (attributes) => ({
          "data-variant": attributes.variant as string,
        }),
      },
    };
  },
  parseHTML() {
    return [{ tag: 'aside[data-type="callout"]' }];
  },
  renderHTML({ HTMLAttributes }) {
    return [
      "aside",
      mergeAttributes(HTMLAttributes, {
        "data-type": "callout",
        class: "kt-callout",
      }),
      0,
    ];
  },
});

/** Mermaid source block; rendered client-side. */
export const Mermaid = Node.create({
  name: "mermaid",
  group: "block",
  atom: true,
  addAttributes() {
    return {
      source: {
        default: "flowchart LR\n  A-->B",
        parseHTML: (element) => element.textContent ?? "",
        renderHTML: () => ({}),
      },
    };
  },
  parseHTML() {
    return [{ tag: 'pre[data-type="mermaid"]' }];
  },
  renderHTML({ node }) {
    return [
      "pre",
      { "data-type": "mermaid", class: "kt-mermaid" },
      node.attrs.source as string,
    ];
  },
  addNodeView() {
    return ({ node }) => {
      const dom = document.createElement("pre");
      dom.className = "kt-mermaid";
      dom.dataset.type = "mermaid";
      dom.textContent = String(node.attrs.source ?? "");
      void renderMermaid(dom, String(node.attrs.source ?? ""));
      return {
        dom,
        update: (updated) => {
          if (updated.type.name !== "mermaid") return false;
          const source = String(updated.attrs.source ?? "");
          dom.textContent = source;
          void renderMermaid(dom, source);
          return true;
        },
      };
    };
  },
});

async function renderMermaid(host: HTMLElement, source: string) {
  try {
    const mermaid = (await import("mermaid")).default;
    mermaid.initialize({ startOnLoad: false, securityLevel: "strict" });
    const id = `mmd-${Math.random().toString(36).slice(2)}`;
    const { svg } = await mermaid.render(id, source);
    host.innerHTML = svg;
  } catch {
    host.textContent = source || "Invalid Mermaid diagram";
  }
}

/** Inline KaTeX math. */
export const MathInline = Node.create({
  name: "mathInline",
  group: "inline",
  inline: true,
  atom: true,
  addAttributes() {
    return {
      latex: { default: "" },
    };
  },
  parseHTML() {
    return [{ tag: 'span[data-type="math-inline"]' }];
  },
  renderHTML({ node }) {
    return [
      "span",
      { "data-type": "math-inline", class: "kt-math-inline" },
      String(node.attrs.latex ?? ""),
    ];
  },
  addNodeView() {
    return ({ node }) => {
      const dom = document.createElement("span");
      dom.className = "kt-math-inline";
      dom.dataset.type = "math-inline";
      void renderKatex(dom, String(node.attrs.latex ?? ""), false);
      return {
        dom,
        update: (updated) => {
          if (updated.type.name !== "mathInline") return false;
          void renderKatex(dom, String(updated.attrs.latex ?? ""), false);
          return true;
        },
      };
    };
  },
});

/** Block KaTeX math. */
export const MathBlock = Node.create({
  name: "mathBlock",
  group: "block",
  atom: true,
  addAttributes() {
    return {
      latex: { default: "" },
    };
  },
  parseHTML() {
    return [{ tag: 'div[data-type="math-block"]' }];
  },
  renderHTML({ node }) {
    return [
      "div",
      { "data-type": "math-block", class: "kt-math-block" },
      String(node.attrs.latex ?? ""),
    ];
  },
  addNodeView() {
    return ({ node }) => {
      const dom = document.createElement("div");
      dom.className = "kt-math-block";
      dom.dataset.type = "math-block";
      void renderKatex(dom, String(node.attrs.latex ?? ""), true);
      return {
        dom,
        update: (updated) => {
          if (updated.type.name !== "mathBlock") return false;
          void renderKatex(dom, String(updated.attrs.latex ?? ""), true);
          return true;
        },
      };
    };
  },
});

async function renderKatex(
  host: HTMLElement,
  latex: string,
  displayMode: boolean,
) {
  try {
    const katex = (await import("katex")).default;
    await import("katex/dist/katex.min.css");
    host.innerHTML = katex.renderToString(latex || "\\;", {
      throwOnError: false,
      displayMode,
    });
  } catch {
    host.textContent = latex;
  }
}

/** Allowlisted iframe embed. */
export const Embed = Node.create({
  name: "embed",
  group: "block",
  atom: true,
  addAttributes() {
    return {
      src: { default: "" },
    };
  },
  parseHTML() {
    return [{ tag: 'div[data-type="embed"]' }];
  },
  renderHTML({ node }) {
    return [
      "div",
      { "data-type": "embed", "data-src": String(node.attrs.src ?? "") },
    ];
  },
  addNodeView() {
    return ({ node }) => {
      const wrap = document.createElement("div");
      wrap.className = "kt-embed";
      wrap.dataset.type = "embed";
      const src = String(node.attrs.src ?? "");
      if (isAllowedEmbedUrl(src)) {
        const frame = document.createElement("iframe");
        frame.src = src;
        frame.title = "Embedded content";
        frame.loading = "lazy";
        frame.referrerPolicy = "no-referrer";
        frame.setAttribute(
          "sandbox",
          "allow-scripts allow-same-origin allow-presentation",
        );
        wrap.append(frame);
      } else {
        wrap.textContent = "Embed blocked";
      }
      return { dom: wrap };
    };
  },
});
