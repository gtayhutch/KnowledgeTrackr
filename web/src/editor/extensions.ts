import CodeBlockLowlight from "@tiptap/extension-code-block-lowlight";
import Image from "@tiptap/extension-image";
import Link from "@tiptap/extension-link";
import Mention from "@tiptap/extension-mention";
import Placeholder from "@tiptap/extension-placeholder";
import { Table } from "@tiptap/extension-table";
import TableCell from "@tiptap/extension-table-cell";
import TableHeader from "@tiptap/extension-table-header";
import TableRow from "@tiptap/extension-table-row";
import { ReactRenderer } from "@tiptap/react";
import StarterKit from "@tiptap/starter-kit";
import { common, createLowlight } from "lowlight";
import tippy, { type Instance as TippyInstance } from "tippy.js";
import {
  MentionList,
  type MentionItem,
  type MentionListRef,
} from "./MentionList";
import { Callout, Embed, MathBlock, MathInline, Mermaid } from "./nodes";

const lowlight = createLowlight(common);

export type MentionLoader = (
  query: string,
) => MentionItem[] | Promise<MentionItem[]>;

/** TipTap extensions for KnowledgeTrackr pages. */
export function createPageExtensions(loadMentions: MentionLoader) {
  return [
    StarterKit.configure({
      codeBlock: false,
    }),
    Placeholder.configure({
      placeholder: "Write the page…",
    }),
    Link.configure({
      openOnClick: false,
      autolink: true,
      HTMLAttributes: { class: "kt-link" },
    }),
    Image.configure({
      HTMLAttributes: { class: "kt-image" },
    }),
    Table.configure({ resizable: true }),
    TableRow,
    TableHeader,
    TableCell,
    CodeBlockLowlight.configure({ lowlight }),
    Callout,
    Mermaid,
    MathInline,
    MathBlock,
    Embed,
    Mention.configure({
      HTMLAttributes: { class: "kt-mention" },
      suggestion: {
        items: async ({ query }) => loadMentions(query),
        render: () => {
          let component: ReactRenderer<MentionListRef> | undefined;
          let popup: TippyInstance[] | undefined;
          return {
            onStart: (props) => {
              component = new ReactRenderer(MentionList, {
                props: {
                  items: props.items as MentionItem[],
                  command: props.command,
                },
                editor: props.editor,
              });
              if (!props.clientRect) return;
              popup = tippy("body", {
                getReferenceClientRect: props.clientRect as () => DOMRect,
                appendTo: () => document.body,
                content: component.element,
                showOnCreate: true,
                interactive: true,
                trigger: "manual",
                placement: "bottom-start",
              });
            },
            onUpdate: (props) => {
              component?.updateProps({
                items: props.items as MentionItem[],
                command: props.command,
              });
              if (props.clientRect) {
                popup?.[0]?.setProps({
                  getReferenceClientRect: props.clientRect as () => DOMRect,
                });
              }
            },
            onKeyDown: (props) => {
              if (props.event.key === "Escape") {
                popup?.[0]?.hide();
                return true;
              }
              return component?.ref?.onKeyDown(props) ?? false;
            },
            onExit: () => {
              popup?.[0]?.destroy();
              component?.destroy();
            },
          };
        },
      },
    }),
  ];
}
