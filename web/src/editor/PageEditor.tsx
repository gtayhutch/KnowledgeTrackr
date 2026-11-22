import type { JSONContent } from "@tiptap/core";
import { EditorContent, useEditor } from "@tiptap/react";
import {
  useCallback,
  useEffect,
  useRef,
  useState,
  type FormEvent,
} from "react";
import "tippy.js/dist/tippy.css";
import { api, ApiError, uploadFile } from "../api";
import { Button, Input, Label, QuietButton } from "../components";
import { emptyDoc } from "./content";
import { isAllowedEmbedUrl } from "./embeds";
import { createPageExtensions } from "./extensions";
import type { MentionItem } from "./MentionList";

export type PageDocument = {
  id: string;
  title: string;
  content: JSONContent;
  updatedAt: number;
};

type Attachment = {
  id: string;
  fileName: string;
  contentType: string;
  byteSize: number;
};

type Props = {
  companyId: string;
  spaceId: string;
  pageId?: string;
  parentId?: string | null;
  composing: boolean;
  onCreated: (id: string) => void;
  onMessage: (message: string | null) => void;
};

/** Single-writer TipTap page editor with view/edit and autosave (ADR 0007). */
export function PageEditor({
  companyId,
  spaceId,
  pageId,
  parentId,
  composing,
  onCreated,
  onMessage,
}: Props) {
  const [title, setTitle] = useState("");
  const [editing, setEditing] = useState(composing || !pageId);
  const [updatedAt, setUpdatedAt] = useState<number | null>(null);
  const [files, setFiles] = useState<Attachment[]>([]);
  const [saving, setSaving] = useState(false);
  const [ready, setReady] = useState(false);
  const saveTimer = useRef<number | null>(null);
  const updatedAtRef = useRef<number | null>(null);
  const titleRef = useRef(title);
  const pageIdRef = useRef(pageId);
  const mentionsRef = useRef<MentionItem[]>([]);

  titleRef.current = title;
  pageIdRef.current = pageId;
  updatedAtRef.current = updatedAt;

  const loadMentions = useCallback(
    async (query: string): Promise<MentionItem[]> => {
      const q = query.trim().toLowerCase();
      return mentionsRef.current
        .filter((item) => item.label.toLowerCase().includes(q))
        .slice(0, 8);
    },
    [],
  );

  const editor = useEditor({
    extensions: createPageExtensions(loadMentions),
    content: emptyDoc,
    editable: editing,
    onUpdate: () => {
      if (!editing || !pageIdRef.current) return;
      scheduleSave();
    },
  });

  function scheduleSave() {
    if (saveTimer.current) window.clearTimeout(saveTimer.current);
    saveTimer.current = window.setTimeout(() => {
      void persist(false);
    }, 1500);
  }

  async function persist(isCreate: boolean) {
    if (!editor) return;
    const content = editor.getJSON();
    setSaving(true);
    onMessage(null);
    try {
      if (isCreate || !pageIdRef.current) {
        const created = await api<{ id: string; updatedAt: number }>(
          `/api/companies/${companyId}/articles`,
          {
            method: "POST",
            body: JSON.stringify({
              title: titleRef.current,
              content,
              spaceId,
              parentId: parentId ?? null,
            }),
          },
        );
        setUpdatedAt(created.updatedAt);
        onCreated(created.id);
      } else {
        const expected = updatedAtRef.current;
        if (expected == null) return;
        const result = await api<{ updatedAt: number }>(
          `/api/companies/${companyId}/articles/${pageIdRef.current}`,
          {
            method: "PUT",
            body: JSON.stringify({
              title: titleRef.current,
              content,
              expectedUpdatedAt: expected,
            }),
          },
        );
        setUpdatedAt(result.updatedAt);
      }
    } catch (error) {
      if (error instanceof ApiError && error.code === "CONFLICT") {
        onMessage("Someone else saved this page. Reload before editing again.");
        setEditing(false);
      } else {
        onMessage(error instanceof Error ? error.message : "Save failed.");
      }
    } finally {
      setSaving(false);
    }
  }

  useEffect(() => {
    void api<{
      people: { id: string; label: string }[];
      pages: { id: string; label: string; spaceId: string }[];
    }>(
      `/api/companies/${companyId}/mention-targets?spaceId=${encodeURIComponent(spaceId)}`,
    )
      .then((data) => {
        mentionsRef.current = [
          ...data.people.map((person) => ({
            id: person.id,
            label: person.label,
            kind: "person" as const,
          })),
          ...data.pages.map((page) => ({
            id: page.id,
            label: page.label,
            kind: "page" as const,
            href: `#/app/${companyId}/${page.spaceId}/${page.id}`,
          })),
        ];
      })
      .catch(() => {
        mentionsRef.current = [];
      });
  }, [companyId, spaceId]);

  useEffect(() => {
    editor?.setEditable(editing);
  }, [editing, editor]);

  useEffect(() => {
    let cancelled = false;
    async function load() {
      setReady(false);
      if (!pageId) {
        setTitle("");
        setUpdatedAt(null);
        setFiles([]);
        setEditing(true);
        editor?.commands.setContent(emptyDoc);
        setReady(true);
        return;
      }
      try {
        const page = await api<PageDocument & { body?: string }>(
          `/api/companies/${companyId}/articles/${pageId}`,
        );
        if (cancelled) return;
        setTitle(page.title);
        setUpdatedAt(page.updatedAt);
        setEditing(false);
        editor?.commands.setContent(page.content ?? emptyDoc);
        setFiles(
          await api<Attachment[]>(
            `/api/companies/${companyId}/articles/${pageId}/attachments`,
          ),
        );
      } catch (error) {
        onMessage(error instanceof Error ? error.message : "Load failed.");
      } finally {
        if (!cancelled) setReady(true);
      }
    }
    void load();
    return () => {
      cancelled = true;
    };
  }, [pageId, companyId, editor, onMessage]);

  useEffect(() => {
    return () => {
      if (saveTimer.current) window.clearTimeout(saveTimer.current);
    };
  }, []);

  async function onUpload(file: File | undefined) {
    if (!file || !pageId || !editor) return;
    onMessage(null);
    try {
      const uploaded = await uploadFile(companyId, pageId, file);
      setFiles(
        await api<Attachment[]>(
          `/api/companies/${companyId}/articles/${pageId}/attachments`,
        ),
      );
      if (file.type.startsWith("image/")) {
        editor
          .chain()
          .focus()
          .setImage({
            src: `/api/companies/${companyId}/attachments/${uploaded.id}`,
          })
          .run();
      }
    } catch (error) {
      onMessage(error instanceof Error ? error.message : "Upload failed.");
    }
  }

  function insertEmbed(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!editor) return;
    const data = new FormData(event.currentTarget);
    const src = String(data.get("src") ?? "");
    if (!isAllowedEmbedUrl(src)) {
      onMessage("That embed host is not allowed.");
      return;
    }
    editor
      .chain()
      .focus()
      .insertContent({ type: "embed", attrs: { src } })
      .run();
    event.currentTarget.reset();
  }

  if (!ready || !editor) {
    return <p className="text-sm">Loading page…</p>;
  }

  return (
    <div className="kt-page-editor">
      <div className="mb-4 flex flex-wrap items-center gap-2">
        {pageId && !composing ? (
          <QuietButton
            type="button"
            onClick={() => setEditing((value) => !value)}
          >
            {editing ? "Done" : "Edit"}
          </QuietButton>
        ) : null}
        {editing ? (
          <Button
            type="button"
            disabled={saving}
            onClick={() => void persist(!pageId)}
          >
            {saving ? "Saving…" : pageId ? "Save now" : "Create page"}
          </Button>
        ) : null}
        {saving ? <span className="text-xs">Autosaving…</span> : null}
      </div>

      {editing ? (
        <>
          <Label htmlFor="pageTitle">Title</Label>
          <Input
            id="pageTitle"
            value={title}
            onChange={(event) => {
              setTitle(event.target.value);
              if (pageId) scheduleSave();
            }}
            required
          />
          <div className="kt-toolbar mt-4 flex flex-wrap gap-1">
            <QuietButton
              type="button"
              onClick={() => editor.chain().focus().toggleBold().run()}
            >
              Bold
            </QuietButton>
            <QuietButton
              type="button"
              onClick={() => editor.chain().focus().toggleItalic().run()}
            >
              Italic
            </QuietButton>
            <QuietButton
              type="button"
              onClick={() =>
                editor.chain().focus().toggleHeading({ level: 2 }).run()
              }
            >
              H2
            </QuietButton>
            <QuietButton
              type="button"
              onClick={() => editor.chain().focus().toggleBulletList().run()}
            >
              List
            </QuietButton>
            <QuietButton
              type="button"
              onClick={() => editor.chain().focus().toggleCodeBlock().run()}
            >
              Code
            </QuietButton>
            <QuietButton
              type="button"
              onClick={() =>
                editor
                  .chain()
                  .focus()
                  .insertTable({ rows: 3, cols: 3, withHeaderRow: true })
                  .run()
              }
            >
              Table
            </QuietButton>
            <QuietButton
              type="button"
              onClick={() =>
                editor
                  .chain()
                  .focus()
                  .insertContent({
                    type: "callout",
                    content: [{ type: "paragraph" }],
                  })
                  .run()
              }
            >
              Callout
            </QuietButton>
            <QuietButton
              type="button"
              onClick={() =>
                editor
                  .chain()
                  .focus()
                  .insertContent({
                    type: "mermaid",
                    attrs: { source: "flowchart LR\n  A-->B" },
                  })
                  .run()
              }
            >
              Mermaid
            </QuietButton>
            <QuietButton
              type="button"
              onClick={() => {
                const latex = window.prompt("LaTeX", "e=mc^2");
                if (!latex) return;
                editor
                  .chain()
                  .focus()
                  .insertContent({ type: "mathInline", attrs: { latex } })
                  .run();
              }}
            >
              Math
            </QuietButton>
          </div>
          <form
            className="mt-2 flex gap-2"
            onSubmit={(event) => insertEmbed(event)}
          >
            <Input
              name="src"
              aria-label="Embed URL"
              placeholder="https://www.youtube.com/…"
            />
            <QuietButton type="submit">Embed</QuietButton>
          </form>
        </>
      ) : (
        <h1 className="mb-4 text-3xl">{title || "Untitled"}</h1>
      )}

      <EditorContent editor={editor} className="kt-editor mt-4" />

      {pageId ? (
        <div className="mt-8">
          <h2 className="mb-2 text-xl">Files</h2>
          <ul className="mb-3 text-sm">
            {files.map((file) => (
              <li key={file.id}>
                <a href={`/api/companies/${companyId}/attachments/${file.id}`}>
                  {file.fileName}
                </a>
              </li>
            ))}
          </ul>
          {editing ? (
            <input
              type="file"
              aria-label="Upload a file"
              onChange={(event) => void onUpload(event.target.files?.[0])}
            />
          ) : null}
        </div>
      ) : null}
    </div>
  );
}
