import { useEffect, useState, type FormEvent } from "react";
import { api, ApiError, uploadFile } from "./api";
import { Button, Input, Label, QuietButton, TextArea } from "./components";
import {
  createPasskey,
  getPasskey,
  type CreationOptions,
  type RequestOptions,
} from "./passkey";

type Session = {
  user: { id: string; email: string; displayName: string };
  companies: { id: string; name: string; role: string }[];
};

type Article = {
  id: string;
  title: string;
  body: string;
  authorId: string;
  updatedAt: number;
};

type Attachment = {
  id: string;
  fileName: string;
  contentType: string;
  byteSize: number;
};

type Route =
  | { screen: "sign-in" }
  | { screen: "enroll"; token?: string }
  | { screen: "recover"; token?: string }
  | { screen: "library"; companyId?: string; articleId?: string };

/** KnowledgeTrackr. Hash routes keep the email links free of a router package. */
export function App() {
  const [route, setRoute] = useState<Route>(() => readRoute());
  const [session, setSession] = useState<Session | null>(null);
  const [ready, setReady] = useState(false);

  useEffect(() => {
    const sync = () => setRoute(readRoute());
    window.addEventListener("hashchange", sync);
    api<Session>("/api/session")
      .then(setSession)
      .catch(() => setSession(null))
      .finally(() => setReady(true));
    return () => window.removeEventListener("hashchange", sync);
  }, []);

  async function refresh() {
    setSession(await api<Session>("/api/session"));
  }

  if (!ready) {
    return <p className="p-8 text-sm">Loading…</p>;
  }

  return (
    <div className="mx-auto min-h-screen max-w-6xl px-6 py-8">
      <header className="mb-8 flex items-baseline justify-between border-b border-rule pb-4">
        <a href="#/app" className="font-serif text-2xl">
          KnowledgeTrackr
        </a>
        {session ? (
          <div className="flex items-center gap-4 text-sm">
            <span>{session.user.displayName}</span>
            <QuietButton
              type="button"
              onClick={() => {
                void api("/api/auth/sign-out", { method: "POST" }).finally(
                  () => {
                    setSession(null);
                    location.hash = "#/sign-in";
                  },
                );
              }}
            >
              Sign out
            </QuietButton>
          </div>
        ) : (
          <nav className="flex gap-4 text-sm">
            <a href="#/sign-in">Sign in</a>
            <a href="#/enroll">Create an account</a>
          </nav>
        )}
      </header>
      {route.screen === "sign-in" ? <SignIn onSignedIn={setSession} /> : null}
      {route.screen === "enroll" ? (
        <Enroll token={route.token} onSignedIn={setSession} />
      ) : null}
      {route.screen === "recover" ? (
        <Recover token={route.token} onSignedIn={setSession} />
      ) : null}
      {route.screen === "library" ? (
        session ? (
          <Library
            session={session}
            companyId={route.companyId}
            articleId={route.articleId}
            onChanged={() => void refresh()}
          />
        ) : (
          <SignIn onSignedIn={setSession} />
        )
      ) : null}
    </div>
  );
}

function SignIn({ onSignedIn }: { onSignedIn: (session: Session) => void }) {
  const [email, setEmail] = useState("");
  const [message, setMessage] = useState<string | null>(null);
  const [pending, setPending] = useState(false);

  async function submit(event: FormEvent) {
    event.preventDefault();
    setPending(true);
    setMessage(null);
    try {
      const options = await api<RequestOptions>("/api/auth/sign-in/options", {
        method: "POST",
        body: JSON.stringify({ email }),
      });
      const ceremony = await getPasskey(options);
      await api("/api/auth/sign-in/finish", {
        method: "POST",
        body: JSON.stringify({ email, ...ceremony }),
      });
      onSignedIn(await api<Session>("/api/session"));
      location.hash = "#/app";
    } catch (error) {
      setMessage(messageOf(error));
    } finally {
      setPending(false);
    }
  }

  return (
    <form onSubmit={(event) => void submit(event)} className="mx-auto max-w-md">
      <h1 className="mb-2 text-3xl">Sign in</h1>
      <p className="mb-6 text-sm">
        Use the passkey for this account. There is no password.
      </p>
      <Label htmlFor="email">Email</Label>
      <Input
        id="email"
        type="email"
        value={email}
        onChange={(event) => setEmail(event.target.value)}
        required
      />
      {message ? <p className="mt-3 text-sm">{message}</p> : null}
      <Button className="mt-4" type="submit" disabled={pending}>
        {pending ? "Waiting for the passkey…" : "Continue with a passkey"}
      </Button>
      <p className="mt-6 text-sm">
        <a href="#/recover">Lost the passkey?</a>
      </p>
    </form>
  );
}

function Enroll({
  token,
  onSignedIn,
}: {
  token?: string;
  onSignedIn: (session: Session) => void;
}) {
  const [email, setEmail] = useState("");
  const [displayName, setDisplayName] = useState("");
  const [message, setMessage] = useState<string | null>(null);
  const [pending, setPending] = useState(false);
  const [sent, setSent] = useState(false);

  async function start(event: FormEvent) {
    event.preventDefault();
    setPending(true);
    setMessage(null);
    try {
      await api("/api/auth/enroll/start", {
        method: "POST",
        body: JSON.stringify({ email, displayName }),
      });
      setSent(true);
    } catch (error) {
      setMessage(messageOf(error));
    } finally {
      setPending(false);
    }
  }

  async function finish(event: FormEvent) {
    event.preventDefault();
    if (!token) return;
    setPending(true);
    setMessage(null);
    try {
      const options = await api<CreationOptions>("/api/auth/enroll/options", {
        method: "POST",
        body: JSON.stringify({ token, displayName }),
      });
      const ceremony = await createPasskey(options);
      await api("/api/auth/enroll/finish", {
        method: "POST",
        body: JSON.stringify({ token, displayName, ...ceremony }),
      });
      onSignedIn(await api<Session>("/api/session"));
      location.hash = "#/app";
    } catch (error) {
      setMessage(messageOf(error));
    } finally {
      setPending(false);
    }
  }

  if (token) {
    return (
      <form
        onSubmit={(event) => void finish(event)}
        className="mx-auto max-w-md"
      >
        <h1 className="mb-2 text-3xl">Create your passkey</h1>
        <p className="mb-6 text-sm">
          This link expires in 15 minutes and does not sign you in by itself.
        </p>
        <Label htmlFor="displayName">Name</Label>
        <Input
          id="displayName"
          value={displayName}
          onChange={(event) => setDisplayName(event.target.value)}
          required
        />
        {message ? <p className="mt-3 text-sm">{message}</p> : null}
        <Button className="mt-4" type="submit" disabled={pending}>
          {pending ? "Waiting for the passkey…" : "Create a passkey"}
        </Button>
      </form>
    );
  }

  return (
    <form onSubmit={(event) => void start(event)} className="mx-auto max-w-md">
      <h1 className="mb-2 text-3xl">Create an account</h1>
      <p className="mb-6 text-sm">
        We email a link. You create the passkey on the next page.
      </p>
      <Label htmlFor="displayName">Name</Label>
      <Input
        id="displayName"
        value={displayName}
        onChange={(event) => setDisplayName(event.target.value)}
        required
      />
      <div className="mt-4">
        <Label htmlFor="email">Email</Label>
        <Input
          id="email"
          type="email"
          value={email}
          onChange={(event) => setEmail(event.target.value)}
          required
        />
      </div>
      {sent ? (
        <p className="mt-3 text-sm">Check your email for the link.</p>
      ) : null}
      {message ? <p className="mt-3 text-sm">{message}</p> : null}
      <Button className="mt-4" type="submit" disabled={pending}>
        {pending ? "Sending…" : "Email me a link"}
      </Button>
    </form>
  );
}

function Recover({
  token,
  onSignedIn,
}: {
  token?: string;
  onSignedIn: (session: Session) => void;
}) {
  const [email, setEmail] = useState("");
  const [message, setMessage] = useState<string | null>(null);
  const [pending, setPending] = useState(false);
  const [sent, setSent] = useState(false);

  async function start(event: FormEvent) {
    event.preventDefault();
    setPending(true);
    setMessage(null);
    try {
      await api("/api/auth/recover/start", {
        method: "POST",
        body: JSON.stringify({ email }),
      });
      setSent(true);
    } catch (error) {
      setMessage(messageOf(error));
    } finally {
      setPending(false);
    }
  }

  async function finish(event: FormEvent) {
    event.preventDefault();
    if (!token) return;
    setPending(true);
    setMessage(null);
    try {
      const options = await api<CreationOptions>("/api/auth/recover/options", {
        method: "POST",
        body: JSON.stringify({ token }),
      });
      const ceremony = await createPasskey(options);
      await api("/api/auth/recover/finish", {
        method: "POST",
        body: JSON.stringify({ token, ...ceremony }),
      });
      onSignedIn(await api<Session>("/api/session"));
      location.hash = "#/app";
    } catch (error) {
      setMessage(messageOf(error));
    } finally {
      setPending(false);
    }
  }

  if (token) {
    return (
      <form
        onSubmit={(event) => void finish(event)}
        className="mx-auto max-w-md"
      >
        <h1 className="mb-2 text-3xl">Replace your passkey</h1>
        <p className="mb-6 text-sm">
          The previous passkey stops working after this one is saved.
        </p>
        {message ? <p className="mb-3 text-sm">{message}</p> : null}
        <Button type="submit" disabled={pending}>
          {pending
            ? "Waiting for the passkey…"
            : "Create a replacement passkey"}
        </Button>
      </form>
    );
  }

  return (
    <form onSubmit={(event) => void start(event)} className="mx-auto max-w-md">
      <h1 className="mb-2 text-3xl">Replace a passkey</h1>
      <p className="mb-6 text-sm">
        If the address has an account, we email a recovery link.
      </p>
      <Label htmlFor="email">Email</Label>
      <Input
        id="email"
        type="email"
        value={email}
        onChange={(event) => setEmail(event.target.value)}
        required
      />
      {sent ? (
        <p className="mt-3 text-sm">
          If that account exists, the link is on its way.
        </p>
      ) : null}
      {message ? <p className="mt-3 text-sm">{message}</p> : null}
      <Button className="mt-4" type="submit" disabled={pending}>
        {pending ? "Sending…" : "Email me a link"}
      </Button>
    </form>
  );
}

function Library({
  session,
  companyId,
  articleId,
  onChanged,
}: {
  session: Session;
  companyId?: string;
  articleId?: string;
  onChanged: () => void;
}) {
  const company =
    session.companies.find((item) => item.id === companyId) ??
    session.companies[0];
  const [name, setName] = useState("");
  const [memberEmail, setMemberEmail] = useState("");
  const [memberRole, setMemberRole] = useState("member");
  const [query, setQuery] = useState("");
  const [articles, setArticles] = useState<Article[]>([]);
  const [title, setTitle] = useState("");
  const [body, setBody] = useState("");
  const [files, setFiles] = useState<Attachment[]>([]);
  const [message, setMessage] = useState<string | null>(null);

  useEffect(() => {
    if (!company) return;
    const activeId = companyId ?? company.id;
    void api<Article[]>(
      `/api/companies/${activeId}/articles?q=${encodeURIComponent(query)}`,
    )
      .then(setArticles)
      .catch((error: unknown) => setMessage(messageOf(error)));
  }, [company, companyId, query]);

  useEffect(() => {
    if (!company || !articleId) {
      setTitle("");
      setBody("");
      setFiles([]);
      return;
    }
    const activeId = companyId ?? company.id;
    void api<Article>(`/api/companies/${activeId}/articles/${articleId}`).then(
      (article) => {
        setTitle(article.title);
        setBody(article.body);
      },
    );
    void api<Attachment[]>(
      `/api/companies/${activeId}/articles/${articleId}/attachments`,
    ).then(setFiles);
  }, [articleId, company, companyId]);

  async function createCompany(event: FormEvent) {
    event.preventDefault();
    const created = await api<{ id: string }>("/api/companies", {
      method: "POST",
      body: JSON.stringify({ name }),
    });
    setName("");
    onChanged();
    location.hash = `#/app/${created.id}`;
  }

  if (!company) {
    return (
      <form
        onSubmit={(event) => void createCompany(event)}
        className="max-w-md"
      >
        <h1 className="mb-2 text-3xl">Start a company library</h1>
        <Label htmlFor="companyName">Company name</Label>
        <Input
          id="companyName"
          value={name}
          onChange={(event) => setName(event.target.value)}
          required
        />
        <Button className="mt-4" type="submit">
          Create the library
        </Button>
      </form>
    );
  }

  const activeCompanyId = companyId ?? company.id;

  async function saveArticle(event: FormEvent) {
    event.preventDefault();
    setMessage(null);
    try {
      if (articleId) {
        await api(`/api/companies/${activeCompanyId}/articles/${articleId}`, {
          method: "PUT",
          body: JSON.stringify({ title, body }),
        });
      } else {
        const created = await api<{ id: string }>(
          `/api/companies/${activeCompanyId}/articles`,
          {
            method: "POST",
            body: JSON.stringify({ title, body }),
          },
        );
        location.hash = `#/app/${activeCompanyId}/${created.id}`;
      }
      const next = await api<Article[]>(
        `/api/companies/${activeCompanyId}/articles?q=${encodeURIComponent(query)}`,
      );
      setArticles(next);
    } catch (error) {
      setMessage(messageOf(error));
    }
  }

  async function onUpload(file: File | undefined) {
    if (!file || !articleId) return;
    setMessage(null);
    try {
      await uploadFile(activeCompanyId, articleId, file);
      setFiles(
        await api<Attachment[]>(
          `/api/companies/${activeCompanyId}/articles/${articleId}/attachments`,
        ),
      );
    } catch (error) {
      setMessage(messageOf(error));
    }
  }

  return (
    <div className="grid gap-8 md:grid-cols-[16rem_1fr]">
      <aside>
        <ul className="mb-6 space-y-2 text-sm">
          {session.companies.map((item) => (
            <li key={item.id}>
              <a
                href={`#/app/${item.id}`}
                className={item.id === activeCompanyId ? "font-semibold" : ""}
              >
                {item.name}
              </a>
            </li>
          ))}
        </ul>
        <form onSubmit={(event) => void createCompany(event)} className="mb-6">
          <Label htmlFor="companyName">New company</Label>
          <Input
            id="companyName"
            value={name}
            onChange={(event) => setName(event.target.value)}
          />
          <QuietButton className="mt-2" type="submit">
            Add
          </QuietButton>
        </form>
        {company.role === "admin" ? (
          <form
            onSubmit={(event) => {
              event.preventDefault();
              void api(`/api/companies/${activeCompanyId}/members`, {
                method: "POST",
                body: JSON.stringify({ email: memberEmail, role: memberRole }),
              })
                .then(() => {
                  setMemberEmail("");
                  setMessage("Member added.");
                })
                .catch((error: unknown) => setMessage(messageOf(error)));
            }}
          >
            <Label htmlFor="memberEmail">Add a member</Label>
            <Input
              id="memberEmail"
              type="email"
              value={memberEmail}
              onChange={(event) => setMemberEmail(event.target.value)}
            />
            <select
              className="mt-2 h-10 w-full rounded-md border border-rule bg-white px-3 text-sm"
              value={memberRole}
              onChange={(event) => setMemberRole(event.target.value)}
            >
              <option value="member">Member</option>
              <option value="admin">Admin</option>
            </select>
            <QuietButton className="mt-2" type="submit">
              Add member
            </QuietButton>
          </form>
        ) : null}
      </aside>
      <section>
        <form
          className="mb-4 flex gap-2"
          onSubmit={(event) => {
            event.preventDefault();
            const field = new FormData(event.currentTarget).get("q");
            setQuery(typeof field === "string" ? field : "");
          }}
        >
          <Input
            name="q"
            aria-label="Search articles"
            placeholder="Search articles"
          />
          <QuietButton type="submit">Search</QuietButton>
        </form>
        <ul className="mb-6 divide-y divide-rule border-y border-rule text-sm">
          {articles.map((article) => (
            <li key={article.id}>
              <a
                className="block py-2"
                href={`#/app/${activeCompanyId}/${article.id}`}
              >
                {article.title}
              </a>
            </li>
          ))}
        </ul>
        <form onSubmit={(event) => void saveArticle(event)}>
          <h1 className="mb-4 text-3xl">
            {articleId ? "Edit article" : "New article"}
          </h1>
          <Label htmlFor="title">Title</Label>
          <Input
            id="title"
            value={title}
            onChange={(event) => setTitle(event.target.value)}
            required
          />
          <div className="mt-4">
            <Label htmlFor="body">Body</Label>
            <TextArea
              id="body"
              value={body}
              onChange={(event) => setBody(event.target.value)}
            />
          </div>
          {message ? <p className="mt-3 text-sm">{message}</p> : null}
          <Button className="mt-4" type="submit">
            Save
          </Button>
        </form>
        {articleId ? (
          <div className="mt-8">
            <h2 className="mb-2 text-xl">Files</h2>
            <ul className="mb-3 text-sm">
              {files.map((file) => (
                <li key={file.id}>
                  <a
                    href={`/api/companies/${activeCompanyId}/attachments/${file.id}`}
                  >
                    {file.fileName}
                  </a>
                </li>
              ))}
            </ul>
            <input
              type="file"
              aria-label="Upload a file"
              onChange={(event) => void onUpload(event.target.files?.[0])}
            />
          </div>
        ) : null}
      </section>
    </div>
  );
}

function readRoute(): Route {
  const parts = location.hash.replace(/^#/, "").split("/").filter(Boolean);
  if (parts[0] === "enroll") return { screen: "enroll", token: parts[1] };
  if (parts[0] === "recover") return { screen: "recover", token: parts[1] };
  if (parts[0] === "app")
    return { screen: "library", companyId: parts[1], articleId: parts[2] };
  if (parts.length === 0) return { screen: "sign-in" };
  return { screen: "sign-in" };
}

function messageOf(error: unknown): string {
  if (error instanceof ApiError && error.code === "REAUTH_REQUIRED") {
    return "Sign out and sign in again before changing members or the company name.";
  }
  return error instanceof Error ? error.message : "Something went wrong.";
}
