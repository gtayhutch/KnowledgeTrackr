/** A failed API call. `field` names the input the person should correct. */
export class ApiError extends Error {
  readonly field: string | undefined;
  readonly status: number;
  readonly code: string;

  constructor(message: string, status: number, code: string, field?: string) {
    super(message);
    this.name = "ApiError";
    this.status = status;
    this.code = code;
    this.field = field;
  }
}

type Envelope<T> = {
  ok: boolean;
  data?: T;
  message?: string;
  code?: string;
  field?: string;
};

/** Calls the Worker. The session cookie is sent when one exists. */
export async function api<T>(path: string, init: RequestInit = {}): Promise<T> {
  const headers = new Headers(init.headers);
  if (init.body !== undefined && !headers.has("content-type")) {
    headers.set("content-type", "application/json");
  }
  const response = await fetch(path, {
    ...init,
    headers,
    credentials: "include",
  });
  const text = await response.text();
  const body = (text ? JSON.parse(text) : { ok: response.ok }) as Envelope<T>;
  if (!response.ok || !body.ok) {
    throw new ApiError(
      body.message ?? "The request failed.",
      response.status,
      body.code ?? "ERROR",
      body.field,
    );
  }
  return body.data as T;
}

/** Uploads one file. The Worker checks the type and the 10 MB limit. */
export function uploadFile(
  companyId: string,
  articleId: string,
  file: File,
): Promise<{ id: string }> {
  return api(`/api/companies/${companyId}/articles/${articleId}/attachments`, {
    method: "POST",
    headers: {
      "content-type": contentTypeFor(file),
      "x-file-name": file.name,
    },
    body: file,
  });
}

function contentTypeFor(file: File): string {
  if (file.type) {
    return file.type.split(";")[0]?.trim() || "application/octet-stream";
  }
  const name = file.name.toLowerCase();
  if (name.endsWith(".md")) return "text/markdown";
  if (name.endsWith(".txt")) return "text/plain";
  if (name.endsWith(".png")) return "image/png";
  if (name.endsWith(".jpg") || name.endsWith(".jpeg")) return "image/jpeg";
  if (name.endsWith(".webp")) return "image/webp";
  if (name.endsWith(".pdf")) return "application/pdf";
  return "application/octet-stream";
}
