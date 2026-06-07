import type {
  Me,
  User,
  Profile,
  Server,
  Credential,
  CredentialPutBody,
  AuditPage,
  ApiErrorBody,
} from "@/lib/types";

export class ApiError extends Error {
  constructor(
    public status: number,
    public code: string,
    message: string,
  ) {
    super(message);
    this.name = "ApiError";
  }
}

async function request<T>(
  path: string,
  init?: RequestInit & { json?: unknown },
): Promise<T> {
  const { json, headers, ...rest } = init ?? {};
  const res = await fetch(path, {
    ...rest,
    headers: {
      ...(json !== undefined ? { "Content-Type": "application/json" } : {}),
      ...headers,
    },
    body: json !== undefined ? JSON.stringify(json) : rest.body,
    // Same-origin rewrite forwards the cookie automatically; this is the
    // default but we state it for clarity.
    credentials: "same-origin",
    cache: "no-store",
  });
  if (res.status === 204) return undefined as T;
  const text = await res.text();
  const data = text ? JSON.parse(text) : undefined;
  if (!res.ok) {
    const body = data as ApiErrorBody | undefined;
    throw new ApiError(
      res.status,
      body?.error?.code ?? "unknown",
      body?.error?.message ?? res.statusText,
    );
  }
  return data as T;
}

export const api = {
  me: () => request<Me>("/api/me"),
  logout: () => request<void>("/api/auth/logout", { method: "POST" }),

  listProfiles: () => request<Profile[]>("/api/profiles"),
  getProfile: (id: number) => request<Profile>(`/api/profiles/${id}`),
  createProfile: (body: { name: string; slug: string }) =>
    request<Profile>("/api/profiles", { method: "POST", json: body }),
  renameProfile: (id: number, name: string) =>
    request<Profile>(`/api/profiles/${id}`, { method: "PATCH", json: { name } }),
  deleteProfile: (id: number) =>
    request<void>(`/api/profiles/${id}`, { method: "DELETE" }),
  setProfileServers: (id: number, servers: string[]) =>
    request<Profile>(`/api/profiles/${id}/servers`, {
      method: "PUT",
      json: { servers },
    }),
  rotateProfileToken: (id: number) =>
    request<Profile>(`/api/profiles/${id}/token`, { method: "POST" }),

  listServers: () => request<Server[]>("/api/servers"),
  installServer: (ref: string) =>
    request<Server>("/api/servers/install", { method: "POST", json: { ref } }),
  uninstallServer: (name: string) =>
    request<void>(`/api/servers/${encodeURIComponent(name)}`, {
      method: "DELETE",
    }),

  listCredentials: () => request<Credential[]>("/api/credentials"),
  putCredential: (server: string, body: CredentialPutBody) =>
    request<void>(`/api/credentials/${encodeURIComponent(server)}`, {
      method: "PUT",
      json: body,
    }),
  deleteCredential: (server: string) =>
    request<void>(`/api/credentials/${encodeURIComponent(server)}`, {
      method: "DELETE",
    }),

  listUsers: () => request<User[]>("/api/users"),
  impersonate: (user_id: number, ttl_minutes: number) =>
    request<void>("/api/admin/impersonate", {
      method: "POST",
      json: { user_id, ttl_minutes },
    }),
  stopImpersonation: () =>
    request<void>("/api/admin/impersonate", { method: "DELETE" }),

  listAudit: (params: { before?: number; limit?: number; user_id?: number }) => {
    const q = new URLSearchParams();
    if (params.before) q.set("before", String(params.before));
    if (params.limit) q.set("limit", String(params.limit));
    if (params.user_id) q.set("user_id", String(params.user_id));
    const qs = q.toString();
    return request<AuditPage>(`/api/audit${qs ? `?${qs}` : ""}`);
  },
};
