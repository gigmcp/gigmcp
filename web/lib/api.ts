import type {
  Me,
  User,
  Profile,
  Server,
  CatalogResponse,
  CatalogServer,
  Credential,
  CredentialPutBody,
  AuditPage,
  ApiErrorBody,
  OverviewStats,
  AppSummary,
  AppDetail,
  ConnectedAccount,
  AuthConfig,
  AuthConfigPutBody,
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

/** Encodes a single path segment so interpolated values (ids, names, slugs)
 *  can never escape the "/api/..." prefix or inject extra segments/queries. */
function seg(value: string | number): string {
  return encodeURIComponent(String(value));
}

/** Builds a "?k=v" query string from the truthy params, "" if none.
 *  URLSearchParams percent-encodes values, so they cannot smuggle params. */
function query(params: Record<string, number | undefined>): string {
  const q = new URLSearchParams();
  for (const [key, value] of Object.entries(params)) {
    if (value) q.set(key, String(value));
  }
  const qs = q.toString();
  return qs ? `?${qs}` : "";
}

function toApiError(res: Response, data: unknown): ApiError {
  const body = data as ApiErrorBody | undefined;
  return new ApiError(
    res.status,
    body?.error?.code ?? "unknown",
    body?.error?.message ?? res.statusText,
  );
}

async function parseResponse<T>(res: Response): Promise<T> {
  if (res.status === 204) return undefined as T;
  const text = await res.text();
  const data = text ? JSON.parse(text) : undefined;
  if (!res.ok) throw toApiError(res, data);
  return data as T;
}

// Same-origin invariant: every path passed here is a relative "/api/..."
// string built from literals; dynamic path segments go through seg()
// (encodeURIComponent) and query values through URLSearchParams, so no
// runtime value can change the origin, traverse out of /api, or smuggle
// extra query parameters.
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
  return parseResponse<T>(res);
}

export const api = {
  me: () => request<Me>("/api/me"),
  logout: () => request<void>("/api/auth/logout", { method: "POST" }),

  overview: () => request<OverviewStats>("/api/overview"),
  apps: async (): Promise<AppSummary[]> => {
    const res = await request<{ apps: AppSummary[] }>("/api/apps");
    return res.apps;
  },
  app: (name: string) => request<AppDetail>(`/api/apps/${seg(name)}`),
  setAppTool: (name: string, tool: string, enabled: boolean) =>
    request<void>(`/api/apps/${seg(name)}/tools/${seg(tool)}`, {
      method: "PUT",
      json: { enabled },
    }),


  listProfiles: () => request<Profile[]>("/api/profiles"),
  getProfile: (id: number) => request<Profile>(`/api/profiles/${seg(id)}`),
  createProfile: (body: { name: string; slug: string }) =>
    request<Profile>("/api/profiles", { method: "POST", json: body }),
  renameProfile: (id: number, name: string) =>
    request<Profile>(`/api/profiles/${seg(id)}`, {
      method: "PATCH",
      json: { name },
    }),
  deleteProfile: (id: number) =>
    request<void>(`/api/profiles/${seg(id)}`, { method: "DELETE" }),
  setProfileServers: (id: number, servers: string[]) =>
    request<Profile>(`/api/profiles/${seg(id)}/servers`, {
      method: "PUT",
      json: { servers },
    }),
  rotateProfileToken: (id: number) =>
    request<Profile>(`/api/profiles/${seg(id)}/token`, { method: "POST" }),

  listServers: () => request<Server[]>("/api/servers"),
  installServer: (ref: string) =>
    request<Server>("/api/servers/install", { method: "POST", json: { ref } }),
  uninstallServer: (name: string) =>
    request<void>(`/api/servers/${seg(name)}`, { method: "DELETE" }),

  // Registry catalog (signed index, cached gateway-side for ~5 minutes).
  // 501 registry_disabled when no registry is configured; 502
  // registry_unavailable when the index cannot be fetched or verified.
  catalog: async (): Promise<CatalogServer[]> => {
    const res = await request<CatalogResponse>("/api/registry/servers");
    return res.servers;
  },

  listCredentials: () => request<Credential[]>("/api/credentials"),
  putCredential: (server: string, body: CredentialPutBody) =>
    request<void>(`/api/credentials/${seg(server)}`, {
      method: "PUT",
      json: body,
    }),
  deleteCredential: (server: string) =>
    request<void>(`/api/credentials/${seg(server)}`, { method: "DELETE" }),

  listUsers: () => request<User[]>("/api/users"),
  impersonate: (user_id: number, ttl_minutes: number) =>
    request<void>("/api/admin/impersonate", {
      method: "POST",
      json: { user_id, ttl_minutes },
    }),
  stopImpersonation: () =>
    request<void>("/api/admin/impersonate", { method: "DELETE" }),

  listAudit: (params: { before?: number; limit?: number; user_id?: number }) =>
    request<AuditPage>(`/api/audit${query(params)}`),

  // Connected Accounts (OAuth). The start endpoint is a 302 the BROWSER must
  // follow as a top-level navigation (cross-origin redirect to the vendor),
  // so the UI uses window.location with oauthStartUrl rather than fetch().
  listConnections: () => request<ConnectedAccount[]>("/api/connections"),
  disconnect: (vendor: string) =>
    request<void>(`/api/connections/${seg(vendor)}`, { method: "DELETE" }),

  listAuthConfigs: () => request<AuthConfig[]>("/api/auth-configs"),
  putAuthConfig: (vendor: string, body: AuthConfigPutBody) =>
    request<void>(`/api/auth-configs/${seg(vendor)}`, { method: "PUT", json: body }),
  deleteAuthConfig: (vendor: string) =>
    request<void>(`/api/auth-configs/${seg(vendor)}`, { method: "DELETE" }),
};

/** Builds the top-level navigation URL that starts the OAuth connect flow.
 *  The browser must hit this as a full navigation (not fetch) so it can follow
 *  the cross-origin 302 to the vendor's consent page. */
export function oauthStartUrl(vendor: string, server?: string): string {
  const q = new URLSearchParams({ vendor });
  if (server) q.set("server", server);
  return `/api/connections/oauth/start?${q.toString()}`;
}
