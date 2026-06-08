export type Role = "admin" | "user";

export interface User {
  id: number;
  email: string;
  display_name: string;
  role: Role;
}

export interface Me {
  user: User;
  impersonating: boolean;
  real_user?: User;
}

export interface Profile {
  id: number;
  slug: string;
  name: string;
  user_id: number;
  endpoint: string; // "/mcp/p/<slug>"
  servers: string[];
  token?: string; // plaintext, ONLY on create/rotate
}

export interface Server {
  id: number;
  name: string;
}

/** One entry of the signed registry index served by /api/registry/servers. */
export interface CatalogServer {
  name: string;
  description: string; // may be ""
  latest: string;
}

export interface CatalogResponse {
  servers: CatalogServer[];
}

export interface Credential {
  server: string;
  inject_header: string;
  inject_format: string;
  placeholder: string;
  allowed_hosts: string[];
}

export interface CredentialPutBody {
  secret: string;
  inject_header?: string;
  inject_format?: string;
  placeholder?: string;
  allowed_hosts?: string[];
}

export interface AuditEvent {
  id: number;
  ts: string;
  kind: "egress" | "auth" | "admin";
  user_id: number | null;
  profile_id: number | null;
  server: string;
  host: string;
  decision: string;
  detail: string;
}

export interface AuditPage {
  events: AuditEvent[];
  next_before: number; // 0 == no more pages
}

export interface ApiErrorBody {
  error: { code: string; message: string };
}
