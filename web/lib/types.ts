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

export type AppAuthType = "oauth2" | "api_key" | "basic" | "custom_env" | "none";

export interface HeatmapDay {
  date: string; // YYYY-MM-DD
  count: number;
}

export interface OverviewStats {
  tool_calls: number;
  apps: number;
  connected: number;
  profiles: number;
  most_used_app: string;
  heatmap: HeatmapDay[];
}

export interface AppSummary {
  name: string;
  display_name: string;
  category: string; // "" until registry branding lands
  auth_type: AppAuthType;
  connected: boolean;
  version: string;
}

export interface AppTool {
  name: string;
  default: boolean;
  enabled: boolean;
}

export interface AppDetail {
  name: string;
  display_name: string;
  category: string;
  description: string;
  auth_type: AppAuthType;
  provider: string;
  vendor: string; // canonical OAuth grouping key; == provider for un-backfilled manifests
  scopes: string[];
  connected: boolean;
  version: string;
  allowed_hosts: string[];
  tools: AppTool[];
  inject_header: string;
  inject_format: string;
  placeholder: string;
}

export interface ConnectedAccount {
  vendor: string;
  granted_scopes: string[];
  expires_at: number; // unix seconds
}

export interface AuthConfig {
  vendor: string;
  authorize_url: string;
  token_url: string;
  client_id: string;
  default_scopes: string[];
  pkce: boolean;
  mode: "managed" | "byo";
  has_secret: boolean;
}

export interface AuthConfigPutBody {
  authorize_url: string;
  token_url: string;
  client_id: string;
  client_secret?: string; // omitted = keep existing
  default_scopes?: string[];
  pkce?: boolean;
  mode: "managed" | "byo";
}
