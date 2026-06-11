"use client";
import {
  useQuery,
  useMutation,
  useQueryClient,
} from "@tanstack/react-query";
import { api } from "@/lib/api";
import type { CredentialPutBody, AuthConfigPutBody } from "@/lib/types";

export const keys = {
  me: ["me"] as const,
  overview: ["overview"] as const,
  profiles: ["profiles"] as const,
  profile: (id: number) => ["profile", id] as const,
  servers: ["servers"] as const,
  apps: ["apps"] as const,
  app: (name: string) => ["app", name] as const,
  catalog: ["catalog"] as const,
  credentials: ["credentials"] as const,
  users: ["users"] as const,
  audit: ["audit"] as const,
  connections: ["connections"] as const,
  authConfigs: ["authConfigs"] as const,
};

export const useMe = () =>
  useQuery({ queryKey: keys.me, queryFn: api.me, retry: false });

/** Returns true while the session is an impersonation — mutations are 403'd
 *  server-side; this hook lets UI components disable controls proactively. */
export const useReadOnly = () => {
  const me = useMe();
  return me.data?.impersonating ?? false;
};

export const useProfiles = () =>
  useQuery({ queryKey: keys.profiles, queryFn: api.listProfiles });
export const useProfile = (id: number) =>
  useQuery({ queryKey: keys.profile(id), queryFn: () => api.getProfile(id) });

export const useServers = () =>
  useQuery({ queryKey: keys.servers, queryFn: api.listServers });

export const useOverview = () =>
  useQuery({ queryKey: keys.overview, queryFn: api.overview });
export const useApps = () =>
  useQuery({ queryKey: keys.apps, queryFn: api.apps });
export const useApp = (name: string) =>
  useQuery({ queryKey: keys.app(name), queryFn: () => api.app(name) });

/** Registry catalog. The gateway caches the verified index for ~5 minutes;
 *  staleTime mirrors that so reopening the picker doesn't refetch. The
 *  caller gates `enabled` so we only fetch while the picker is open. */
export const useCatalog = (enabled = true) =>
  useQuery({
    queryKey: keys.catalog,
    queryFn: api.catalog,
    enabled,
    staleTime: 5 * 60 * 1000,
    // The catalog dialog renders 501 registry_disabled / 502
    // registry_unavailable as in-dialog states; skip the global error toast.
    meta: { suppressErrorToast: true },
  });
export const useCredentials = () =>
  useQuery({ queryKey: keys.credentials, queryFn: api.listCredentials });
export const useUsers = (enabled = true) =>
  useQuery({ queryKey: keys.users, queryFn: api.listUsers, enabled });

export const useCreateProfile = () => {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: api.createProfile,
    onSuccess: () => qc.invalidateQueries({ queryKey: keys.profiles }),
  });
};
export const useDeleteProfile = () => {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: api.deleteProfile,
    onSuccess: () => qc.invalidateQueries({ queryKey: keys.profiles }),
  });
};
export const useRenameProfile = () => {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ id, name }: { id: number; name: string }) =>
      api.renameProfile(id, name),
    onSuccess: (_d, v) => {
      qc.invalidateQueries({ queryKey: keys.profile(v.id) });
      qc.invalidateQueries({ queryKey: keys.profiles });
    },
  });
};
export const useSetProfileServers = () => {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ id, servers }: { id: number; servers: string[] }) =>
      api.setProfileServers(id, servers),
    onSuccess: (_d, v) => qc.invalidateQueries({ queryKey: keys.profile(v.id) }),
  });
};
export const useRotateToken = () => {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (id: number) => api.rotateProfileToken(id),
    onSuccess: (_d, id) => qc.invalidateQueries({ queryKey: keys.profile(id) }),
  });
};

export const useSetAppTool = (name: string) => {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ tool, enabled }: { tool: string; enabled: boolean }) =>
      api.setAppTool(name, tool, enabled),
    onSuccess: () => qc.invalidateQueries({ queryKey: keys.app(name) }),
  });
};

export const useInstallServer = () => {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (ref: string) => api.installServer(ref),
    onSuccess: () => qc.invalidateQueries({ queryKey: keys.servers }),
  });
};
export const useUninstallServer = () => {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (name: string) => api.uninstallServer(name),
    onSuccess: () => qc.invalidateQueries({ queryKey: keys.servers }),
  });
};

export const usePutCredential = () => {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ server, body }: { server: string; body: CredentialPutBody }) =>
      api.putCredential(server, body),
    onSuccess: () => qc.invalidateQueries({ queryKey: keys.credentials }),
  });
};
export const useDeleteCredential = () => {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (server: string) => api.deleteCredential(server),
    onSuccess: () => qc.invalidateQueries({ queryKey: keys.credentials }),
  });
};

export const useImpersonate = () => {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ userId, ttl }: { userId: number; ttl: number }) =>
      api.impersonate(userId, ttl),
    onSuccess: () => qc.invalidateQueries(),
  });
};
export const useStopImpersonation = () => {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: api.stopImpersonation,
    onSuccess: () => qc.invalidateQueries(),
  });
};

export const useConnections = () =>
  useQuery({ queryKey: keys.connections, queryFn: api.listConnections });

export const useDisconnect = () => {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (vendor: string) => api.disconnect(vendor),
    onSuccess: () => qc.invalidateQueries({ queryKey: keys.connections }),
  });
};

export const useAuthConfigs = (enabled = true) =>
  useQuery({ queryKey: keys.authConfigs, queryFn: api.listAuthConfigs, enabled });

export const usePutAuthConfig = () => {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ vendor, body }: { vendor: string; body: AuthConfigPutBody }) =>
      api.putAuthConfig(vendor, body),
    onSuccess: () => qc.invalidateQueries({ queryKey: keys.authConfigs }),
  });
};

export const useDeleteAuthConfig = () => {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (vendor: string) => api.deleteAuthConfig(vendor),
    onSuccess: () => qc.invalidateQueries({ queryKey: keys.authConfigs }),
  });
};
