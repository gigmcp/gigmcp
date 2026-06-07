"use client";
import {
  useQuery,
  useMutation,
  useQueryClient,
} from "@tanstack/react-query";
import { api } from "@/lib/api";
import type { CredentialPutBody } from "@/lib/types";

export const keys = {
  me: ["me"] as const,
  profiles: ["profiles"] as const,
  profile: (id: number) => ["profile", id] as const,
  servers: ["servers"] as const,
  credentials: ["credentials"] as const,
  users: ["users"] as const,
  audit: ["audit"] as const,
};

export const useMe = () =>
  useQuery({ queryKey: keys.me, queryFn: api.me, retry: false });

export const useProfiles = () =>
  useQuery({ queryKey: keys.profiles, queryFn: api.listProfiles });
export const useProfile = (id: number) =>
  useQuery({ queryKey: keys.profile(id), queryFn: () => api.getProfile(id) });

export const useServers = () =>
  useQuery({ queryKey: keys.servers, queryFn: api.listServers });
export const useCredentials = () =>
  useQuery({ queryKey: keys.credentials, queryFn: api.listCredentials });
export const useUsers = () =>
  useQuery({ queryKey: keys.users, queryFn: api.listUsers });

export function useInvalidate() {
  const qc = useQueryClient();
  return (key: readonly unknown[]) =>
    qc.invalidateQueries({ queryKey: key });
}

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
