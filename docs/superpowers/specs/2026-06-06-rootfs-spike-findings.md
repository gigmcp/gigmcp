# Spike C: rootfs-under-sandbox findings

**Date:** 2026-06-06  
**Branch:** manifest-registry  
**Scope:** THROWAWAY investigation — no production code changed.  
**Environment:** gigmcp-dev (golang:1.26.4-bookworm + bubblewrap 0.8.0, aarch64), run with
`--security-opt seccomp=unconfined --security-opt apparmor=unconfined
--security-opt systempaths=unconfined --cap-add NET_ADMIN`

---

## 1. Current sandbox anatomy (read from internal/sandbox/sandbox.go)

Both `commandNoNet` and `commandEgress` build a bwrap argv that:

1. Unshares all namespaces (`--unshare-all` or decomposed `--unshare-{user,pid,net,ipc,uts,cgroup}`).
2. Clears the environment and sets `PATH=/usr/bin:/bin` only.
3. Creates a fresh tmpfs at `/etc` (mode 0755, before caller mounts, so CA-cert overlays land on something world-readable even after a uid-drop to 65534).
4. Applies **caller-supplied mounts** (`spec.Mounts`) in order — each is `--ro-bind` or `--ro-bind-try`.
5. Adds fixed isolation mounts: `--proc /proc`, `--dev /dev`, `--tmpfs /tmp`.
6. For egress, appends `--ro-bind <bootstrapPath> <bootstrapPath>` **after** `--tmpfs /tmp` so a bootstrap binary in a TempDir survives the tmpfs overlay.
7. Appends `-- <spec.Exec> [spec.Args...]` (or `-- bootstrap cidr proxy peer -- server [args]` in egress mode).

`spec.Mounts` is currently populated with a **single entry** that maps the extracted static binary to `/app/server`. The v1 packaging decision (oci.go line 7) says "exactly one file is extracted".

Existing helper `ShellMounts()` (sandbox.go:187–194) already shows the per-top-dir pattern: `/bin`, `/usr`, `/lib`, `/lib64`(optional) — used in tests only.

---

## 2. Failure mode: dynamic binary with only the binary mounted

### Setup

- Target: `/usr/bin/perl` (dynamically linked; ldd output: `libm.so.6`, `libc.so.6`, linker `/lib/ld-linux-aarch64.so.1`)
- Replicated current sandbox pattern: `--ro-bind /usr/bin/perl /app/server` plus standard isolation mounts; no lib dirs.

### Step 1 — bare binary, no linker at all

```
bwrap \
  --die-with-parent --new-session --unshare-all \
  --clearenv --setenv PATH /usr/bin:/bin \
  --tmpfs /etc \
  --ro-bind /usr/bin/perl /app/server \
  --proc /proc --dev /dev --tmpfs /tmp --chdir / \
  -- /app/server -e 'print "ok\n"'
```

**Result:** `bwrap: execvp /app/server: No such file or directory` (exit 1)

This is the kernel reporting ENOENT for the ELF interpreter (`/lib/ld-linux-aarch64.so.1`)
listed in the binary's PT_INTERP segment — the file exists at `/app/server` inside the
sandbox, but the kernel cannot find its interpreter. The error message is misleading
(it says the binary is missing rather than its interpreter).

### Step 2 — binary + linker only, no libc

```
bwrap ... \
  --ro-bind /usr/bin/perl /usr/bin/perl \
  --ro-bind /lib/ld-linux-aarch64.so.1 /lib/ld-linux-aarch64.so.1 \
  -- /usr/bin/perl -e 'print "ok\n"'
```

**Result:**
```
/usr/bin/perl: error while loading shared libraries: libm.so.6: cannot open shared object file: No such file or directory
```
Exit 127. This is the expected dynamic-linker error once the linker itself is present.

---

## 3. Fix: full-rootfs bind mounts

Two approaches were verified; both work.

### Approach A — per-top-dir ro-binds (recommended)

```
bwrap \
  --die-with-parent --new-session --unshare-all \
  --clearenv --setenv PATH /usr/bin:/bin \
  --tmpfs /etc \
  --ro-bind /usr /usr \
  --ro-bind /bin /bin \
  --ro-bind /lib /lib \
  --proc /proc --dev /dev --tmpfs /tmp --chdir / \
  -- /usr/bin/perl -e 'print "ok\n"'
```

**Result:** `ok` (exit 0)

Notes:
- `/lib64` is absent in Debian bookworm (all four canonical top-level dirs `/bin`, `/sbin`, `/lib` are symlinks into `/usr`). The `--ro-bind-try` variant (already used for optional mounts in `ShellMounts()`) handles absent dirs cleanly.
- `--ro-bind /bin /bin` where the host's `/bin` is a symlink to `usr/bin`: bwrap resolves the symlink on the source path and mounts the real directory at `/bin` in the sandbox. Result: `/bin/sh` and `/usr/bin/sh` both work inside the sandbox (they resolve to the same content). Verified.

### Approach B — single `--ro-bind / /`

```
bwrap \
  --die-with-parent --new-session --unshare-all \
  --clearenv --setenv PATH /usr/bin:/bin \
  --ro-bind / / \
  --tmpfs /etc \
  --proc /proc --dev /dev --tmpfs /tmp --chdir / \
  -- /usr/bin/perl -e 'print "ok\n"'
```

**Result:** `ok` (exit 0), Python3 also confirmed working with this approach.

**Critical ordering observation** (bwrap last-mount-wins): `--tmpfs /etc` placed AFTER
`--ro-bind / /` wins → `/etc` is an empty tmpfs (0 files visible, CA cert overlay works).
`--tmpfs /etc` placed BEFORE `--ro-bind / /` loses → `/etc` is the host's `/etc` (94 files
visible, host secrets exposed). This makes approach B fragile to mount-order bugs. The
current sandbox code places `--tmpfs /etc` at the top of argv as an explicit invariant; with
approach B the caller would need to guarantee the ordering is `ro-bind / / → tmpfs /etc`, but
a rootfs image might itself contain a `/etc` that the operator wants to selectively expose.

**Isolation downside of approach B:** `/sys`, `/var`, `/root`, and other host directories
become visible inside the sandbox (from the container's perspective these are the container's
own `/sys` etc. — not the host machine's — but they leak the container's filesystem tree
beyond `usr/bin/lib`). With approach A, `/sys`, `/var`, `/root` do not exist inside the
sandbox at all. Approach A is strictly more minimal.

---

## 4. Egress-mode unshare flags: no interaction issues

Both approaches were tested with decomposed unshare flags mirroring `commandEgress`:

```
--unshare-user --unshare-pid --unshare-net
--unshare-ipc --unshare-uts --unshare-cgroup
```

**Result:** `ok` (exit 0) in both cases. No interaction surprises with rootfs bind mounts.

---

## 5. uid 65534 and file permissions

### With `--uid 65534 --gid 65534` (userns)

Tested with both rootfs approaches + per-top-dir mounts:

```
uid=65534 gid=65534
/usr/bin/perl:                readable  (mode=755)
/lib/aarch64-linux-gnu/libc.so.6: readable (mode=755)
/etc/gigmcp-ca.pem:           readable  (mode=644)
/tmp:                         writable  (tmpfs, uid 65534 owns it)
```

Exit 0. A `0755` file owned by root is world-executable; a `0644` file is world-readable.
Standard OCI image layer entries use these modes for interpreter, shared libraries, and
config files, so files extracted by the gateway (running as uid 0 inside the dev container,
or as the gateway service uid on a real host) with default tar permissions are readable by
the sandboxed process at uid 65534.

**Exception to watch for:** files with mode `0600` or `0700` owned by root (e.g.
`/etc/shadow`, some certs, private keys). These would NOT be readable at uid 65534. This is
typically desirable (secrets should not be readable), but image authors must be aware.

### egress actual mode (no `--uid`/`--gid`, gateway writes uid_map externally)

In `commandEgress` the gateway writes its own uid_map via `writeUIDGIDMaps` (spawn.go) and
unblocks via `--userns-block-fd`. The map covers 0..65534 and bootstrap starts as uid 0 then
calls `setuid(65534)` before exec'ing the server. The read-permission analysis above applies
identically because the file ownership inside the user namespace is still root (uid 0) and
the process sees uid 65534 as "other" — the read/exec permission bits (r-x for 0755, r-- for
0644) are what matters.

---

## 6. How this composes with the gateway flow

### Current flow (v1, static binary)

1. `oci.Puller.Extract(ctx, ref, digest, entrypoint, dest)` → writes one file to
   `<cacheDir>/<digest>/server` with mode 0555.
2. `sandbox.Spec{Exec: "/app/server", Mounts: []Mount{{Src: dest, Dst: "/app/server"}}}` →
   single `--ro-bind <dest> /app/server`.

### Proposed flow (v2, full rootfs)

1. New `oci.Puller.ExtractRootfs(ctx, ref, digest, destDir)` → walks `mutate.Extract(img)`
   tar stream and materialises every entry under `destDir` (regular files, directories,
   symlinks, hardlinks). Whiteouts are already handled by `mutate.Extract`. Sets permissions
   from tar header.
2. `sandbox.Spec` gains a new field:
   ```go
   // RootfsDir is a host-side directory containing a pre-extracted OCI rootfs.
   // When non-empty, each top-level entry of RootfsDir is ro-bound into the
   // sandbox at the same name under /, before the fixed isolation mounts.
   // The existing Exec/Mounts fields are still applied on top (allowing /app/server
   // and CA-cert overlays to override rootfs contents).
   RootfsDir string
   ```
3. argv emission sketch (inside `commandNoNet`/`commandEgress`, immediately after
   `--tmpfs /etc` and before the caller `spec.Mounts` loop):
   ```go
   if spec.RootfsDir != "" {
       entries, _ := os.ReadDir(spec.RootfsDir)
       for _, e := range entries {
           src := filepath.Join(spec.RootfsDir, e.Name())
           dst := "/" + e.Name()
           // Skip dirs that are managed by fixed mounts: proc, dev, tmp, etc
           switch e.Name() {
           case "proc", "dev", "tmp", "sys":
               continue
           }
           args = append(args, "--ro-bind-try", src, dst)
       }
   }
   ```
   `--ro-bind-try` tolerates a missing source (e.g. `/sbin` is a symlink in the image
   but has already resolved into `/usr` during extraction, leaving no `/sbin` dir in
   `destDir`). The existing `spec.Mounts` loop runs after, so the CA cert and
   `/app/server` mounts override rootfs content at those paths. Fixed isolation mounts
   (`--proc /proc`, `--dev /dev`, `--tmpfs /tmp`) run last and always win (existing behaviour
   preserved).

4. `spec.Exec` for a Node.js server would be e.g. `/usr/local/bin/node`, and
   `spec.Args` would include the script path (also bind-mounted via `spec.Mounts`).

---

## 7. Interaction notes

| Topic | Finding |
|---|---|
| **seccomp** | Unconfined in dev container; production seccomp profile must allow `mmap`, `execve`, `openat`, `read` for interpreter chain. No new syscalls beyond what a static binary already needs — dynamic linking is user-space only once the interpreter is exec'd. |
| **`--tmpfs /etc` ordering** | Must remain BEFORE rootfs dir binds; the per-top-dir loop skips `etc` only if the caller explicitly does so. Safest: emit `--tmpfs /etc` first (as now), then rootfs binds, then `spec.Mounts` (CA cert overlays). The existing code already does this for the no-rootfs path. |
| **`--proc /proc`** | Already placed in fixed mounts (after caller mounts, last-wins). The sandbox sees only its own PID namespace (PIDs 1–N where N is the process count in its tree). Verified: Python inside sandbox lists `[1, 2]` only. No change needed. |
| **`/tmp` writability** | `--tmpfs /tmp` is already a fixed mount (last-wins). Verified writable at uid 65534. |
| **bootstrap binary path** | `commandEgress` appends `--ro-bind <bootstrapPath> <bootstrapPath>` AFTER `--tmpfs /tmp`. If `bootstrapPath` is under `/tmp`, this correctly overlays it. With rootfs mounts added, the bootstrap append must still come after `--tmpfs /tmp` — the proposed sketch preserves this (rootfs binds are emitted before `--tmpfs /tmp` in the fixed-mounts block, and bootstrap append is last). |
| **uid 65534 read perms** | Standard OCI file modes (`0755` exec, `0644` data) are readable by uid 65534 ("other" bits). Files extracted by gateway (running as root or service uid) retain their tar-header permissions. No chown needed. Root-owned `0600` files are not readable at uid 65534 — expected/desired. |
| **symlinks in rootfs** | `mutate.Extract` preserves symlink tar entries (`TypeSymlink`). If extracted to `destDir`, symlinks like `destDir/bin -> usr/bin` are real symlinks on the filesystem. `--ro-bind-try destDir/bin /bin` resolves the symlink source and mounts the real dir at `/bin` in the sandbox. Verified: `--ro-bind <symlink-src> /bin` works correctly (bwrap follows the symlink). |
| **whiteouts** | `mutate.Extract` (go-containerregistry) applies layer whiteouts before the tar stream is produced. `ExtractRootfs` does not need to handle `.wh.` entries itself. |
| **OCI layout re-verification** | Current `oci.go` note (line 43): layout layer blobs are not hash-re-verified on local read. This applies equally to a full rootfs extraction; trust model is unchanged. |

---

## 8. Open questions for the sandbox owner

1. **Directory skip list**: Which rootfs top-level dirs should `RootfsDir` emission
   always skip? Proposed: `proc`, `dev`, `tmp`, `sys`. Should `etc` be skipped entirely
   (relying on `--tmpfs /etc` + explicit CA-cert mount) or should some `/etc` content
   from the image (e.g. `/etc/ld.so.conf.d`) be preserved? The linker reads
   `/etc/ld.so.conf` — images that rely on a non-standard library search path stored
   in `/etc/ld.so.conf.d/` will break if `/etc` is a blank tmpfs.
   
2. **Landlock**: The hardening plan defers Landlock. When added, the Landlock ruleset
   will need to cover all per-dir bind-mount paths (currently just `/app/server`). The
   `RootfsDir` loop should emit corresponding Landlock read rules.

3. **`/etc/ld.so.conf` vs `--setenv LD_LIBRARY_PATH`**: One way to sidestep the
   `/etc/ld.so.conf` question is to emit `--setenv LD_LIBRARY_PATH /lib:/usr/lib:...` for
   well-known rootfs layouts, making the linker not need `/etc/ld.so.conf` at all. This is
   fragile for unusual distros (Alpine musl vs glibc, etc.) and should be discussed.

4. **Storage location for extracted rootfs**: A full rootfs can be hundreds of MB.
   The current store caches single-file extracts by digest. A rootfs cache needs a
   directory-per-digest model. Eviction policy (LRU vs TTL vs manual GC) is an open
   design question.

5. **`ExtractRootfs` atomicity**: Writing a directory tree is not atomic. A partial
   extraction (gateway crash mid-walk) could leave a corrupt rootfs. A
   write-to-temp-then-rename pattern (or a "complete" sentinel file) is needed.

6. **Image platform pinning**: `oci.Extract` today requires a platform image-manifest
   digest (not a multi-arch index digest). This remains true for rootfs extraction.
   The manifest registry must store per-platform digests, or the gateway must resolve
   the index to the correct platform manifest before calling `ExtractRootfs`.

---

## 9. Recommendation for the follow-up plan

The per-top-dir approach (Approach A) is clearly preferable to `--ro-bind / /`: it
exposes only `usr`, `bin`, `lib` (and any other dirs the image actually has) and does
not leak `/sys`, `/var`, `/root`, or other host-filesystem artifacts into the sandbox.
It also composes cleanly with the existing `--tmpfs /etc` + CA-cert overlay pattern.

Recommended plan for the follow-up implementation task:

1. **Add `oci.Puller.ExtractRootfs`**: walks `mutate.Extract` tar stream, materialises
   full directory tree under a dest dir with atomicity sentinel. Hardlinks and symlinks
   preserved. Mode/ownership from tar header (no chown needed for uid 65534 compat).

2. **Add `sandbox.Spec.RootfsDir string`**: when non-empty, emit `--ro-bind-try <dir>/<entry> /<entry>` for each top-level entry of `RootfsDir`, skipping `proc`, `dev`, `tmp`, `sys`, and `etc` (the last being handled by the existing `--tmpfs /etc` + explicit CA mount). Place these before `spec.Mounts` in argv so caller-mounts still win.

3. **Decide `/etc` policy (open question 1)**: If images rely on `/etc/ld.so.conf`,
   either add `/etc/ld.so.conf.d` as an explicit optional mount from the rootfs, or
   accept that v2 images must ship with `LD_LIBRARY_PATH` set in the image config and
   the gateway emits it via `--setenv`.

4. **Update store**: directory-per-digest cache for rootfs extractions, with sentinel.

5. **Update manifest registry schema**: add `runtime: {type: rootfs, entrypoint: [...]}` or
   similar field so the installer/resolver knows to call `ExtractRootfs` and set
   `spec.RootfsDir` + `spec.Exec` from the image config's `Entrypoint`/`Cmd`.

bwrap handles it cleanly. No new kernel capabilities, no changes to seccomp requirements,
no changes to the userns/netns/pid-namespace setup. The extension is entirely in how
`spec.Mounts` (or the new `RootfsDir`) is populated before `Command(spec)` is called.
