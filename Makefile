DEV_IMAGE := gigemcp-dev

.PHONY: dev-image test test-local

dev-image:
	docker build -f Dockerfile.dev -t $(DEV_IMAGE) .

# Full suite, including sandbox tests — runs on Linux inside Docker.
# seccomp/apparmor are relaxed because bwrap needs unprivileged user
# namespaces, which Docker's default profiles block (see DESIGN.md §3).
# systempaths=unconfined unmasks /proc so bwrap can mount a fresh procfs in the sandbox's pid namespace.
test: dev-image
	docker run --rm \
		--security-opt seccomp=unconfined \
		--security-opt apparmor=unconfined \
		--security-opt systempaths=unconfined \
		-v $(PWD):/src -w /src \
		-v gigemcp-gomod:/go/pkg/mod \
		-v gigemcp-gocache:/root/.cache/go-build \
		$(DEV_IMAGE) go test ./...

# Host-side subset — sandbox tests self-skip on macOS.
test-local:
	go test ./...
