# Nitro Enclave image for TOPRF node.
#
# Alpine-based because Nitro's init requires a minimal userspace to bootstrap.
# The binary cannot run as PID 1 directly — it needs a shell wrapper that
# exec's into it (sets up the process environment properly).
#
# Build: docker build -t toprf-node-enclave .
# EIF:   nitro-cli build-enclave --docker-uri toprf-node-enclave --output-file toprf-node.eif
#
# PCR0 = hash of entire EIF (deterministic from this Docker image)
# PCR1 = hash of kernel (Nitro-provided)
# PCR2 = hash of application (this binary + image layers)
#
# REPRODUCIBILITY: Base image pinned by digest. Same commit + same Rust
# toolchain = identical image = identical PCRs.

# Pin Alpine by digest for reproducible CA certificates
FROM alpine:3.21@sha256:a8560b36e8b8210634f77d9f7f9efd7ffa463e380b75e2e74aff4511df3ef88c

RUN apk --no-cache add ca-certificates && rm -rf /var/cache/apk/*

# The TOPRF node binary (static musl, no dependencies)
COPY toprf-node /toprf-node
RUN chmod +x /toprf-node

# Shell wrapper — exec replaces the shell with the binary.
# Default: join mode on port 3001.
# For genesis mode, override init.sh during deployment (see README).
RUN printf '#!/bin/sh\nexec /toprf-node --join --port 3001\n' > /init.sh && chmod +x /init.sh
ENTRYPOINT ["/init.sh"]
