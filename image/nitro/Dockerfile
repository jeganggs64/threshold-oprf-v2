# Nitro Enclave image for TOPRF node.
#
# Single image for ALL nodes — genesis and join mode are configured at runtime
# via POST /configure. This ensures identical PCR values across all nodes.
#
# Build: docker build -t toprf-node-enclave .
# EIF:   nitro-cli build-enclave --docker-uri toprf-node-enclave --output-file toprf-node.eif
#
# PCR0 = hash of entire EIF (identical across all nodes)
# PCR1 = hash of kernel (Nitro-provided)
# PCR2 = hash of application
#
# REPRODUCIBILITY: Base image pinned by digest. Same commit + same Rust
# toolchain = identical image = identical PCRs.

FROM alpine:3.21@sha256:a8560b36e8b8210634f77d9f7f9efd7ffa463e380b75e2e74aff4511df3ef88c

RUN apk --no-cache add ca-certificates && rm -rf /var/cache/apk/*

COPY toprf-node /toprf-node
RUN chmod +x /toprf-node

# Shell wrapper — exec replaces the shell with the binary.
# No mode flags — configuration comes via POST /configure at runtime.
RUN printf '#!/bin/sh\nexec /toprf-node --port 3001\n' > /init.sh && chmod +x /init.sh
ENTRYPOINT ["/init.sh"]
