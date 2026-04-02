# Nitro Enclave image for TOPRF node.
#
# Contains only the static binary + CA certs.
# No shell, no SSH, no OS. The binary IS the application.
#
# Build: docker build -t toprf-node-enclave .
# EIF:   nitro-cli build-enclave --docker-uri toprf-node-enclave --output-file toprf-node.eif
#
# PCR0 = hash of entire EIF (deterministic from this Docker image)
# PCR1 = hash of kernel (Nitro-provided)
# PCR2 = hash of application (this binary)
#
# REPRODUCIBILITY: All base images are pinned by digest. Anyone building
# from the same commit with the same Rust toolchain gets identical PCRs.

# Pin Alpine by digest for reproducible CA certificates
# Update this digest when you want newer CA certs (and commit the change)
FROM alpine:3.21@sha256:a8560b36e8b8210634f77d9f7f9efd7ffa463e380b75e2e74aff4511df3ef88c AS certs
RUN apk --no-cache add ca-certificates

FROM scratch

# CA certificates (pinned Alpine version for reproducibility)
COPY --from=certs /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt

# The TOPRF node binary (static musl, no dependencies)
COPY toprf-node /toprf-node

# Run as PID 1
ENTRYPOINT ["/toprf-node"]

# Default arguments — vsock by default (Nitro Enclave), port 3001
CMD ["--join", "--port", "3001"]
