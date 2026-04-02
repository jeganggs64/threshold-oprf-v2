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

FROM scratch

# CA certificates for HTTPS (Google Play Integrity API verification)
COPY --from=alpine:latest /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt

# The TOPRF node binary (static musl, no dependencies)
COPY toprf-node /toprf-node

# Run as PID 1
ENTRYPOINT ["/toprf-node"]

# Default arguments — overridden at launch via enclave config
CMD ["--join", "--port", "3001"]
