FROM alpine:3.21

RUN apk add --no-cache openssl tcpdump tshark python3

# Override default openssl.cnf to re-enable TLS 1.0/1.1 and legacy providers
COPY configs/openssl-legacy.cnf /etc/ssl/openssl.cnf

WORKDIR /work

COPY configs/ configs/
COPY scripts/ scripts/

RUN chmod +x scripts/*.sh && mkdir -p certs pcaps

CMD ["sh", "-c", "./scripts/gen-certs.sh && ./scripts/run-tests.sh"]
