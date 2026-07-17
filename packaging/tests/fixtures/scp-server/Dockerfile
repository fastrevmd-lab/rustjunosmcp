FROM debian:12-slim@sha256:1def178129dfb5f24db43afbf2fcac04530012e3264ba4ff81c71184e17a9ee4

RUN apt-get update \
    && apt-get install -y --no-install-recommends openssh-server passwd \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --create-home --uid 10001 --shell /bin/sh fixture \
    && passwd --delete fixture \
    && install -d -m 0755 /run/sshd

COPY sshd_config /etc/ssh/sshd_config
COPY entrypoint.sh /usr/local/bin/scp-fixture-entrypoint
RUN chmod 0755 /usr/local/bin/scp-fixture-entrypoint

EXPOSE 22
HEALTHCHECK --interval=2s --timeout=1s --start-period=2s --retries=15 CMD test -s /run/sshd.pid && kill -0 "$(cat /run/sshd.pid)"
ENTRYPOINT ["/usr/local/bin/scp-fixture-entrypoint"]
