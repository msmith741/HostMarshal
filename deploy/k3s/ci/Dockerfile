# CI-only image, never published or used as a production image.
FROM ubuntu:24.04
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends ca-certificates && rm -rf /var/lib/apt/lists/*
COPY target/debug/hostmarshal /usr/local/bin/hostmarshal
RUN chmod 0555 /usr/local/bin/hostmarshal
USER 10001:10001
ENTRYPOINT ["/usr/local/bin/hostmarshal"]
