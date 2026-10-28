# syntax=docker/dockerfile:1
FROM maven:3.9-eclipse-temurin-21@sha256:99e61abcff91a9b1333463bd8451fb18495d6eba9250ac66a338b518f8278320 AS build
WORKDIR /src
COPY pom.xml ./
COPY zstd-decoder/pom.xml zstd-decoder/pom.xml
COPY http2-codec/pom.xml http2-codec/pom.xml
COPY http3-codec/pom.xml http3-codec/pom.xml
COPY quic/pom.xml quic/pom.xml
COPY microproxy/pom.xml microproxy/pom.xml
COPY microproxy-otel/pom.xml microproxy-otel/pom.xml
COPY microproxy-starlark/pom.xml microproxy-starlark/pom.xml
COPY quic-interop/pom.xml quic-interop/pom.xml
COPY http3-codec/src/main http3-codec/src/main
COPY quic/src/main quic/src/main
COPY quic-interop/src/main quic-interop/src/main
RUN --mount=type=cache,target=/root/.m2 mvn --batch-mode -Pinterop -pl quic-interop -am -Dmaven.test.skip=true package

FROM eclipse-temurin:21-jre-jammy@sha256:9603446cf51296842eab342514857cf7ab55a8891cd564e6c68ec237fae65a16 AS jre
FROM martenseemann/quic-network-simulator-endpoint@sha256:3b2b9e6fa317da238c8140a7b6d2bf8d4d45a8464b873eecac3ff2a32520b71a
RUN apt-get update && apt-get install --yes --no-install-recommends libstdc++6 zlib1g ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY --from=jre /opt/java/openjdk /opt/java/openjdk
ENV JAVA_HOME=/opt/java/openjdk
ENV PATH=/opt/java/openjdk/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
WORKDIR /opt/microproxy
COPY --from=build /src/quic-interop/target/quic-interop.jar ./quic-interop.jar
COPY --chmod=755 quic-interop/run_endpoint.sh /run_endpoint.sh
ARG SOURCE_REVISION=working-tree
LABEL org.opencontainers.image.source="https://github.com/mahmoudimus/MicroProxy" \
      org.opencontainers.image.revision="${SOURCE_REVISION}" \
      org.opencontainers.image.description="MicroProxy QUIC Interop Runner endpoint"
ENV MICROPROXY_SOURCE_REVISION=${SOURCE_REVISION}
ENTRYPOINT ["/run_endpoint.sh"]
