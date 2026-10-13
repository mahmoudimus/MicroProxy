#!/usr/bin/env bash
# Downloads or builds the external proxies of the load-testing comparison into .tools/ next to this
# script (git-ignored), at the versions pinned in versions.env:
#
#   envoy     the official Envoy release binary, checked against its published SHA-256
#   goproxy   goproxy/main.go built with a pinned Go toolchain (checked SHA-256; modules via go.sum)
#   g3proxy   g3proxy built from its release tag (commit checked) with cargo --locked
#   squid     the distribution's Squid package (apt-get; root only)
#
#   loadtest/competitors/setup.sh                  # all four
#   loadtest/competitors/setup.sh envoy goproxy    # some
#
# Nothing here is needed by the Maven build or by CI; see docs/project/performance.md.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TOOLS="$HERE/.tools"
# shellcheck source=versions.env
. "$HERE/versions.env"
mkdir -p "$TOOLS/bin" "$TOOLS/dl"

log() { printf '[setup] %s\n' "$*" >&2; }

# fetch URL FILE SHA256: downloads URL to FILE unless FILE already has that checksum.
fetch() {
    local url=$1 out=$2 sha=$3
    if [ -f "$out" ] && echo "$sha  $out" | sha256sum -c --status; then return 0; fi
    log "downloading $url"
    curl -fsSL --retry 3 -o "$out.part" "$url"
    if ! echo "$sha  $out.part" | sha256sum -c --status; then
        log "checksum mismatch for $url (expected $sha)"
        rm -f "$out.part"
        exit 1
    fi
    mv "$out.part" "$out"
}

setup_envoy() {
    local f="$TOOLS/dl/envoy-$ENVOY_VERSION-linux-x86_64"
    fetch "https://github.com/envoyproxy/envoy/releases/download/v$ENVOY_VERSION/envoy-$ENVOY_VERSION-linux-x86_64" \
        "$f" "$ENVOY_SHA256"
    install -m 0755 "$f" "$TOOLS/bin/envoy"
    "$TOOLS/bin/envoy" --version
}

setup_go() {
    local f="$TOOLS/dl/go$GO_VERSION.linux-amd64.tar.gz"
    fetch "https://go.dev/dl/go$GO_VERSION.linux-amd64.tar.gz" "$f" "$GO_SHA256"
    if [ ! -x "$TOOLS/go$GO_VERSION/bin/go" ]; then
        rm -rf "$TOOLS/go$GO_VERSION" && mkdir -p "$TOOLS/go$GO_VERSION"
        tar -C "$TOOLS/go$GO_VERSION" --strip-components=1 -xzf "$f"
    fi
}

setup_goproxy() {
    setup_go
    log "building goproxy/"
    (
        cd "$HERE/goproxy"
        export GOTOOLCHAIN=local GOPATH="$TOOLS/gopath" GOCACHE="$TOOLS/gocache" GOFLAGS="-mod=readonly -modcacherw"
        "$TOOLS/go$GO_VERSION/bin/go" build -trimpath -o "$TOOLS/bin/goproxy-proxy" .
    )
    "$TOOLS/bin/goproxy-proxy" -version
}

# The cargo to build with: one of RUST_VERSION on the PATH, or a toolchain installed under .tools.
cargo_bin() {
    if command -v cargo >/dev/null && [ "$(cargo --version | awk '{print $2}')" = "$RUST_VERSION" ]; then
        command -v cargo
        return
    fi
    export RUSTUP_HOME="$TOOLS/rustup" CARGO_HOME="$TOOLS/cargo"
    if [ ! -x "$CARGO_HOME/bin/cargo" ]; then
        local init="$TOOLS/dl/rustup-init"
        log "installing Rust $RUST_VERSION with rustup-init"
        curl -fsSL --retry 3 -o "$init" https://static.rust-lang.org/rustup/dist/x86_64-unknown-linux-gnu/rustup-init
        local sha
        sha=$(curl -fsSL https://static.rust-lang.org/rustup/dist/x86_64-unknown-linux-gnu/rustup-init.sha256 | awk '{print $1}')
        echo "$sha  $init" | sha256sum -c --status || { log "rustup-init checksum mismatch"; exit 1; }
        chmod +x "$init"
        "$init" -y --no-modify-path --profile minimal --default-toolchain "$RUST_VERSION" >&2
    fi
    echo "$CARGO_HOME/bin/cargo"
}

setup_g3proxy() {
    command -v capnp >/dev/null || {
        log "g3proxy needs the Cap'n Proto compiler (apt-get install capnproto) and OpenSSL headers (libssl-dev)"
        exit 1
    }
    local src="$TOOLS/src/g3"
    if [ ! -d "$src/.git" ]; then
        mkdir -p "$TOOLS/src"
        git clone --quiet --depth 1 --branch "g3proxy-v$G3PROXY_VERSION" https://github.com/bytedance/g3 "$src"
    fi
    local head
    head=$(git -C "$src" rev-parse HEAD)
    [ "$head" = "$G3_COMMIT" ] || { log "g3 checkout is $head, expected $G3_COMMIT"; exit 1; }
    local cargo
    cargo=$(cargo_bin)
    log "building g3proxy $G3PROXY_VERSION with $("$cargo" --version) (several minutes)"
    (cd "$src" && "$cargo" build --locked --release -p g3proxy --no-default-features --features rustls-ring)
    install -m 0755 "$src/target/release/g3proxy" "$TOOLS/bin/g3proxy"
    "$TOOLS/bin/g3proxy" --version
}

setup_squid() {
    if [ -x /usr/sbin/squid ] && /usr/sbin/squid -v | grep -q "Version ${SQUID_APT_VERSION%%-*}"; then
        /usr/sbin/squid -v | head -1
        return
    fi
    [ "$(id -u)" = 0 ] || { log "installing Squid needs root (apt-get install squid=$SQUID_APT_VERSION)"; exit 1; }
    # Install without starting the service: the harness starts its own Squid per run.
    printf '#!/bin/sh\nexit 101\n' > /usr/sbin/policy-rc.d && chmod +x /usr/sbin/policy-rc.d
    trap 'rm -f /usr/sbin/policy-rc.d' RETURN
    # The pinned package exists only on the distribution it was published for (Ubuntu 24.04); elsewhere
    # install the distribution's Squid and say so (the harness records every proxy's version per run).
    if apt-cache madison squid 2>/dev/null | grep -q "| $SQUID_APT_VERSION |"; then
        DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends "squid=$SQUID_APT_VERSION" >&2
    else
        log "squid $SQUID_APT_VERSION is not available here; installing this distribution's squid instead"
        DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends squid >&2
    fi
    /usr/sbin/squid -v | head -1
}

targets=("$@")
[ ${#targets[@]} -gt 0 ] || targets=(envoy goproxy g3proxy squid)
for t in "${targets[@]}"; do
    case "$t" in
        envoy | goproxy | g3proxy | squid) "setup_$t" ;;
        *) log "unknown target $t (envoy, goproxy, g3proxy or squid)"; exit 2 ;;
    esac
done
log "done: $(ls "$TOOLS/bin" | tr '\n' ' ')"
