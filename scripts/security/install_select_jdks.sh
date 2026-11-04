#!/usr/bin/env bash
set -euo pipefail

select_tools_dir="${RUNNER_TEMP:?}/microproxy-select-tools"
mkdir -p "$select_tools_dir"
curl --fail --location --retry 3 --output "$select_tools_dir/jdk21.tar.gz" \
  'https://github.com/adoptium/temurin21-binaries/releases/download/jdk-21.0.13%2B9/OpenJDK21U-jdk_x64_linux_hotspot_21.0.13_9.tar.gz'
printf '%s  %s\n' 'd7f5d5cf865a2902b70ff549b97586a7d3f234e016f041ab447ea740c7d66d1c' "$select_tools_dir/jdk21.tar.gz" | sha256sum --check --strict -
mkdir "$select_tools_dir/jdk21"
tar --extract --gzip --file "$select_tools_dir/jdk21.tar.gz" --directory "$select_tools_dir/jdk21" --strip-components=1
printf 'SELECT_JDK21=%s\n' "$select_tools_dir/jdk21" >> "${GITHUB_ENV:?}"

curl --fail --location --retry 3 --output "$select_tools_dir/jdk25.tar.gz" \
  'https://github.com/adoptium/temurin25-binaries/releases/download/jdk-25.0.5%2B8/OpenJDK25U-jdk_x64_linux_hotspot_25.0.5_8.tar.gz'
printf '%s  %s\n' '68982529869257d0ee6b824ec5aa270ff8b118bb438670da0b97ebdab178d7fb' "$select_tools_dir/jdk25.tar.gz" | sha256sum --check --strict -
mkdir "$select_tools_dir/jdk25"
tar --extract --gzip --file "$select_tools_dir/jdk25.tar.gz" --directory "$select_tools_dir/jdk25" --strip-components=1
printf 'SELECT_JDK25=%s\n' "$select_tools_dir/jdk25" >> "${GITHUB_ENV:?}"
