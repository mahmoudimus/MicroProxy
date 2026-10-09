# Maven Central publishing

MicroProxy publishes under the verified `io.github.mahmoudimus` namespace. The
parent POM and all four modules are published together at the release version:
`microproxy-parent`, `zstd-decoder`, `http2-codec`, `microproxy`, and
`microproxy-starlark`. Sources and Javadoc accompany each module. The core test
JAR and the executable Starlark `all` JAR are attached artifacts.

The first release configured for Central is 0.1.1. The existing GitHub-only
v0.1.0 tag does not contain the publishing profile.

## One-time credentials

Generate a [Central Portal user token](https://central.sonatype.org/publish/generate-portal-token/)
for the account that owns the namespace. Its generated username and password
are different from the account's login credentials.

Create a dedicated, passphrase-protected OpenPGP signing key, or use an existing
release signing key. Keep a secure backup of the private key and passphrase.
Follow Sonatype's [GPG instructions](https://central.sonatype.org/publish/requirements/gpg/)
and publish the **public** key to a supported keyserver so Central can verify
signatures. For example, after generating a key with `gpg --full-generate-key`:

```bash
gpg --list-secret-keys --keyid-format LONG
KEY_ID=YOUR_SIGNING_KEY_FINGERPRINT
gpg --keyserver hkps://keyserver.ubuntu.com --send-keys "$KEY_ID"
```

Add these repository Actions secrets in
[GitHub settings](https://github.com/mahmoudimus/MicroProxy/settings/secrets/actions):

| Secret | Value |
| --- | --- |
| `MAVEN_CENTRAL_USERNAME` | Central user token username |
| `MAVEN_CENTRAL_PASSWORD` | Central user token password |
| `MAVEN_GPG_PRIVATE_KEY` | ASCII-armored exported private signing key |
| `MAVEN_GPG_PASSPHRASE` | Signing key passphrase |

The CLI can set them without putting values in shell history. The first three
commands prompt for values; the last streams the exported key directly into
GitHub's encrypted secret storage:

```bash
gh secret set MAVEN_CENTRAL_USERNAME --repo mahmoudimus/MicroProxy
gh secret set MAVEN_CENTRAL_PASSWORD --repo mahmoudimus/MicroProxy
gh secret set MAVEN_GPG_PASSPHRASE --repo mahmoudimus/MicroProxy
gpg --armor --export-secret-keys "$KEY_ID" |
  gh secret set MAVEN_GPG_PRIVATE_KEY --repo mahmoudimus/MicroProxy
```

Do not commit credentials or paste them into issues, pull requests, or chat.
The Maven GPG plugin's Java signer reads the key and passphrase from environment
variables; no import into a persistent GPG keyring is required on the runner.

## Release and retry

Release Please prepares version changes. After its release PR is merged, the
Release workflow builds and uploads the GitHub assets, then calls the Maven
Central workflow with the same tag. Central publication rebuilds and tests the
tagged source on JDK 21, attaches sources and Javadoc, signs all artifacts,
uploads the reactor bundle, and waits for Sonatype to report `PUBLISHED`.

The publishing workflow installs Maven 3.9.16 and verifies its SHA-512 checksum.
Maven 3.10.0 leaves `maven-metadata-local.xml` in the Central plugin's staging
tree, which makes Sonatype reject the bundle. Keep the publishing runtime
pinned until the plugin supports that metadata change. Local signing and
deployment checks should use Maven 3.9.16 too.

Missing secrets fail before building. Tags must be stable `vX.Y.Z` versions and
match the root POM; snapshots are rejected by the workflow. Central releases
are immutable: do not move tags or attempt to replace published artifacts.

To retry a failed publication after correcting credentials or a transient
service failure, dispatch the workflow against the existing release tag:

```bash
gh workflow run central.yml --repo mahmoudimus/MicroProxy -f tag=v0.1.1
```

Check the workflow logs and the
[Central deployment page](https://central.sonatype.com/publishing/deployments)
before retrying if the first run timed out: publication may have finished after
the runner stopped. A green job means Sonatype confirmed publication; mirrors
and search indexing may take additional time.

## Local validation

Ordinary builds do not load the publishing plugins. CI checks the Central
profile's sources and Javadoc without signing or uploading:

```bash
mvn --batch-mode -Pcentral -Dgpg.skip=true -DskipTests verify
```

To check signing without uploading, use a checkout with
`MAVEN_GPG_KEY` and `MAVEN_GPG_PASSPHRASE` supplied securely in the environment:

```bash
mvn --batch-mode -Pcentral -DskipTests verify
```

Signatures are attached under each module's `target` directory. Only `deploy`
uploads artifacts; `verify` does not need a Central token or server entry.
