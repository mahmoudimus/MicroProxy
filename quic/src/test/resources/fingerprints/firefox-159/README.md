# Firefox 159.0 (macOS) captures

Taken 2026-10-28 with `scripts/fingerprints/CaptureBrowser.java` from Firefox 159.0 (Homebrew
cask), headless, on a fresh profile that trusts the capture CA, loading `https://localhost:8443/`.

- `clienthello-0.bin`: a new connection's ClientHello (handshake message, type and length first).
- `clienthello-resumed.bin`: the next connection's, resuming the first one's session (PSK).
- `h2-preface-0.bin`, `h2-preface-0.txt`: the HTTP/2 frames after the connection preface, up to
  the first request's HEADERS.
- `h2-page.txt`: every request of a page that loads a stylesheet, scripts, an image and a fetch
  (`CaptureBrowser ... page`): the HEADERS priority weight of each kind of request.
