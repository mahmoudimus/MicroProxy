/*
 * The animated diagrams of the architecture page (docs/architecture.md): how MicroProxy's design
 * differs from LittleProxy's, step by step, with play, pause and step controls. Each diagram is a
 * <div class="mp-arch" data-scene="..."> on the page; the page's prose says the same things without
 * them, and static SVGs stand in when scripts do not run.
 *
 * Every step names the real classes and methods: MicroProxy's from
 * microproxy/src/main/java/org/microproxy/impl/ (and its README.md), LittleProxy's from
 * io.github.littleproxy:littleproxy:2.9.1 (org.littleshoot.proxy.impl). Figures come from the
 * page itself (the commits that introduced the buffer pool and the body fast path) or, for slow
 * readers, from the measured data of the performance page (docs/assets/perf/results.json).
 *
 * Shares the performance page's tokens (perf.css: palette, light and dark), honours
 * prefers-reduced-motion (no autoplay, no transitions, the last step shown), and every control is
 * a button.
 */
(function () {
  "use strict";

  var SVGNS = "http://www.w3.org/2000/svg";
  var STEP_MS = 6500;

  function reducedMotion() {
    return window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches;
  }

  function el(tag, attrs, parent, text) {
    var e = document.createElement(tag);
    if (attrs) Object.keys(attrs).forEach(function (k) { if (attrs[k] != null) e.setAttribute(k, attrs[k]); });
    if (text != null) e.textContent = text;
    if (parent) parent.appendChild(e);
    return e;
  }

  function sv(tag, attrs, parent, text) {
    var e = document.createElementNS(SVGNS, tag);
    if (attrs) Object.keys(attrs).forEach(function (k) { if (attrs[k] != null) e.setAttribute(k, attrs[k]); });
    if (text != null) e.textContent = text;
    if (parent) parent.appendChild(e);
    return e;
  }

  // Caption text with `code` spans, built from text nodes only.
  function rich(parent, text) {
    String(text).split("`").forEach(function (part, i) {
      if (!part) return;
      if (i % 2) el("code", null, parent, part);
      else parent.appendChild(document.createTextNode(part));
    });
  }

  // --- the panel builder: named elements whose state the steps set ---

  function Panel(svg) {
    this.svg = svg;
    this.items = {};
    this.initial = {};
  }

  // A box with a (possibly multi-line) label.
  Panel.prototype.box = function (key, x, y, w, h, label, cls) {
    var g = sv("g", { class: "mp-a-box " + (cls || "") }, this.svg);
    sv("rect", { x: x, y: y, width: w, height: h, rx: 6 }, g);
    var lines = String(label).split("\n");
    var t = sv("text", { x: x + w / 2, y: y + h / 2 - ((lines.length - 1) * 12) / 2 + 4, "text-anchor": "middle" }, g);
    lines.forEach(function (line, i) {
      sv("tspan", { x: x + w / 2, dy: i ? 12 : 0 }, t, line);
    });
    this.reg(key, g, { cls: [], text: null });
    return g;
  };

  // A text whose content the steps may change.
  Panel.prototype.text = function (key, x, y, str, cls, anchor) {
    var t = sv("text", { x: x, y: y, class: cls || "mp-a-note", "text-anchor": anchor || "start" }, this.svg, str);
    if (key) this.reg(key, t, { text: str, cls: [] });
    return t;
  };

  // A token (a request, a buffer, a thread) that moves: a circle or a small block with a label.
  Panel.prototype.token = function (key, x, y, label, cls, shape) {
    var g = sv("g", { class: "mp-a-token " + (cls || "") }, this.svg);
    if (shape === "block") {
      sv("rect", { x: -11, y: -7, width: 22, height: 14, rx: 3 }, g);
    } else {
      sv("circle", { r: 9 }, g);
    }
    if (label) sv("text", { y: 3.5, "text-anchor": "middle" }, g, label);
    this.reg(key, g, { x: x, y: y, cls: [], hidden: false });
    return g;
  };

  // A level gauge: a track and a fill whose fraction the steps set.
  Panel.prototype.gauge = function (key, x, y, w, h, cls) {
    var g = sv("g", { class: "mp-a-gauge " + (cls || "") }, this.svg);
    sv("rect", { class: "mp-a-track", x: x, y: y, width: w, height: h, rx: 3 }, g);
    var f = sv("rect", { class: "mp-a-fill", x: x, y: y, width: w, height: h, rx: 3 }, g);
    this.reg(key, g, { level: 0, cls: [] });
    this.items[key].fill = f;
    return g;
  };

  Panel.prototype.line = function (x1, y1, x2, y2, cls, key) {
    var l = sv("line", { x1: x1, y1: y1, x2: x2, y2: y2, class: cls || "mp-a-link" }, this.svg);
    if (key) this.reg(key, l, { cls: [], hidden: false });
    return l;
  };

  Panel.prototype.arrow = function (x1, y1, x2, y2, cls, key) {
    var l = this.line(x1, y1, x2, y2, (cls || "mp-a-link") + " mp-a-arrow", key);
    l.setAttribute("marker-end", "url(#" + this.markerId + ")");
    return l;
  };

  Panel.prototype.reg = function (key, node, state) {
    this.items[key] = { node: node };
    // State classes given at build time (such as a thread that starts parked) are its initial state.
    var given = (node.getAttribute("class") || "").split(/\s+/);
    ["on", "warn", "park", "gone", "hot"].forEach(function (c) {
      if (given.indexOf("mp-a-" + c) >= 0 && state.cls && state.cls.indexOf(c) < 0) state.cls.push(c);
    });
    this.initial[key] = state;
  };

  // --- a scene: panels, steps, captions and controls ---

  function Scene(root, def) {
    var self = this;
    this.root = root;
    this.def = def;
    this.step = 0;
    this.timer = null;
    root.classList.add("mp-perf-root");
    root.textContent = "";
    el("h4", { class: "mp-title" }, root, def.title);
    var controls = el("div", { class: "mp-row mp-a-controls", role: "group", "aria-label": "Animation controls: " + def.title }, root);
    this.prev = el("button", { type: "button", class: "mp-btn", "aria-label": "Previous step" }, controls, "◀ Back");
    this.playBtn = el("button", { type: "button", class: "mp-btn", "aria-label": "Play" }, controls, "▶ Play");
    this.next = el("button", { type: "button", class: "mp-btn", "aria-label": "Next step" }, controls, "Next ▶");
    this.counter = el("span", { class: "mp-a-count", "aria-live": "off" }, controls);
    this.panelsEl = el("div", { class: "mp-a-panels" + (def.panels.length > 1 ? " mp-a-two" : "") }, root);
    this.panels = def.panels.map(function (p, i) {
      var wrap = el("figure", { class: "mp-a-panel" }, self.panelsEl);
      var svg = sv("svg", { viewBox: "0 0 " + p.w + " " + p.h, role: "img", "aria-label": p.title, class: (p.cls || "mp-a-plain") + "-panel" }, wrap);
      var panel = new Panel(svg);
      var defs = sv("defs", null, svg);
      panel.markerId = "mp-a-m-" + Math.random().toString(36).slice(2);
      var m = sv("marker", { id: panel.markerId, viewBox: "0 0 10 10", refX: 9, refY: 5, markerWidth: 7, markerHeight: 7, orient: "auto-start-reverse" }, defs);
      sv("path", { d: "M0 0L10 5L0 10Z", class: "mp-a-arrowhead" }, m);
      sv("text", { x: 8, y: 16, class: "mp-a-title " + (p.cls || "") }, svg, p.title);
      p.build(panel);
      var cap = el("figcaption", { class: "mp-a-caption", "aria-live": "polite" }, wrap);
      return { def: p, panel: panel, caption: cap, index: i };
    });
    this.prev.addEventListener("click", function () { self.pause(); self.go(self.step - 1); });
    this.next.addEventListener("click", function () { self.pause(); self.go(self.step + 1); });
    this.playBtn.addEventListener("click", function () {
      if (self.timer) self.pause();
      else self.play(true);
    });
    var start = reducedMotion() ? def.steps.length - 1 : 0;
    this.go(start, true);
    if (!reducedMotion() && "IntersectionObserver" in window) {
      this.io = new IntersectionObserver(function (entries) {
        if (!root.isConnected) {
          self.io.disconnect();
          return;
        }
        var visible = entries.some(function (e) { return e.isIntersecting; });
        if (visible && !self.autoplayed) {
          self.autoplayed = true;
          self.play(false);
        } else if (!visible && self.timer) {
          self.pause();
        }
      }, { threshold: 0.4 });
      this.io.observe(root);
    }
  }

  Scene.prototype.play = function (fromUser) {
    var self = this;
    if (reducedMotion()) return;
    if (fromUser && this.step >= this.def.steps.length - 1) this.go(0);
    this.playBtn.textContent = "❚❚ Pause";
    this.playBtn.setAttribute("aria-label", "Pause");
    clearInterval(this.timer);
    this.timer = setInterval(function () {
      if (!self.root.isConnected) {
        self.pause();
        return;
      }
      if (self.step >= self.def.steps.length - 1) {
        self.pause();
        return;
      }
      self.go(self.step + 1);
    }, STEP_MS);
  };

  Scene.prototype.pause = function () {
    clearInterval(this.timer);
    this.timer = null;
    this.playBtn.textContent = "▶ Play";
    this.playBtn.setAttribute("aria-label", "Play");
  };

  // Shows step i: the state is the initial one with steps 0..i applied, so stepping back works.
  Scene.prototype.go = function (i, first) {
    var steps = this.def.steps;
    i = Math.max(0, Math.min(steps.length - 1, i));
    this.step = i;
    this.counter.textContent = "Step " + (i + 1) + " of " + steps.length;
    this.prev.disabled = i === 0;
    this.next.disabled = i === steps.length - 1;
    var self = this;
    this.panels.forEach(function (pw) {
      var state = JSON.parse(JSON.stringify(pw.panel.initial));
      var api = stateApi(state);
      for (var s = 0; s <= i; s++) {
        var fn = steps[s].panels[pw.index];
        if (fn && fn.apply) fn.apply(api, self.def.data || {});
      }
      commit(pw.panel, state, first);
      pw.caption.textContent = "";
      var c = steps[i].panels[pw.index];
      var text = c ? (typeof c.caption === "function" ? c.caption(self.def.data || {}) : c.caption) : "";
      rich(pw.caption, text);
    });
  };

  function stateApi(state) {
    function get(k) {
      if (!state[k]) throw new Error("no element " + k);
      return state[k];
    }
    return {
      at: function (k, x, y) { var s = get(k); s.x = x; s.y = y; },
      on: function (k) { var s = get(k); if (s.cls.indexOf("on") < 0) s.cls.push("on"); },
      off: function (k) { var s = get(k); s.cls = s.cls.filter(function (c) { return c !== "on"; }); },
      cls: function (k, c, set) {
        var s = get(k);
        s.cls = s.cls.filter(function (x) { return x !== c; });
        if (set !== false) s.cls.push(c);
      },
      text: function (k, t) { get(k).text = t; },
      level: function (k, v) { get(k).level = Math.max(0, Math.min(1, v)); },
      show: function (k, v) { get(k).hidden = v === false; },
      hide: function (k) { get(k).hidden = true; }
    };
  }

  function commit(panel, state, first) {
    Object.keys(state).forEach(function (k) {
      var s = state[k];
      var item = panel.items[k];
      var n = item.node;
      if (first) n.classList.add("mp-a-instant");
      if (s.x != null) n.style.transform = "translate(" + s.x + "px," + s.y + "px)";
      if (s.text != null && n.tagName.toLowerCase() === "text") n.textContent = s.text;
      if (s.level != null && item.fill) item.fill.style.transform = "scaleX(" + s.level + ")";
      ["on", "warn", "park", "gone", "hot"].forEach(function (c) { n.classList.toggle("mp-a-" + c, s.cls.indexOf(c) >= 0); });
      if (s.hidden != null) n.classList.toggle("mp-a-hidden", !!s.hidden);
      if (first) {
        // Let the first state land without transitions.
        n.getBoundingClientRect();
        requestAnimationFrame(function () { n.classList.remove("mp-a-instant"); });
      }
    });
  }

  // --- the scenes ---

  var LP = "mp-a-lp";
  var MP = "mp-a-mp";
  var SCENES = {};

  // 1. Concurrency: event loops and callbacks against a virtual thread per connection.
  SCENES.concurrency = function () {
    var stages = ["read request", "filters", "connect (or reuse)", "write request", "stream body", "read response", "stream back"];
    var sy = function (i) { return 64 + i * 30; };
    var vx = [168, 232, 296];
    return {
      title: "Concurrency: event-loop callbacks against a thread per connection",
      panels: [
        {
          title: "LittleProxy 2.9.1 (Netty)",
          cls: LP,
          w: 360,
          h: 330,
          build: function (p) {
            p.box("loopC", 8, 28, 344, 26, "client-side event loop (clientToProxyWorkerPool)", "mp-a-lane");
            p.text("loopCnow", 180, 70, "idle: waiting in the selector", "mp-a-note", "middle");
            p.text(null, 14, 92, "conns", "mp-a-small", "middle");
            [["c1", 112], ["c2", 152], ["c3", 192]].forEach(function (c, i) {
              p.token(c[0], 14, c[1], String(i + 1), LP + " mp-a-conn");
            });
            p.box("h1", 32, 86, 320, 22, "HttpRequestDecoder");
            p.box("h2", 32, 116, 320, 22, "ClientToProxyConnection.read() · AWAITING_INITIAL");
            p.box("h3", 32, 146, 320, 22, "ProxyToServerConnection.write() → connectAndWrite()");
            p.box("h4", 32, 176, 320, 22, "ConnectionFlow: ConnectChannel → … (callbacks)");
            p.box("h5", 32, 206, 320, 22, "HttpRequestEncoder → server");
            p.box("h6", 32, 236, 320, 22, "readHTTPInitial() → clientConnection.respond()");
            p.box("loopS", 8, 272, 344, 26, "server-side event loop (proxyToServerWorkerPool)", "mp-a-lane");
            p.text("loopSnow", 180, 316, "idle", "mp-a-note", "middle");
            p.token("req", 14, 112, "1", LP + " mp-a-req", "block");
          }
        },
        {
          title: "MicroProxy (virtual threads)",
          cls: MP,
          w: 360,
          h: 330,
          build: function (p) {
            stages.forEach(function (s, i) {
              p.text(null, 8, sy(i) + 4, s, "mp-a-small");
              p.line(140, sy(i), 320, sy(i), "mp-a-grid");
            });
            ["conn 1", "conn 2", "conn 3"].forEach(function (c, i) {
              p.text(null, vx[i], 44, "VT " + c.slice(-1), "mp-a-small", "middle");
              p.line(vx[i], 52, vx[i], sy(6) + 8, "mp-a-thread");
            });
            p.token("v1", vx[0], sy(0), "1", MP + " mp-a-park");
            p.token("v2", vx[1], sy(0), "2", MP + " mp-a-park");
            p.token("v3", vx[2], sy(0), "3", MP + " mp-a-park");
            p.box("k1", 8, 270, 168, 26, "carrier thread 1", "mp-a-lane");
            p.box("k2", 184, 270, 168, 26, "carrier thread 2", "mp-a-lane");
            p.text("k1now", 92, 316, "idle", "mp-a-note", "middle");
            p.text("k2now", 268, 316, "idle", "mp-a-note", "middle");
          }
        }
      ],
      steps: [
        {
          panels: [
            {
              apply: function (s) { s.hide("req"); },
              caption: "Three client connections are open. Each is registered with one of the client-side event loop threads, and each thread multiplexes many connections; here the three share one (LittleProxy's defaults: 2 acceptor, 8 client-side and 8 server-side worker threads, in `NioEventLoopGroup`s).",
            },
            {
              caption: "Each connection has a virtual thread of its own, parked in `Http1ClientChannel.awaitRequest()` waiting for a byte, holding no buffer. The carrier threads (the JDK's scheduler) are free.",
              apply: function () {}
            }
          ]
        },
        {
          panels: [
            {
              caption: "Bytes arrive on conn 1. The event loop runs `HttpRequestDecoder`, then `ClientToProxyConnection.read()`: the connection's `ConnectionState` is `AWAITING_INITIAL`, so `readHTTPInitial()` runs the filters.",
              apply: function (s) {
                s.show("req"); s.on("loopC"); s.on("h1"); s.on("h2"); s.on("c1");
                s.text("loopCnow", "running conn 1's callbacks");
                s.at("req", 48, 127);
              }
            },
            {
              caption: "Bytes arrive on conn 1: its virtual thread unparks, is mounted on a carrier and runs straight down `ClientConnection.serveRequests()` into `handleRequest()`: it reads the request, then runs the filters.",
              apply: function (s) {
                s.cls("v1", "park", false); s.on("v1"); s.at("v1", vx[0], sy(1)); s.on("k1");
                s.text("k1now", "running VT 1");
              }
            }
          ]
        },
        {
          panels: [
            {
              caption: "There is no server connection yet: `ProxyToServerConnection.write()` sees `DISCONNECTED` and calls `connectAndWrite()`, which starts a `ConnectionFlow` with its `ConnectChannel` step. The callback returns; the loop moves on to conn 2's bytes, which waited until now.",
              apply: function (s) {
                s.off("h1"); s.off("h2"); s.on("h3"); s.on("h4"); s.off("c1"); s.on("c2");
                s.at("req", 48, 187);
                s.text("loopCnow", "conn 1 waits for the flow; now running conn 2");
              }
            },
            {
              caption: "VT 1 connects to the server, which blocks: the virtual thread parks and leaves its carrier. Meanwhile conn 2's request has arrived, so the carrier runs VT 2; the code of both is plain sequential Java.",
              apply: function (s) {
                s.at("v1", vx[0], sy(2)); s.cls("v1", "park"); s.off("v1");
                s.cls("v2", "park", false); s.on("v2"); s.at("v2", vx[1], sy(1));
                s.text("k1now", "VT 1 parked in connect; running VT 2");
              }
            }
          ]
        },
        {
          panels: [
            {
              caption: "The connect completes on the server-side loop. A listener on its `ChannelFuture` advances the `ConnectionFlow`, and when the flow succeeds the request is written through `HttpRequestEncoder`. The server connection is now `AWAITING_INITIAL`, waiting for the response.",
              apply: function (s) {
                s.off("h3"); s.off("h4"); s.on("h5"); s.on("loopS");
                s.at("req", 48, 217);
                s.text("loopSnow", "running the flow's next step for conn 1");
              }
            },
            {
              caption: "Connected: VT 1 unparks on whichever carrier is free, writes the request head, streams the request body, then reads the response, which blocks again until the server answers: VT 1 parks.",
              apply: function (s) {
                s.cls("v1", "park", false); s.on("v1"); s.at("v1", vx[0], sy(5)); s.on("k2");
                s.text("k2now", "running VT 1, until it parks again");
                s.cls("v1", "park"); s.off("v1");
              }
            }
          ]
        },
        {
          panels: [
            {
              caption: "The response arrives on the server-side loop: `HttpResponseDecoder`, then `ProxyToServerConnection.readHTTPInitial()` calls `clientConnection.respond()`, whose write Netty hands to the client channel's own loop as a task; each later `HttpContent` goes the same way through `readHTTPChunk()`.",
              apply: function (s) {
                s.off("h5"); s.on("h6"); s.on("c1"); s.off("c2");
                s.at("req", 48, 247);
                s.text("loopSnow", "running conn 1's response callbacks");
                s.text("loopCnow", "writing conn 1's response (a queued task)");
              }
            },
            {
              caption: "The response arrives: VT 1 unparks, reads the response head and streams the body back with `writeData()` (a write that blocks while the client is slow is the backpressure). Then it loops back to `awaitRequest()` and parks, holding no buffer.",
              apply: function (s) {
                s.cls("v1", "park", false); s.on("v1"); s.at("v1", vx[0], sy(6));
                s.text("k2now", "running VT 1");
              }
            }
          ]
        },
        {
          panels: [
            {
              caption: "The same work, as a state machine driven by callbacks (`ConnectionState`, `ConnectionFlow`, handler swaps in the pipeline), with backpressure managed by hand. Envoy is event-driven too: one event loop per worker thread, each owning its connections.",
              apply: function (s) {
                s.off("h6"); s.off("c1"); s.off("loopS");
                s.at("req", 14, 112); s.hide("req");
                s.text("loopCnow", "back in the selector"); s.text("loopSnow", "idle");
              }
            },
            {
              caption: "The same work, as one straight-line loop per connection; a blocking call parks only its own virtual thread, and a few carrier threads run them all. Go's `net/http` (and so goproxy) also runs a goroutine per connection.",
              apply: function (s) {
                s.at("v1", vx[0], sy(0)); s.cls("v1", "park"); s.off("v1"); s.off("k1"); s.off("k2");
                s.at("v2", vx[1], sy(1)); s.cls("v2", "park", false);
                s.text("k1now", "running VT 2"); s.text("k2now", "idle"); s.on("k1"); s.on("v2");
              }
            }
          ]
        }
      ]
    };
  };

  // 2. Backpressure with a slow reader.
  SCENES.backpressure = function (data) {
    function perReader(id) {
      var m = data && data.memory && data.memory.slowread && data.memory.slowread[id];
      return m && m.rssKbPerConnection ? m.rssKbPerConnection : null;
    }
    function kb(st) {
      return st ? Math.round(st.med).toLocaleString("en-US") + " KB" : null;
    }
    var lpKb = kb(perReader("littleproxy"));
    var mpKb = kb(perReader("microproxy"));
    var readers = data && data.settings ? data.settings["slowread-connections"] : null;
    return {
      title: "Backpressure: a client that reads slowly",
      data: data,
      panels: [
        {
          title: "LittleProxy: writability callbacks",
          cls: LP,
          w: 360,
          h: 230,
          build: function (p) {
            p.box("origin", 6, 40, 60, 60, "origin");
            p.box("client", 300, 40, 54, 60, "slow\nclient");
            p.box("srv", 82, 34, 90, 44, "server channel\nautoRead");
            p.text("auto", 127, 92, "on", "mp-a-note", "middle");
            p.box("out", 184, 34, 104, 44, "client channel\noutbound buffer");
            p.text(null, 96, 112, "queued for the client (direct memory)", "mp-a-small");
            p.gauge("q", 96, 118, 192, 12, LP);
            p.line(96 + 192 * 0.25, 112, 96 + 192 * 0.25, 136, "mp-a-mark");
            p.line(96 + 192 * 0.5, 112, 96 + 192 * 0.5, 136, "mp-a-mark");
            p.text(null, 96 + 192 * 0.25 + 2, 148, "low 32 KiB", "mp-a-small", "end");
            p.text(null, 96 + 192 * 0.5 + 4, 148, "high 64 KiB", "mp-a-small", "start");
            p.text("qtext", 192, 166, "queued: almost nothing", "mp-a-note", "middle");
            p.arrow(66, 56, 82, 56);
            p.arrow(172, 56, 184, 56);
            p.arrow(288, 56, 300, 56, null, "toClient");
            p.text("writable", 180, 186, "isWritable(): true", "mp-a-note", "middle");
            p.text("callback", 180, 206, "", "mp-a-code", "middle");
          }
        },
        {
          title: "MicroProxy: a write that blocks",
          cls: MP,
          w: 360,
          h: 230,
          build: function (p) {
            p.box("origin", 6, 40, 60, 60, "origin");
            p.box("client", 300, 40, 54, 60, "slow\nclient");
            p.box("vt", 96, 34, 180, 44, "VT: relayResponseBody()\nbody.read → writeData");
            p.text("vtstate", 186, 92, "running", "mp-a-note", "middle");
            p.text(null, 96, 112, "kernel receive buffer (from origin)", "mp-a-small");
            p.gauge("rcv", 96, 118, 180, 12, MP);
            p.text("window", 186, 148, "TCP window: open", "mp-a-note", "middle");
            p.arrow(66, 56, 96, 56, null, "fromOrigin");
            p.arrow(276, 56, 300, 56);
            p.text(null, 186, 186, "one 64 KiB buffer from relayBuffers", "mp-a-note", "middle");
            p.text("heap", 186, 206, "", "mp-a-code", "middle");
          }
        }
      ],
      steps: [
        {
          panels: [
            {
              caption: "The client reads as fast as the origin sends. Each read from the server channel becomes `HttpContent` messages that `ClientToProxyConnection.respond()` writes to the client channel; the outbound buffer stays nearly empty.",
              apply: function (s) { s.level("q", 0.06); }
            },
            {
              caption: "The client reads as fast as the origin sends. The connection's virtual thread loops in `relayResponseBody()`: `body.read(buf)` into one 64 KiB buffer from the server's `relayBuffers` pool, then `client.writeData(buf)`.",
              apply: function (s) { s.level("rcv", 0.06); }
            }
          ]
        },
        {
          panels: [
            {
              caption: "The client slows down. The server channel still reads (`autoRead` is on), and every read is queued in the client channel's outbound buffer, in pooled direct memory, until it passes Netty's 64 KiB high water mark.",
              apply: function (s) {
                s.level("q", 0.62); s.cls("q", "warn"); s.text("qtext", "queued: past the high water mark");
              }
            },
            {
              caption: "The client slows down. Once its socket's send buffer is full, `writeData()` blocks and the virtual thread parks inside the write. While it is parked it calls `body.read()` no more.",
              apply: function (s) {
                s.cls("vt", "park"); s.text("vtstate", "parked in writeData()");
              }
            }
          ]
        },
        {
          panels: [
            {
              caption: "`isWritable()` turns false, Netty calls `channelWritabilityChanged()`, and `ProxyConnection` calls `becameSaturated()`: `ClientToProxyConnection` stops reading every server connection (`stopReading()`, `setAutoRead(false)`). What was read before that stays queued.",
              apply: function (s) {
                s.level("q", 0.9); s.text("auto", "off"); s.cls("srv", "warn");
                s.text("writable", "isWritable(): false");
                s.text("callback", "becameSaturated() → stopReading()");
              }
            },
            {
              caption: "The origin's bytes wait in the kernel's receive buffer. When it is full the TCP window closes and the origin stops sending: TCP flow control is the backpressure, and the proxy's heap holds one 64 KiB buffer for this response.",
              apply: function (s) {
                s.level("rcv", 1); s.cls("rcv", "warn"); s.text("window", "TCP window: closed"); s.cls("fromOrigin", "gone");
              }
            }
          ]
        },
        {
          panels: [
            {
              caption: "The client drains the queue below the 32 KiB low water mark: `becameWritable()` calls `resumeReading()` on the server connections, and the next burst is read and queued.",
              apply: function (s) {
                s.level("q", 0.2); s.cls("q", "warn", false); s.text("auto", "on"); s.cls("srv", "warn", false);
                s.text("writable", "isWritable(): true"); s.text("callback", "becameWritable() → resumeReading()");
                s.text("qtext", "drained below the low water mark");
              }
            },
            {
              caption: "The client takes some bytes: the write returns, the virtual thread unparks, reads the next piece (at most 64 KiB) and writes it, which blocks again. The kernel buffer drains and the window reopens as it does.",
              apply: function (s) {
                s.cls("vt", "park", false); s.text("vtstate", "running, then parked again");
                s.level("rcv", 0.7); s.cls("rcv", "warn", false); s.text("window", "TCP window: reopening"); s.cls("fromOrigin", "gone", false);
              }
            }
          ]
        },
        {
          panels: [
            {
              caption: function () {
                return "Both proxies stop reading the origin. LittleProxy does it by hand, and what it read before stopping stays queued in direct memory" +
                  (lpKb ? ": measured with " + readers + " slow readers, its RSS rose by about " + lpKb + " per reader (median of the runs on the performance page)." : ".");
              },
              apply: function (s) {
                s.text("callback", "per slow reader: what was read before stopReading()");
                s.level("q", 0.9); s.cls("q", "warn"); s.text("qtext", "queued when reading stopped");
                s.text("auto", "off"); s.cls("srv", "warn"); s.text("writable", "isWritable(): false");
              }
            },
            {
              caption: function () {
                return "MicroProxy needs no callback: a blocked write is the backpressure, and the bytes in flight sit in kernel socket buffers" +
                  (mpKb ? ". Measured the same way, its RSS rose by about " + mpKb + " per reader." : ".");
              },
              apply: function (s) { s.text("heap", "per slow reader: one parked thread, one relay buffer"); }
            }
          ]
        }
      ]
    };
  };

  // 3. Idle connections and the buffer pool.
  SCENES.buffers = function () {
    var rows = [110, 150, 190, 230];
    function ownBuffers(p, y, prefix) {
      [0, 1, 2, 3].forEach(function (i) { p.box(prefix + i, 96 + i * 46, y - 11, 40, 22, "16K", "mp-a-buf"); });
      p.box(prefix + "r", 284, y - 11, 64, 22, "64K", "mp-a-buf mp-a-relay");
    }
    return {
      title: "Idle connections and the buffer pool",
      panels: [
        {
          title: "Before: buffers owned for life",
          w: 360,
          h: 290,
          build: function (p) {
            p.text(null, 8, 64, "each connection pair, from accept to close:", "mp-a-note");
            rows.forEach(function (y, i) {
              p.token("c" + i, 22, y, String(i + 1), "mp-a-neutral");
              p.text(null, 38, y + 4, "idle", "mp-a-small");
              ownBuffers(p, y, "b" + i + "_");
            });
            p.text(null, 8, 264, "four 16 KiB stream buffers and a 64 KiB relay buffer", "mp-a-note");
            p.text("total", 8, 282, "per client/server pair, even while idle", "mp-a-note");
          }
        },
        {
          title: "Now: lent by BufferPool while bytes move",
          cls: MP,
          w: 360,
          h: 290,
          build: function (p) {
            p.box("io", 8, 30, 196, 52, "", "mp-a-lane");
            p.text(null, 106, 43, "ioBuffers", "mp-a-small", "middle");
            p.text(null, 106, 55, "16 KiB each, ≤512 kept", "mp-a-small", "middle");
            p.box("relay", 212, 30, 140, 52, "", "mp-a-lane");
            p.text(null, 282, 43, "relayBuffers", "mp-a-small", "middle");
            p.text(null, 282, 55, "64 KiB each, ≤64 kept", "mp-a-small", "middle");
            rows.forEach(function (y, i) {
              p.token("c" + i, 22, y, String(i + 1), MP + " mp-a-park");
              p.text("s" + i, 38, y + 4, "awaitNext()", "mp-a-small");
            });
            p.token("r1", 70, 70, "16K", "mp-a-buf", "block");
            p.token("w1", 100, 70, "16K", "mp-a-buf", "block");
            p.token("x1", 130, 70, "16K", "mp-a-buf", "block");
            p.token("rb", 260, 70, "64K", "mp-a-buf mp-a-relay", "block");
            p.text("note", 8, 282, "", "mp-a-note");
          }
        }
      ],
      steps: [
        {
          panels: [
            {
              caption: "Before this design, each client connection and its server connection kept their buffers for their whole lives: four 16 KiB stream buffers plus a 64 KiB relay buffer, about 141 KiB even while idle.",
              apply: function () {}
            },
            {
              caption: "Now an idle connection holds no buffer: between requests its virtual thread waits in `ByteReader.awaitNext()`, a one-byte read with nothing borrowed. The buffers sit in the server's `BufferPool`s.",
              apply: function () {}
            }
          ]
        },
        {
          panels: [
            { caption: "A request arrives on conn 2; the same buffers serve it.", apply: function (s) { s.text("total", "per client/server pair, busy or idle"); } },
            {
              caption: "A request arrives on conn 2: its `ByteReader` takes a 16 KiB buffer from `ioBuffers` (`pool.take()`), and the `PooledOutputStream` to the server takes another while it writes.",
              apply: function (s) {
                s.at("r1", 180, 150); s.at("w1", 210, 150);
                s.cls("c1", "park", false); s.on("c1"); s.text("s1", "reading the request");
              }
            }
          ]
        },
        {
          panels: [
            { caption: "The response body is relayed through the connection's own 64 KiB relay buffer.", apply: function () {} },
            {
              caption: "The response body is relayed through a 64 KiB buffer from `relayBuffers`, borrowed for this body only. The write buffer went back on its flush.",
              apply: function (s) {
                s.at("rb", 270, 150); s.at("w1", 100, 70);
                s.text("s1", "relaying the body");
              }
            }
          ]
        },
        {
          panels: [
            { caption: "The exchange ends; every buffer stays with its connection while it idles.", apply: function () {} },
            {
              caption: "The exchange ends: the relay buffer is given back, and `ByteReader.release()` returns the read buffer once it is drained. Beyond each pool's limit, returned buffers are left to the garbage collector, so a burst never grows the pool for good.",
              apply: function (s) {
                s.at("rb", 260, 70); s.at("r1", 70, 70);
                s.cls("c1", "park"); s.off("c1"); s.text("s1", "awaitNext()");
              }
            }
          ]
        },
        {
          panels: [
            { caption: "Measured with 2,000 idle keep-alive connections: about 141 KiB of heap per client/server pair, and 113 KiB per idle CONNECT tunnel.", apply: function () {} },
            {
              caption: "Measured the same way: about 11 KiB per idle client/server pair (from 141 KiB) and 15 KiB per idle CONNECT tunnel (from 113 KiB); tunnels keep a buffer only while data keeps arriving. Throughput did not change.",
              apply: function (s) { s.text("note", "≈11 KiB per idle pair, 15 KiB per idle tunnel"); }
            }
          ]
        }
      ]
    };
  };

  // 4. The body fast path.
  SCENES.fastpath = function () {
    return {
      title: "Bodies no filter reads: one reused buffer instead of a message per piece",
      panels: [
        {
          title: "A filter reads the body: a message per piece",
          w: 360,
          h: 220,
          build: function (p) {
            p.box("srv", 6, 40, 56, 50, "server");
            p.box("cli", 298, 40, 56, 50, "client");
            p.box("rd", 74, 40, 70, 50, "MessageBody\n.next()");
            p.box("flt", 156, 40, 130, 50, "content hooks\nserverToProxyResponse\nproxyToClientResponse");
            p.arrow(62, 65, 74, 65);
            p.arrow(286, 65, 298, 65);
            for (var i = 0; i < 4; i++) {
              p.token("m" + i, 109, 120, "", "mp-a-obj", "block");
            }
            p.text(null, 8, 168, "each piece: a new HttpContent and its bytes", "mp-a-note");
            p.text("gc", 8, 190, "", "mp-a-note");
          }
        },
        {
          title: "No filter reads it: relayResponseBody()",
          cls: MP,
          w: 360,
          h: 220,
          build: function (p) {
            p.box("srv", 6, 40, 56, 50, "server");
            p.box("cli", 298, 40, 56, 50, "client");
            p.box("rd", 74, 40, 100, 50, "body.read(buf)\nparses chunking");
            p.box("wr", 186, 40, 100, 50, "client.writeData\n(buf); flush when\nnothing buffered");
            p.arrow(62, 65, 74, 65);
            p.arrow(174, 65, 186, 65);
            p.arrow(286, 65, 298, 65);
            p.token("buf", 180, 124, "64K", MP + " mp-a-buf", "block");
            p.text(null, 8, 168, "one 64 KiB buffer from relayBuffers, reused", "mp-a-note");
            p.text("fig", 8, 190, "", "mp-a-note");
          }
        }
      ],
      steps: [
        {
          panels: [
            {
              caption: "When a filter overrides a content hook (`clientToProxyRequest` / `proxyToServerRequest`, or `serverToProxyResponse` / `proxyToClientResponse`, checked through chains as well), the body travels as messages: `MessageBody.next()` returns an `HttpContent` per piece, which each hook sees.",
              apply: function (s) { s.on("rd"); }
            },
            {
              caption: "When none does, the body skips message objects. `relayResponseBody()` borrows one 64 KiB buffer and loops: `body.read(buf)` parses any chunk framing and fills it with body data.",
              apply: function (s) { s.on("rd"); s.at("buf", 124, 118); }
            }
          ]
        },
        {
          panels: [
            {
              caption: "Each piece is a new object with its own bytes, passed through the hooks and written with `writeContent()`.",
              apply: function (s) { s.off("rd"); s.on("flt"); s.at("m0", 221, 120); s.at("m1", 109, 120); }
            },
            {
              caption: "`client.writeData(buf)` re-frames the data if the client's side is chunked (`writeEnd` adds the last chunk and trailers), and the output is flushed only when no more input is already buffered.",
              apply: function (s) { s.off("rd"); s.on("wr"); s.at("buf", 236, 118); }
            }
          ]
        },
        {
          panels: [
            {
              caption: "And the next piece, and the next: every one allocates, and the old ones wait for the garbage collector.",
              apply: function (s) {
                s.at("m0", 300, 140); s.cls("m0", "gone"); s.at("m1", 221, 120); s.at("m2", 109, 120);
                s.text("gc", "garbage: piece 1, piece 2, …");
              }
            },
            {
              caption: "The same buffer goes round again for the next piece: nothing new is allocated per piece.",
              apply: function (s) { s.on("rd"); s.off("wr"); s.at("buf", 124, 118); }
            }
          ]
        },
        {
          panels: [
            {
              caption: "Through per-piece objects, a 256 MiB body relayed on loopback at about 0.47 GB/s with `Content-Length` (0.25 GB/s chunked), allocating about 270 MB.",
              apply: function (s) {
                s.at("m1", 300, 140); s.cls("m1", "gone"); s.at("m2", 221, 120); s.at("m3", 109, 120);
                s.text("gc", "about 270 MB allocated for a 256 MiB body");
              }
            },
            {
              caption: "Through the reused buffer, the same body relays at about 1.2 GB/s (0.6 GB/s chunked), allocating under 3 MB. LittleProxy relays every body as Netty `HttpContent` messages through its pipeline.",
              apply: function (s) { s.text("fig", "1.2 GB/s (from 0.47), under 3 MB allocated"); s.off("rd"); }
            }
          ]
        }
      ]
    };
  };

  // 5. One exchange logic over interchangeable transports.
  SCENES.transports = function () {
    var cx = [72, 210, 348];
    return {
      title: "One exchange logic, interchangeable transports",
      panels: [
        {
          title: "MicroProxy: ClientChannel → handleRequest → ServerConnection",
          cls: MP,
          w: 420,
          h: 372,
          build: function (p) {
            p.box("t1", 8, 30, 128, 40, "HTTP/1 connection\nHttp1ClientChannel", "mp-a-tight");
            p.box("t2", 146, 30, 128, 40, "HTTP/2 stream\nHttp2StreamChannel", "mp-a-tight");
            p.box("t3", 284, 30, 128, 40, "HTTP/3 stream\nHttp3StreamChannel", "mp-a-tight");
            p.box("cc", 8, 96, 404, 24, "ClientChannel: requestBody · writeHead · writeData · relay · close", "mp-a-lane");
            p.box("ex", 8, 136, 404, 80, "ClientConnection.handleRequest(channel, request)\nauthentication · filters · routing · chained proxies\nconnection pool · retries · relay · tunnels\n ", "mp-a-core");
            p.box("sc", 8, 232, 404, 24, "ServerConnection: writeRequestHead · writeData · readResponse", "mp-a-lane");
            p.box("s1", 8, 280, 128, 52, "HTTP/1.1\nServerConnection\nitself", "mp-a-tight");
            p.box("s2", 146, 280, 128, 52, "Http2UpstreamStream\non a shared\nHttp2UpstreamConnection", "mp-a-tight");
            p.box("s3", 284, 280, 128, 52, "Http3UpstreamStream\non a shared\nHttp3UpstreamConnection", "mp-a-tight");
            p.text("note", 210, 358, "", "mp-a-note", "middle");
            p.token("r1", cx[0], 84, "1", "mp-a-t1", "block");
            p.token("r2", cx[1], 84, "2", "mp-a-t2", "block");
            p.token("r3", cx[2], 84, "3", "mp-a-t3", "block");
          }
        }
      ],
      steps: [
        {
          panels: [{
            caption: "A request on an HTTP/1 connection: `Http1ClientChannel` (with `ByteReader`, `HttpCodec` and `Framing`) parses it and hands it to `ClientConnection.handleRequest()`, which runs the filters, picks the route and takes or makes an HTTP/1.1 `ServerConnection`.",
            apply: function (s) { s.on("t1"); s.at("r1", cx[0], 202); s.on("ex"); s.hide("r2"); s.hide("r3"); }
          }]
        },
        {
          panels: [{
            caption: "The response comes back through the same `ServerConnection` methods (`readResponse`, `responseBody`) and goes out through the channel's `writeHead` and `writeData`. The exchange logic touched the client only through `ClientChannel`.",
            apply: function (s) { s.on("s1"); s.at("r1", cx[0], 268); }
          }]
        },
        {
          panels: [{
            caption: "An HTTP/2 stream: `Http2Connection` gives each stream a thread of its own and an `Http2StreamChannel`, and the very same `handleRequest()` runs; to an HTTP/2 server it uses one stream (`Http2UpstreamStream`) of a connection shared through `Http2Origins`.",
            apply: function (s) { s.off("t1"); s.off("s1"); s.at("r1", cx[0], 84); s.show("r2"); s.on("t2"); s.on("s2"); s.at("r2", cx[1], 268); }
          }]
        },
        {
          panels: [{
            caption: "An HTTP/3 request stream: `Http3StreamChannel`, the same exchange logic again, and on the server side whichever the route needs: here one stream of an `Http3UpstreamConnection` shared through `Http3Origins` (an HTTP/1.1 or HTTP/2 server works the same way).",
            apply: function (s) { s.off("t2"); s.off("s2"); s.at("r2", cx[1], 84); s.show("r3"); s.on("t3"); s.on("s3"); s.at("r3", cx[2], 268); }
          }]
        },
        {
          panels: [{
            caption: "So filters, routing, pooling, retries and the body fast path are written once, and HTTP/2 and HTTP/3 streams run them concurrently, each on its own virtual thread; only the wire format differs per transport.",
            apply: function (s) {
              s.on("t1"); s.on("t2"); s.on("t3"); s.on("s1"); s.on("s2"); s.on("s3"); s.show("r2"); s.show("r3");
              s.at("r1", cx[0], 202); s.at("r2", cx[1], 202); s.at("r3", cx[2], 202);
              s.text("note", "three transports, one handleRequest()");
            }
          }]
        }
      ]
    };
  };

  // --- wiring ---

  var perfData = null;

  function loadPerf(url) {
    if (!perfData) {
      perfData = fetch(url, { credentials: "same-origin" }).then(function (r) {
        if (!r.ok) throw new Error("HTTP " + r.status);
        return r.json();
      }).catch(function () { perfData = null; return null; });
    }
    return perfData;
  }

  function init() {
    var nodes = document.querySelectorAll(".mp-arch[data-scene]:not([data-ready])");
    if (!nodes.length) return;
    var srcEl = document.querySelector(".mp-arch[data-perf-src]");
    var url = new URL(srcEl ? srcEl.getAttribute("data-perf-src") : "../assets/perf/results.json", window.location.href).href;
    loadPerf(url).then(function (data) {
      Array.prototype.forEach.call(nodes, function (node) {
        var make = SCENES[node.getAttribute("data-scene")];
        if (!make) return;
        node.setAttribute("data-ready", "");
        try {
          new Scene(node, make(data));
        } catch (e) {
          node.removeAttribute("data-ready");
          node.textContent = "";
          if (window.console) console.error("architecture diagram", e);
        }
      });
      document.documentElement.classList.add("mp-arch-ready");
    });
  }

  // For docs/scripts/render_arch_svgs.js: the scene names.
  window.__mpArchScenes = Object.keys(SCENES);

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init);
  } else {
    init();
  }
})();
