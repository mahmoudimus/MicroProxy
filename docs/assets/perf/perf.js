/*
 * The interactive charts of the performance page (docs/project/performance.md), drawn in plain SVG
 * from docs/assets/perf/results.json, which loadtest/competitors/aggregate.py writes from the
 * harness's raw results. No number is written in this file: every value on a chart comes from that
 * JSON. A chart is a <div class="mp-perf-chart" data-chart="..."> on the page; anything else on the
 * site is left alone.
 *
 * Works with Material's instant navigation (re-initialises on document$), honours
 * prefers-reduced-motion (the final state, no animation), Material's light and dark schemes (CSS
 * tokens in perf.css), keyboard use (every control is a button, select or range; plots take arrow
 * keys) and narrow screens (the SVG is drawn at the container's width).
 */
(function () {
  "use strict";

  var SVGNS = "http://www.w3.org/2000/svg";
  var SHAPES = ["circle", "square", "triangle", "diamond", "triangleDown", "plus", "circle", "square"];
  var HIDDEN_KEY = "mp-perf-hidden";
  var dataPromise = null;
  var hidden = loadHidden();
  var charts = [];
  var nf0 = new Intl.NumberFormat("en-US", { maximumFractionDigits: 0 });
  var nf1 = new Intl.NumberFormat("en-US", { maximumFractionDigits: 1, minimumFractionDigits: 1 });
  var nf2 = new Intl.NumberFormat("en-US", { maximumFractionDigits: 2, minimumFractionDigits: 2 });

  function reducedMotion() {
    return window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches;
  }

  function loadHidden() {
    try {
      var v = JSON.parse(window.localStorage.getItem(HIDDEN_KEY) || "[]");
      return Array.isArray(v) ? v : [];
    } catch (e) {
      return [];
    }
  }

  function saveHidden() {
    try {
      window.localStorage.setItem(HIDDEN_KEY, JSON.stringify(hidden));
    } catch (e) {
      /* Storage unavailable: the choice lasts for this page only. */
    }
  }

  // --- small DOM helpers (text always goes in through textContent) ---

  function el(tag, attrs, parent, text) {
    var e = document.createElement(tag);
    setAttrs(e, attrs);
    if (text != null) e.textContent = text;
    if (parent) parent.appendChild(e);
    return e;
  }

  function sv(tag, attrs, parent, text) {
    var e = document.createElementNS(SVGNS, tag);
    setAttrs(e, attrs);
    if (text != null) e.textContent = text;
    if (parent) parent.appendChild(e);
    return e;
  }

  function setAttrs(e, attrs) {
    if (!attrs) return;
    Object.keys(attrs).forEach(function (k) {
      if (attrs[k] != null) e.setAttribute(k, attrs[k]);
    });
  }

  function color(p) {
    return "var(--mp-c" + (p.slot % 8) + ")";
  }

  function fmtMs(v) {
    if (v == null) return "n/a";
    return v >= 100 ? nf0.format(v) + " ms" : nf2.format(v) + " ms";
  }

  function fmtSpread(st, f) {
    if (!st) return "n/a";
    if (st.n <= 1 || st.min === st.max) return f(st.med) + (st.n ? " (" + st.n + " run" + (st.n > 1 ? "s" : "") + ")" : "");
    return f(st.med) + " (" + f(st.min) + "–" + f(st.max) + ", " + st.n + " runs)";
  }

  function compact(v) {
    if (v >= 1000) return (Math.round(v / 100) / 10).toString().replace(/\.0$/, "") + "K";
    return String(Math.round(v * 100) / 100);
  }

  // A harness size setting ("16m", "8192") in words.
  function size(v) {
    var m = /^(\d+(?:\.\d+)?)([kmg]?)$/i.exec(String(v || "").trim());
    if (!m) return String(v);
    var bytes = Number(m[1]) * { "": 1, k: 1024, m: 1048576, g: 1073741824 }[m[2].toLowerCase()];
    if (bytes >= 1048576) return nf0.format(bytes / 1048576) + " MB";
    if (bytes >= 1024) return nf0.format(bytes / 1024) + " KB";
    return nf0.format(bytes) + " bytes";
  }

  function niceMax(v) {
    if (!(v > 0)) return 1;
    var e = Math.pow(10, Math.floor(Math.log10(v)));
    var steps = [1, 1.5, 2, 2.5, 3, 4, 5, 6, 8, 10];
    for (var i = 0; i < steps.length; i++) if (v <= steps[i] * e) return steps[i] * e;
    return 10 * e;
  }

  // Ticks at round steps (1, 2, 2.5 or 5 times a power of ten), about four to six of them.
  function niceTicks(max) {
    var counts = [5, 4, 6, 8, 3, 10, 2];
    for (var i = 0; i < counts.length; i++) {
      var step = max / counts[i];
      var e = Math.pow(10, Math.floor(Math.log10(step)));
      var m = Math.round((step / e) * 1000) / 1000;
      if ([1, 2, 2.5, 5, 10].indexOf(m) >= 0) return linTicks(max, counts[i]);
    }
    return linTicks(max, 4);
  }

  function linTicks(max, n) {
    var out = [];
    for (var i = 0; i <= n; i++) out.push((max * i) / n);
    return out;
  }

  function ease(t) {
    return t < 0.5 ? 2 * t * t : 1 - Math.pow(-2 * t + 2, 2) / 2;
  }

  // A marker of the given shape, centered on x, y.
  function marker(g, shape, x, y, r, fill, extra) {
    var attrs = Object.assign({ fill: fill, stroke: "var(--mp-surface)", "stroke-width": 2 }, extra || {});
    var d;
    switch (shape) {
      case "square":
        d = "M" + (x - r) + " " + (y - r) + "h" + 2 * r + "v" + 2 * r + "h" + -2 * r + "Z";
        break;
      case "triangle":
        d = "M" + x + " " + (y - r * 1.2) + "L" + (x + r * 1.1) + " " + (y + r * 0.8) + "L" + (x - r * 1.1) + " " + (y + r * 0.8) + "Z";
        break;
      case "triangleDown":
        d = "M" + x + " " + (y + r * 1.2) + "L" + (x + r * 1.1) + " " + (y - r * 0.8) + "L" + (x - r * 1.1) + " " + (y - r * 0.8) + "Z";
        break;
      case "diamond":
        d = "M" + x + " " + (y - r * 1.3) + "L" + (x + r * 1.3) + " " + y + "L" + x + " " + (y + r * 1.3) + "L" + (x - r * 1.3) + " " + y + "Z";
        break;
      case "plus":
        var a = r * 0.45;
        d = "M" + (x - a) + " " + (y - r) + "h" + 2 * a + "v" + (r - a) + "h" + (r - a) + "v" + 2 * a + "h" + -(r - a) + "v" + (r - a) + "h" + -2 * a + "v" + -(r - a) + "h" + -(r - a) + "v" + -2 * a + "h" + (r - a) + "Z";
        break;
      default:
        return sv("circle", Object.assign(attrs, { cx: x, cy: y, r: r }), g);
    }
    return sv("path", Object.assign(attrs, { d: d }), g);
  }

  // A small swatch for the legend: the series' line and marker.
  function legendKey(p, line) {
    var s = sv("svg", { width: 22, height: 12, viewBox: "0 0 22 12", "aria-hidden": "true" });
    if (line) sv("line", { x1: 1, y1: 6, x2: 21, y2: 6, stroke: color(p), "stroke-width": p.id === "microproxy" ? 3 : 2, "stroke-linecap": "round" }, s);
    else sv("rect", { x: 3, y: 1, width: 16, height: 10, rx: 2, fill: color(p) }, s);
    marker(s, SHAPES[p.slot % 8], 11, 6, 3.5, color(p), { "stroke-width": 1 });
    return s;
  }

  // --- the shared frame of every chart ---

  function Chart(root, data, spec) {
    this.root = root;
    this.data = data;
    this.spec = spec;
    this.progress = reducedMotion() ? 1 : 0;
    this.started = false;
    this.anim = null;
    root.classList.add("mp-perf-root");
    root.textContent = "";
    el("h4", { class: "mp-title" }, root, spec.title);
    if (spec.sub) el("p", { class: "mp-sub" }, root, spec.sub);
    this.controls = el("div", { class: "mp-row" }, root);
    this.legend = el("div", { class: "mp-legend", role: "group", "aria-label": "Proxies shown (toggle)" }, root);
    this.extra = el("div", null, root);
    this.plot = el("div", { class: "mp-plot" }, root);
    this.tip = el("div", { class: "mp-tip", hidden: "", role: "status", "aria-live": "polite" }, this.plot);
    if (spec.note) this.noteEl = el("p", { class: "mp-note" }, root, spec.note);
    this.buildLegend(spec.legendLine !== false);
    var self = this;
    if (!reducedMotion()) {
      var replay = el("button", { type: "button", class: "mp-btn", "aria-label": "Replay the animation of: " + spec.title }, this.controls, "↻ Replay");
      replay.addEventListener("click", function () {
        self.play();
      });
    }
    if ("ResizeObserver" in window) {
      var lastW = 0;
      this.ro = new ResizeObserver(function () {
        if (!root.isConnected) {
          self.ro.disconnect();
          return;
        }
        var w = Math.round(self.plot.clientWidth);
        if (w && w !== lastW) {
          lastW = w;
          self.render();
        }
      });
      this.ro.observe(this.plot);
    }
    if (!reducedMotion() && "IntersectionObserver" in window) {
      this.io = new IntersectionObserver(function (entries) {
        if (entries.some(function (e) { return e.isIntersecting; }) && !self.started) {
          self.io.disconnect();
          self.play();
        }
      }, { threshold: 0.35 });
      this.io.observe(root);
    } else {
      this.progress = 1;
    }
  }

  Chart.prototype.visible = function () {
    return this.data.proxies.filter(function (p) {
      return hidden.indexOf(p.id) < 0;
    });
  };

  Chart.prototype.buildLegend = function (line) {
    var self = this;
    this.legend.textContent = "";
    this.data.proxies.forEach(function (p) {
      var b = el("button", { type: "button", class: "mp-key" + (p.id === "microproxy" ? " mp-main" : ""), "aria-pressed": String(hidden.indexOf(p.id) < 0), title: (p.version || p.label) + (p.language ? " · " + p.language : "") }, self.legend);
      b.appendChild(legendKey(p, line));
      el("span", null, b, p.label);
      b.addEventListener("click", function () {
        var i = hidden.indexOf(p.id);
        if (i >= 0) hidden.splice(i, 1);
        else if (hidden.length < self.data.proxies.length - 1) hidden.push(p.id);
        saveHidden();
        charts.forEach(function (c) {
          if (c.root.isConnected) {
            c.syncLegend();
            c.render();
          }
        });
      });
    });
  };

  Chart.prototype.syncLegend = function () {
    var keys = this.legend.querySelectorAll("button.mp-key");
    var ps = this.data.proxies;
    for (var i = 0; i < keys.length; i++) keys[i].setAttribute("aria-pressed", String(hidden.indexOf(ps[i].id) < 0));
  };

  Chart.prototype.play = function () {
    var self = this;
    this.started = true;
    if (reducedMotion()) {
      this.progress = 1;
      this.render();
      return;
    }
    if (this.anim) cancelAnimationFrame(this.anim);
    var dur = this.spec.duration || 3200;
    var t0 = null;
    function frame(ts) {
      if (t0 == null) t0 = ts;
      var t = Math.min(1, (ts - t0) / dur);
      self.progress = ease(t);
      self.render();
      if (t < 1 && self.root.isConnected) self.anim = requestAnimationFrame(frame);
      else self.anim = null;
    }
    this.progress = 0;
    this.anim = requestAnimationFrame(frame);
  };

  Chart.prototype.stop = function () {
    if (this.anim) cancelAnimationFrame(this.anim);
    this.anim = null;
  };

  // A fresh SVG at the plot's width; returns {svg, w, h, m (margins), pw, ph}.
  Chart.prototype.canvas = function (heightRatio, margins) {
    var old = this.plot.querySelector("svg");
    if (old) old.remove();
    var w = Math.max(280, Math.round(this.plot.clientWidth || 600));
    var h = Math.round(Math.max(220, Math.min(420, w * heightRatio)));
    var m = Object.assign({ l: 52, r: 18, t: 14, b: 40 }, margins || {});
    var svg = sv("svg", { viewBox: "0 0 " + w + " " + h, width: w, height: h, role: "img", "aria-label": this.spec.title });
    this.plot.insertBefore(svg, this.tip);
    return { svg: svg, w: w, h: h, m: m, pw: w - m.l - m.r, ph: h - m.t - m.b };
  };

  Chart.prototype.showTip = function (x, y, header, rows) {
    var tip = this.tip;
    tip.textContent = "";
    el("div", { class: "mp-tip-h" }, tip, header);
    rows.forEach(function (r) {
      var row = el("div", { class: "mp-tip-r" }, tip);
      var k = el("i", { class: "mp-lk" }, row);
      k.style.background = r.color;
      el("b", null, row, r.value);
      el("span", null, row, r.label);
    });
    tip.hidden = false;
    var pw = this.plot.clientWidth;
    var tw = tip.offsetWidth;
    var th = tip.offsetHeight;
    var left = x + 14;
    if (left + tw > pw) left = Math.max(0, x - tw - 14);
    var top = Math.max(0, y - th / 2);
    tip.style.left = left + "px";
    tip.style.top = top + "px";
  };

  Chart.prototype.hideTip = function () {
    this.tip.hidden = true;
  };

  // Axes: horizontal gridlines with y ticks, an x baseline with x ticks, and both axis titles.
  function axes(c, yTicks, Y, yFmt, xTicks, X, xFmt, xTitle, yTitle) {
    var g = sv("g", null, c.svg);
    yTicks.forEach(function (v) {
      var y = Y(v);
      sv("line", { class: "mp-grid", x1: c.m.l, x2: c.m.l + c.pw, y1: y, y2: y }, g);
      sv("text", { class: "mp-tick", x: c.m.l - 6, y: y + 4, "text-anchor": "end" }, g, yFmt(v));
    });
    sv("line", { class: "mp-axis", x1: c.m.l, x2: c.m.l + c.pw, y1: c.m.t + c.ph, y2: c.m.t + c.ph }, g);
    xTicks.forEach(function (v) {
      sv("text", { class: "mp-tick", x: X(v), y: c.m.t + c.ph + 15, "text-anchor": "middle" }, g, xFmt(v));
    });
    sv("text", { class: "mp-axis-title", x: c.m.l + c.pw / 2, y: c.h - 6, "text-anchor": "middle" }, g, xTitle);
    sv("text", { class: "mp-axis-title", x: 12, y: c.m.t + c.ph / 2, "text-anchor": "middle", transform: "rotate(-90 12 " + (c.m.t + c.ph / 2) + ")" }, g, yTitle);
    return g;
  }

  // The points of a series up to xLimit, with the last segment interpolated to it.
  function clipTo(points, xLimit) {
    var out = [];
    for (var i = 0; i < points.length; i++) {
      var p = points[i];
      if (p[0] <= xLimit) {
        out.push(p);
      } else {
        if (i > 0) {
          var a = points[i - 1];
          var f = (xLimit - a[0]) / (p[0] - a[0]);
          out.push([xLimit, a[1] + (p[1] - a[1]) * f, true]);
        }
        break;
      }
    }
    return out;
  }

  function pathOf(pts, X, Y) {
    return pts.map(function (p, i) {
      return (i ? "L" : "M") + X(p[0]).toFixed(1) + " " + Y(p[1]).toFixed(1);
    }).join("");
  }

  /*
   * A line chart with a crosshair: series = [{p, points: [[x, y, extra]], band: [[x, lo, hi]]}].
   * opts: xMax, yMax, yLog {min, max}, xFmt, yFmt, xTitle, yTitle, yCap {value, label}, clampTop,
   * xTicks, tipHeader(x), tipValue(series, point), progress (0..1 of the x range), heightRatio,
   * after(c, X, Y) to draw more.
   */
  function lineChart(chart, series, opts) {
    var c = chart.canvas(opts.heightRatio || 0.5, opts.margins);
    var xMax = opts.xMax;
    var X = function (x) {
      return c.m.l + (c.pw * (opts.xMap ? opts.xMap(x) : x)) / (opts.xMap ? opts.xMap(xMax) : xMax);
    };
    var Y;
    var yTicks;
    if (opts.yLog) {
      var lo = Math.log10(opts.yLog.min);
      var hi = Math.log10(opts.yLog.max);
      Y = function (y) {
        var v = Math.log10(Math.max(opts.yLog.min, y));
        return c.m.t + c.ph - (c.ph * (v - lo)) / (hi - lo);
      };
      yTicks = [];
      for (var e = Math.ceil(lo); e <= hi; e++) yTicks.push(Math.pow(10, e));
    } else {
      Y = function (y) {
        return c.m.t + c.ph - (c.ph * Math.min(y, opts.yMax)) / opts.yMax;
      };
      yTicks = opts.yTickCount ? linTicks(opts.yMax, opts.yTickCount) : niceTicks(opts.yMax);
    }
    axes(c, yTicks, Y, opts.yFmt, opts.xTicks || niceTicks(xMax), X, opts.xFmt, opts.xTitle, opts.yTitle);
    var xLimit = opts.xMin + (xMax - opts.xMin) * opts.progress;
    if (opts.yCap) {
      var cy = Y(opts.yCap.value);
      sv("line", { class: "mp-capline", x1: c.m.l, x2: c.m.l + c.pw, y1: cy, y2: cy }, c.svg);
      sv("text", { class: "mp-cap-text", x: c.m.l + c.pw - 4, y: cy - 6, "text-anchor": "end" }, c.svg, opts.yCap.label);
    }
    if (opts.badge) sv("text", { class: "mp-badge", x: c.m.l + 6, y: c.m.t + 12 }, c.svg, opts.badge);
    // Bands first (behind every line), then lines, then markers.
    series.forEach(function (s) {
      if (!s.band || !s.band.length) return;
      var pts = s.band.filter(function (b) { return b[0] <= xLimit; });
      if (pts.length < 2) return;
      var d = pts.map(function (b, i) { return (i ? "L" : "M") + X(b[0]).toFixed(1) + " " + Y(b[2]).toFixed(1); }).join("");
      for (var i = pts.length - 1; i >= 0; i--) d += "L" + X(pts[i][0]).toFixed(1) + " " + Y(pts[i][1]).toFixed(1);
      sv("path", { d: d + "Z", fill: color(s.p), "fill-opacity": 0.12, stroke: "none" }, c.svg);
    });
    var drawn = [];
    series.forEach(function (s) {
      var pts = clipTo(s.points, xLimit);
      if (!pts.length) return;
      var main = s.p.id === "microproxy";
      sv("path", { d: pathOf(pts, X, Y), fill: "none", stroke: color(s.p), "stroke-width": main ? 3 : 2, "stroke-linejoin": "round", "stroke-linecap": "round" }, c.svg);
      drawn.push({ s: s, pts: pts });
    });
    drawn.forEach(function (d) {
      var shape = SHAPES[d.s.p.slot % 8];
      d.pts.forEach(function (pt) {
        if (pt[2] === true) return; // the interpolated head of an animated line
        var over = !opts.yLog && pt[1] > opts.yMax;
        if (over) {
          // Above the axis: pinned to the top edge as an up-pointing triangle; the value is in the tooltip.
          marker(c.svg, "triangle", X(pt[0]), Y(opts.yMax) + 1, 5, color(d.s.p));
        } else {
          marker(c.svg, shape, X(pt[0]), Y(pt[1]), d.s.p.id === "microproxy" ? 4.5 : 3.6, color(d.s.p));
        }
      });
      if (d.s.end && d.pts.length === d.s.points.length) {
        var last = d.pts[d.pts.length - 1];
        var ex = X(last[0]);
        var ey = Y(last[1]);
        sv("path", { d: "M" + (ex - 7) + " " + (ey - 7) + "L" + (ex + 7) + " " + (ey + 7) + "M" + (ex + 7) + " " + (ey - 7) + "L" + (ex - 7) + " " + (ey + 7), stroke: "var(--mp-surface)", "stroke-width": 6, "stroke-linecap": "round" }, c.svg);
        sv("path", { d: "M" + (ex - 7) + " " + (ey - 7) + "L" + (ex + 7) + " " + (ey + 7) + "M" + (ex + 7) + " " + (ey - 7) + "L" + (ex - 7) + " " + (ey + 7), stroke: color(d.s.p), "stroke-width": 3, "stroke-linecap": "round" }, c.svg);
        sv("text", { class: "mp-label", x: ex + (ex > c.m.l + c.pw - 90 ? -10 : 10), y: ey - 10, "text-anchor": ex > c.m.l + c.pw - 90 ? "end" : "start" }, c.svg, d.s.endLabel || d.s.end.verdict);
      }
    });
    // A direct label at the end of MicroProxy's line, the series the page is about.
    drawn.forEach(function (d) {
      if (d.s.p.id !== "microproxy" || opts.noDirectLabel) return;
      var last = d.pts[d.pts.length - 1];
      var lx = X(last[0]);
      var ly = Y(opts.yLog ? last[1] : Math.min(last[1], opts.yMax));
      var right = lx > c.m.l + c.pw - 80;
      sv("text", { class: "mp-label", x: right ? lx - 8 : lx + 8, y: ly - 8, "text-anchor": right ? "end" : "start" }, c.svg, d.s.p.label);
    });
    if (opts.after) opts.after(c, X, Y, xLimit);
    // The crosshair layer: snaps to the nearest measured x.
    var xs = [];
    series.forEach(function (s) {
      s.points.forEach(function (pt) {
        if (pt[0] <= xLimit + 1e-9 && xs.indexOf(pt[0]) < 0) xs.push(pt[0]);
      });
    });
    xs.sort(function (a, b) { return a - b; });
    var cross = sv("line", { class: "mp-cross", y1: c.m.t, y2: c.m.t + c.ph, visibility: "hidden" }, c.svg);
    var hit = sv("rect", { x: c.m.l, y: c.m.t, width: c.pw, height: c.ph, fill: "transparent", tabindex: 0, role: "application", "aria-label": chart.spec.title + ": use the left and right arrow keys to read the values at each point" }, c.svg);
    var idx = -1;
    function show(i) {
      if (!xs.length) return;
      idx = Math.max(0, Math.min(xs.length - 1, i));
      var x = xs[idx];
      cross.setAttribute("x1", X(x));
      cross.setAttribute("x2", X(x));
      cross.setAttribute("visibility", "visible");
      var rows = [];
      series.forEach(function (s) {
        var pt = s.points.find(function (q) { return q[0] === x; });
        if (!pt) return;
        rows.push({ color: color(s.p), value: opts.tipValue(s, pt), label: s.p.label, y: pt[1] });
      });
      if (opts.sortTip) rows.sort(function (a, b) { return a.y - b.y; });
      chart.showTip(X(x), c.m.t + c.ph / 3, opts.tipHeader(x), rows);
    }
    function nearest(evt) {
      var r = c.svg.getBoundingClientRect();
      var px = ((evt.clientX - r.left) * c.w) / r.width;
      var best = 0;
      for (var i = 1; i < xs.length; i++) if (Math.abs(X(xs[i]) - px) < Math.abs(X(xs[best]) - px)) best = i;
      return best;
    }
    hit.addEventListener("pointermove", function (evt) {
      show(nearest(evt));
    });
    hit.addEventListener("pointerdown", function (evt) {
      show(nearest(evt));
    });
    hit.addEventListener("pointerleave", function () {
      cross.setAttribute("visibility", "hidden");
      chart.hideTip();
    });
    hit.addEventListener("focus", function () {
      show(idx < 0 ? xs.length - 1 : idx);
    });
    hit.addEventListener("blur", function () {
      cross.setAttribute("visibility", "hidden");
      chart.hideTip();
    });
    hit.addEventListener("keydown", function (evt) {
      if (evt.key === "ArrowRight" || evt.key === "ArrowLeft") {
        evt.preventDefault();
        show(idx + (evt.key === "ArrowRight" ? 1 : -1));
      } else if (evt.key === "Home" || evt.key === "End") {
        evt.preventDefault();
        show(evt.key === "Home" ? 0 : xs.length - 1);
      } else if (evt.key === "Escape") {
        cross.setAttribute("visibility", "hidden");
        chart.hideTip();
      }
    });
    return c;
  }

  /* Horizontal bars with min–max whiskers: rows = [{p, st (stats), note}]. */
  function barChart(chart, rows, opts) {
    var rowH = 30;
    var old = chart.plot.querySelector("svg");
    if (old) old.remove();
    var w = Math.max(280, Math.round(chart.plot.clientWidth || 600));
    var labelW = Math.min(130, Math.round(w * 0.3));
    var m = { l: labelW, r: 64, t: 6, b: 30 };
    var h = m.t + m.b + rowH * rows.length;
    var svg = sv("svg", { viewBox: "0 0 " + w + " " + h, width: w, height: h, role: "img", "aria-label": chart.spec.title });
    chart.plot.insertBefore(svg, chart.tip);
    var pw = w - m.l - m.r;
    var vmax = niceMax(Math.max.apply(null, rows.map(function (r) { return r.st ? r.st.max : 0; }).concat([1e-9])));
    var X = function (v) { return m.l + (pw * v) / vmax; };
    (w < 420 ? linTicks(vmax, 2) : niceTicks(vmax)).forEach(function (v) {
      sv("line", { class: "mp-grid", x1: X(v), x2: X(v), y1: m.t, y2: m.t + rowH * rows.length }, svg);
      sv("text", { class: "mp-tick", x: X(v), y: h - 12, "text-anchor": "middle" }, svg, opts.tickFmt(v));
    });
    sv("line", { class: "mp-axis", x1: m.l, x2: m.l, y1: m.t, y2: m.t + rowH * rows.length }, svg);
    rows.forEach(function (r, i) {
      var y = m.t + rowH * i + rowH / 2;
      var g = sv("g", { tabindex: 0, role: "listitem", "aria-label": r.p.label + ": " + (r.st ? opts.aria(r) : r.note || "not measured") }, svg);
      sv("rect", { class: "mp-hit", x: 0, y: y - rowH / 2 + 1, width: w, height: rowH - 2, fill: "transparent", rx: 4 }, g);
      sv("text", { class: r.p.id === "microproxy" ? "mp-label" : "mp-value", x: m.l - 8, y: y + 4, "text-anchor": "end" }, g, r.p.label);
      if (!r.st) {
        sv("text", { class: "mp-value", x: m.l + 6, y: y + 4 }, g, r.note || "not measured");
      } else {
        var f = opts.progress;
        var bw = Math.max(1, (X(r.st.med) - m.l) * f);
        // A 24px-max bar: 4px rounded data end, square at the baseline.
        var bh = 14;
        sv("path", { d: "M" + m.l + " " + (y - bh / 2) + "h" + Math.max(0, bw - 4) + "a4 4 0 0 1 4 4v" + (bh - 8) + "a4 4 0 0 1 -4 4h" + -Math.max(0, bw - 4) + "Z", fill: color(r.p) }, g);
        if (f >= 1) {
          var x1 = X(r.st.min);
          var x2 = X(r.st.max);
          if (x2 - x1 > 0.5) sv("path", { d: "M" + x1 + " " + y + "H" + x2 + "M" + x1 + " " + (y - 5) + "V" + (y + 5) + "M" + x2 + " " + (y - 5) + "V" + (y + 5), stroke: "var(--mp-text-2)", "stroke-width": 1.5, fill: "none" }, g);
          sv("text", { class: "mp-value", x: Math.max(X(r.st.med), x2) + 6, y: y + 4 }, g, opts.valueFmt(r.st.med));
        }
      }
      function tip() {
        if (!r.st) return;
        chart.showTip(Math.min(w - 40, X(r.st.max)), y, r.p.label, [{ color: color(r.p), value: opts.valueFmt(r.st.med), label: "median" }, { color: "transparent", value: opts.valueFmt(r.st.min) + " – " + opts.valueFmt(r.st.max), label: "min – max of " + r.st.n + " runs" }].concat(r.extra || []));
      }
      g.addEventListener("pointerenter", tip);
      g.addEventListener("focus", tip);
      g.addEventListener("pointerleave", function () { chart.hideTip(); });
      g.addEventListener("blur", function () { chart.hideTip(); });
    });
    svg.setAttribute("role", "list");
  }

  function segmented(parent, label, options, current, onChange) {
    var wrap = el("span", { class: "mp-seg", role: "group", "aria-label": label }, parent);
    el("span", null, wrap, label + ":");
    var buttons = options.map(function (o) {
      var b = el("button", { type: "button", class: "mp-btn", "aria-pressed": String(o.value === current) }, wrap, o.label);
      b.addEventListener("click", function () {
        buttons.forEach(function (x) { x.setAttribute("aria-pressed", "false"); });
        b.setAttribute("aria-pressed", "true");
        onChange(o.value);
      });
      return b;
    });
    return wrap;
  }

  // --- the charts ---

  var SPECS = {};

  SPECS.maxrate = function (root, d) {
    var chart = new Chart(root, d, {
      title: "Max sustainable rate (requests/s, higher is better)",
      sub: "The highest offered rate each proxy kept within a p99 of " + d.sloP99Ms + " ms, with no errors and no backlog, on one CPU. Bars are the median of " + d.runs.length + " runs; whiskers span the lowest and highest run.",
      legendLine: false,
      duration: 1600
    });
    chart.render = function () {
      var rows = chart.visible().map(function (p) {
        var s = d.sweep[p.id];
        var cb = (s.clientBoundRuns || []).length;
        return {
          p: p,
          st: s.maxSustainable,
          note: s.unsupported ? "not supported" : "none sustained",
          extra: cb ? [{ color: "transparent", value: String(cb), label: "run" + (cb > 1 ? "s" : "") + " ended by the load generator, left out" }] : null
        };
      });
      barChart(chart, rows, {
        progress: chart.progress,
        tickFmt: compact,
        valueFmt: function (v) { return nf0.format(v) + "/s"; },
        aria: function (r) { return "median " + nf0.format(r.st.med) + " requests per second, runs from " + nf0.format(r.st.min) + " to " + nf0.format(r.st.max); }
      });
    };
    return chart;
  };

  SPECS.latency = function (root, d) {
    var state = { metric: "p99", log: false, band: false, dial: 1 };
    var chart = new Chart(root, d, {
      title: "Latency as the offered load climbs (lower is better)",
      sub: "Each point is one step of the open-loop rate sweep: latency measured from each request's intended send time (corrected for coordinated omission), median of " + d.runs.length + " runs. Every line ends one or two steps past that proxy's knee.",
      note: "Linear axis: points above 100 ms (past a knee) are pinned to the top edge as ▲, with their value in the tooltip. The logarithmic axis shows them in scale.",
      duration: 4200
    });
    var dialRow = el("div", { class: "mp-dial" }, chart.extra);
    var dialId = "mp-dial-" + Math.random().toString(36).slice(2);
    el("label", { for: dialId }, dialRow, "Offered load");
    var rates = [];
    d.proxies.forEach(function (p) {
      d.sweep[p.id].steps.forEach(function (s) { if (rates.indexOf(s.rate) < 0) rates.push(s.rate); });
    });
    rates.sort(function (a, b) { return a - b; });
    var xMax = niceMax(rates[rates.length - 1] || 1);
    var xMin = rates[0] || 0;
    var dial = el("input", { id: dialId, type: "range", min: 0, max: 1000, step: 1, value: 1000, "aria-valuetext": "" }, dialRow);
    var out = el("output", { for: dialId }, dialRow);
    var board = el("div", { class: "mp-board", "aria-live": "off" }, chart.extra);
    dial.addEventListener("input", function () {
      chart.stop();
      chart.started = true;
      chart.progress = Number(dial.value) / 1000;
      chart.render();
    });
    segmented(chart.controls, "Percentile", [{ value: "p50", label: "p50" }, { value: "p99", label: "p99" }, { value: "p999", label: "p99.9" }], "p99", function (v) {
      state.metric = v;
      chart.render();
    });
    segmented(chart.controls, "Latency axis", [{ value: false, label: "linear, 0–100 ms" }, { value: true, label: "logarithmic" }], false, function (v) {
      state.log = v;
      chart.render();
    });
    var bandLabel = el("label", null, chart.controls);
    var bandBox = el("input", { type: "checkbox" }, bandLabel);
    bandLabel.appendChild(document.createTextNode("run-to-run spread"));
    bandBox.addEventListener("change", function () {
      state.band = bandBox.checked;
      chart.render();
    });
    var metricName = { p50: "p50", p99: "p99", p999: "p99.9" };
    chart.render = function () {
      var vis = chart.visible();
      var series = vis.map(function (p) {
        var steps = d.sweep[p.id].steps.filter(function (s) { return s[state.metric]; });
        return {
          p: p,
          points: steps.map(function (s) { return [s.rate, s[state.metric].med, s]; }),
          band: state.band ? steps.map(function (s) { return [s.rate, s[state.metric].min, s[state.metric].max]; }) : null
        };
      });
      var maxY = 0;
      series.forEach(function (s) { s.points.forEach(function (pt) { maxY = Math.max(maxY, pt[1]); }); });
      var dialRate = xMin + (rates[rates.length - 1] - xMin) * chart.progress;
      dial.value = String(Math.round(chart.progress * 1000));
      out.textContent = nf0.format(dialRate) + " req/s";
      dial.setAttribute("aria-valuetext", nf0.format(dialRate) + " requests per second offered");
      lineChart(chart, series, {
        xMin: xMin,
        xMax: xMax,
        progress: (dialRate - xMin) / Math.max(1, xMax - xMin),
        yMax: 100,
        yLog: state.log ? { min: 0.1, max: Math.pow(10, Math.ceil(Math.log10(Math.max(maxY, 1)))) } : null,
        badge: state.log ? "Logarithmic scale" : null,
        heightRatio: 0.52,
        xFmt: compact,
        yFmt: function (v) { return state.log ? (v < 1 ? String(v) : compact(v)) : String(Math.round(v)); },
        xTitle: "offered load (requests/s)",
        yTitle: metricName[state.metric] + " latency (ms)",
        sortTip: true,
        tipHeader: function (x) { return nf0.format(x) + " req/s offered · " + metricName[state.metric]; },
        tipValue: function (s, pt) {
          var st = pt[2];
          var m = st[state.metric];
          var v = fmtMs(m.med) + (m.n > 1 && m.min !== m.max ? " (" + fmtMs(m.min) + "–" + fmtMs(m.max) + ")" : "");
          if (st.sustained * 2 <= st.runs) v += " ✗";
          return v;
        },
        after: function (c, X) {
          // The dial's position on the plot.
          if (chart.progress < 1) {
            var x = X(Math.min(dialRate, xMax));
            sv("line", { x1: x, x2: x, y1: c.m.t, y2: c.m.t + c.ph, stroke: "var(--mp-text-2)", "stroke-width": 1, opacity: 0.5 }, c.svg);
          }
        }
      });
      // The readout: each proxy's value at the last measured step at or below the dial.
      board.textContent = "";
      var rowsB = vis.map(function (p) {
        var steps = d.sweep[p.id].steps.filter(function (s) { return s.rate <= dialRate + 1e-6 && s[state.metric]; });
        var s = steps[steps.length - 1];
        return { p: p, s: s, v: s ? s[state.metric].med : null };
      }).filter(function (r) { return r.s; });
      rowsB.sort(function (a, b) { return a.v - b.v; });
      rowsB.forEach(function (r, i) {
        var div = el("div", null, board);
        el("span", { class: "mp-rank" }, div, String(i + 1) + ".");
        var k = el("i", { class: "mp-lk" }, div);
        k.style.cssText = "display:inline-block;width:12px;height:3px;border-radius:2px;background:" + color(r.p);
        el("b", null, div, fmtMs(r.v) + (r.s.sustained * 2 <= r.s.runs ? " ✗" : ""));
        el("span", null, div, r.p.label + (r.s.rate < dialRate - 1 && r.s === d.sweep[r.p.id].steps[d.sweep[r.p.id].steps.length - 1] ? " (last step " + compact(r.s.rate) + "/s)" : ""));
      });
    };
    return chart;
  };

  SPECS.percentiles = function (root, d) {
    var rates = [];
    d.proxies.forEach(function (p) {
      d.sweep[p.id].steps.forEach(function (s) { if (s.percentiles && rates.indexOf(s.rate) < 0) rates.push(s.rate); });
    });
    rates.sort(function (a, b) { return a - b; });
    var state = { rate: d.commonRate || rates[0] };
    var chart = new Chart(root, d, {
      title: "Latency by percentile at one offered rate (lower is better)",
      sub: "The whole latency distribution at a rate every proxy sustained, as an HDR-style plot: each step right adds a nine (90%, 99%, 99.9%, …), so the far right is the tail and the maximum. Per-percentile median of " + d.runs.length + " runs.",
      note: "The percentile axis is logarithmic in 1/(1 − percentile), the usual way to show latency tails; the latency axis is linear.",
      duration: 2600
    });
    var label = el("label", null, chart.controls, "Offered rate ");
    var select = el("select", { class: "mp-select" }, label);
    rates.forEach(function (r) {
      el("option", { value: r, selected: r === state.rate ? "" : null }, select, nf0.format(r) + " req/s" + (r === d.commonRate ? " (highest all sustained)" : ""));
    });
    select.addEventListener("change", function () {
      state.rate = Number(select.value);
      chart.render();
    });
    function nines(pct) {
      if (pct >= 100) return 5.6;
      return -Math.log10(1 - pct / 100);
    }
    chart.render = function () {
      var series = chart.visible().map(function (p) {
        var s = d.sweep[p.id].steps.find(function (x) { return x.rate === state.rate; });
        return { p: p, points: s && s.percentiles ? s.percentiles.map(function (q) { return [nines(q[0]), q[1], q]; }) : [], step: s };
      });
      var maxY = 0;
      series.forEach(function (s) { s.points.forEach(function (pt) { maxY = Math.max(maxY, pt[1]); }); });
      var names = { 0: "min", 1: "90%", 2: "99%", 3: "99.9%", 4: "99.99%", 5: "99.999%", 5.6: "max" };
      lineChart(chart, series, {
        xMin: 0,
        xMax: 5.6,
        progress: chart.progress,
        yMax: niceMax(maxY * 1.05),
        heightRatio: 0.48,
        xTicks: [0, 1, 2, 3, 4, 5, 5.6],
        xFmt: function (v) { return names[v] || ""; },
        yFmt: function (v) { return String(Math.round(v * 10) / 10); },
        xTitle: "percentile",
        yTitle: "latency (ms)",
        sortTip: true,
        tipHeader: function (x) {
          var any = series.find(function (s) { return s.points.find(function (q) { return q[0] === x; }); });
          var q = any ? any.points.find(function (q2) { return q2[0] === x; })[2] : null;
          return (q ? (q[0] >= 100 ? "maximum" : q[0] <= 0 ? "minimum" : q[0] + "th percentile") : "") + " at " + nf0.format(state.rate) + " req/s";
        },
        tipValue: function (s, pt) {
          var q = pt[2];
          return fmtMs(q[1]) + (q[2] !== q[3] ? " (" + fmtMs(q[2]) + "–" + fmtMs(q[3]) + ")" : "");
        }
      });
    };
    return chart;
  };

  SPECS.idle = function (root, d) {
    var chart = new Chart(root, d, {
      title: "Idle memory: resident set size (MB, lower is better)",
      sub: "RSS after start-up and a few validation requests, before any load: what the OS charges for the proxy doing nothing. Median of " + d.runs.length + " runs; whiskers span min–max.",
      note: "The JVM proxies' RSS depends on heap sizing (here -Xmx1g, G1, Native Memory Tracking on); a native process has no such floor.",
      legendLine: false,
      duration: 1400
    });
    chart.render = function () {
      barChart(chart, chart.visible().map(function (p) {
        return { p: p, st: d.ramp[p.id].idleRssMb };
      }), {
        progress: chart.progress,
        tickFmt: function (v) { return Math.round(v) + " MB"; },
        valueFmt: function (v) { return nf1.format(v) + " MB"; },
        aria: function (r) { return "median " + nf1.format(r.st.med) + " megabytes"; }
      });
    };
    return chart;
  };

  SPECS.ramp = function (root, d) {
    var state = { band: false };
    var chart = new Chart(root, d, {
      title: "Memory as idle keep-alive connections pile up (lower is better)",
      sub: "RSS while the load generator opens idle keep-alive connections in steps, each after one request (so the proxy has also connected upstream). Median of " + d.runs.length + " runs.",
      note: "The largest step is bounded by this container's open-file limit, not by any proxy. Proxies that pool upstream connections (Envoy, goproxy, Squid) keep fewer upstream sockets than those that hold one per client connection.",
      duration: 3600
    });
    var bandLabel = el("label", null, chart.controls);
    var bandBox = el("input", { type: "checkbox" }, bandLabel);
    bandLabel.appendChild(document.createTextNode("run-to-run spread"));
    bandBox.addEventListener("change", function () {
      state.band = bandBox.checked;
      chart.render();
    });
    var maxX = 0;
    var maxY = 0;
    d.proxies.forEach(function (p) {
      d.ramp[p.id].steps.forEach(function (s) {
        if (s.held && s.rssMb) {
          maxX = Math.max(maxX, s.held.med);
          maxY = Math.max(maxY, s.rssMb.max);
        }
      });
    });
    chart.render = function () {
      var series = chart.visible().map(function (p) {
        var steps = d.ramp[p.id].steps.filter(function (s) { return s.held && s.rssMb; });
        return {
          p: p,
          points: steps.map(function (s) { return [s.held.med, s.rssMb.med, s]; }),
          band: state.band ? steps.map(function (s) { return [s.held.med, s.rssMb.min, s.rssMb.max]; }) : null
        };
      });
      var held = Math.round(maxX * chart.progress);
      lineChart(chart, series, {
        xMin: 0,
        xMax: niceMax(maxX),
        progress: (maxX * chart.progress) / niceMax(maxX),
        yMax: niceMax(maxY * 1.05),
        heightRatio: 0.48,
        xFmt: compact,
        yFmt: function (v) { return String(Math.round(v)); },
        xTitle: "idle connections held",
        yTitle: "RSS (MB)",
        sortTip: true,
        badge: chart.progress < 1 ? nf0.format(held) + " connections" : null,
        tipHeader: function (x) { return nf0.format(x) + " idle connections"; },
        tipValue: function (s, pt) {
          var st = pt[2];
          return fmtSpread(st.rssMb, function (v) { return nf1.format(v) + " MB"; });
        }
      });
    };
    return chart;
  };

  SPECS.race = function (root, d) {
    var attacks = Object.keys(d.memory);
    var names = { slowread: "slow readers", slowloris: "slowloris", updown: "large uploads and downloads" };
    var state = { attack: attacks.indexOf("slowread") >= 0 ? "slowread" : attacks[0] };
    var chart = new Chart(root, d, {
      title: "Memory under adversarial clients, in a 512 MB cgroup (lower is better)",
      sub: "RSS over time while the workload runs, every proxy in the same 512 MB memory cgroup (the JVMs additionally capped at a 256 MB heap and 128 MB of direct memory inside it). One line per proxy: the run with the median peak.",
      note: "✕ marks a proxy that ran out of memory (an OutOfMemoryError, or the cgroup's OOM killer) or crashed. Samples are 5 s apart. The verdicts, peaks across all runs and per-connection figures are in the table below.",
      duration: 4200
    });
    segmented(chart.controls, "Workload", attacks.map(function (a) { return { value: a, label: names[a] || a }; }), state.attack, function (v) {
      state.attack = v;
      chart.play();
      if (reducedMotion()) chart.render();
    });
    var desc = el("p", { class: "mp-sub" }, chart.extra);
    chart.render = function () {
      var per = d.memory[state.attack];
      var conns = d.settings[state.attack + "-connections"];
      var text = {
        slowread: conns + " clients each ask for a " + size(d.settings["slowread-bytes"]) + " response and read it at " + size(d.settings["slowread-rate"]) + "/s: the proxy must stop reading from the origin (backpressure) or hold the data.",
        slowloris: conns + " clients trickle their request headers, one line every " + nf0.format(Number(d.settings["slowloris-interval-ms"]) / 1000) + " s.",
        updown: conns + " clients upload and " + conns + " download " + size(d.settings["updown-bytes"]) + " each, in parallel."
      }[state.attack];
      desc.textContent = text || "";
      var maxT = 0;
      var series = [];
      chart.visible().forEach(function (p) {
        var m = per[p.id];
        if (!m || !m.series) return;
        m.series.points.forEach(function (q) { maxT = Math.max(maxT, q[0]); });
        var end = m.series.end;
        var endLabel = !end ? null : end.verdict === "oom"
          ? "out of memory" + (/still running/.test(end.state || "") ? " (kept running)" : "")
          : "crashed";
        series.push({ p: p, points: m.series.points.map(function (q) { return [q[0], q[1], m]; }), end: end, endLabel: endLabel });
      });
      var t = maxT * chart.progress;
      lineChart(chart, series, {
        xMin: 0,
        xMax: niceMax(maxT),
        progress: t / niceMax(maxT),
        yMax: 600,
        yTickCount: 6,
        yCap: { value: 512, label: "512 MB cgroup limit" },
        heightRatio: 0.5,
        xFmt: function (v) { return Math.round(v) + " s"; },
        yFmt: function (v) { return String(Math.round(v)); },
        xTitle: "seconds since the workload started",
        yTitle: "RSS (MB)",
        sortTip: true,
        badge: chart.progress < 1 ? "t = " + Math.round(t) + " s" : null,
        tipHeader: function (x) { return nf1.format(x) + " s into " + (names[state.attack] || state.attack); },
        tipValue: function (s, pt) {
          var m = pt[2];
          var verdicts = Object.keys(m.verdicts).map(function (k) { return k + " ×" + m.verdicts[k]; }).join(", ");
          return nf1.format(pt[1]) + " MB · " + verdicts;
        }
      });
      // Proxies that cannot run this workload are named, not dropped.
      var skipped = chart.visible().filter(function (p) { return per[p.id] && per[p.id].skipped; });
      if (chart.noteEl) chart.noteEl.textContent = chart.spec.note + (skipped.length ? " Not supported here: " + skipped.map(function (p) { return p.label; }).join(", ") + "." : "");
    };
    return chart;
  };

  // --- wiring ---

  function load(url) {
    if (!dataPromise) {
      dataPromise = fetch(url, { credentials: "same-origin" }).then(function (r) {
        if (!r.ok) throw new Error("HTTP " + r.status + " for " + url);
        return r.json();
      });
      dataPromise.catch(function () { dataPromise = null; });
    }
    return dataPromise;
  }

  function init() {
    var nodes = document.querySelectorAll(".mp-perf-chart[data-chart]:not([data-ready])");
    if (!nodes.length) return;
    var src = document.querySelector("[data-perf-src]");
    var url = new URL(src ? src.getAttribute("data-perf-src") : "../../assets/perf/results.json", window.location.href).href;
    charts = charts.filter(function (c) { return c.root.isConnected; });
    load(url).then(function (data) {
      Array.prototype.forEach.call(nodes, function (node) {
        var make = SPECS[node.getAttribute("data-chart")];
        if (!make) return;
        node.setAttribute("data-ready", "");
        try {
          var chart = make(node, data);
          charts.push(chart);
          chart.render();
        } catch (e) {
          node.removeAttribute("data-ready");
          node.textContent = "";
          if (window.console) console.error("performance chart", e);
          return;
        }
      });
      document.documentElement.classList.add("mp-perf-ready");
    }).catch(function (e) {
      // The static charts and tables stay in place.
      if (window.console) console.warn("performance data unavailable: " + e.message);
    });
  }

  if (window.document$ && typeof window.document$.subscribe === "function") {
    window.document$.subscribe(function () {
      document.documentElement.classList.remove("mp-perf-ready");
      init();
    });
  } else if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init);
  } else {
    init();
  }
})();
