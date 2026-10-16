/*
 * The interactive charts of the performance page (docs/project/performance.md), drawn in plain SVG
 * from docs/assets/perf/results.json, which loadtest/competitors/aggregate.py writes from the
 * harness's raw results. No number is written in this file: every value on a chart comes from that
 * JSON. A chart is a <div class="mp-perf-chart" data-chart="..."> on the page; anything else on the
 * site is left alone.
 *
 * The rules every chart follows: a value is shown only where it was measured, and a point on a line
 * is always the median of the same runs (each sweep curve stops at the highest offered rate every one
 * of its runs sustained, marked with a ring); with a handful of runs, the runs themselves are shown
 * as dots rather than whiskers; every value can be read without motion (hover or focus a chart and
 * use the arrow keys, or read the tables beside it). The draw-in animation is decoration only.
 *
 * Works with Material's instant navigation (re-initialises on document$), honours
 * prefers-reduced-motion (the final state, no animation), Material's light and dark schemes (CSS
 * tokens in perf.css), keyboard use (every control is a button, checkbox or select; plots take arrow
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

  function present(v) {
    return typeof v === "number" && isFinite(v);
  }

  function fmtMs(v) {
    if (v == null) return "n/a";
    return v >= 100 ? nf0.format(v) + " ms" : v >= 10 ? nf1.format(v) + " ms" : nf2.format(v) + " ms";
  }

  function fmtUs(v) {
    return v == null ? "n/a" : nf0.format(v) + " µs";
  }

  function fmtRate(v) {
    return nf0.format(v) + " req/s";
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
  function niceTicks(max, few) {
    var counts = few ? [4, 3, 2, 5] : [5, 4, 6, 8, 3, 10, 2];
    for (var i = 0; i < counts.length; i++) {
      var step = max / counts[i];
      var e = Math.pow(10, Math.floor(Math.log10(step)));
      var m = Math.round((step / e) * 1000) / 1000;
      if ([1, 2, 2.5, 5, 10].indexOf(m) >= 0) return linTicks(max, counts[i]);
    }
    return linTicks(max, few ? 2 : 4);
  }

  function linTicks(max, n) {
    var out = [];
    for (var i = 0; i <= n; i++) out.push((max * i) / n);
    return out;
  }

  // 1, 2, 5 times each power of ten between min and max.
  function logTicks(min, max) {
    var out = [];
    for (var e = Math.floor(Math.log10(min)); e <= Math.ceil(Math.log10(max)); e++) {
      [1, 2, 5].forEach(function (m) {
        var v = m * Math.pow(10, e);
        if (v >= min * 0.999 && v <= max * 1.001) out.push(v);
      });
    }
    return out;
  }

  function ease(t) {
    return t < 0.5 ? 2 * t * t : 1 - Math.pow(-2 * t + 2, 2) / 2;
  }

  // "a · b · c" of the values that were measured.
  function runList(values, f) {
    return (values || []).filter(present).map(f).join(" · ");
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

  // A small key for the legend: the series' line and marker, or a dot.
  function legendKey(p, line) {
    var s = sv("svg", { width: 22, height: 12, viewBox: "0 0 22 12", "aria-hidden": "true" });
    if (line) sv("line", { x1: 1, y1: 6, x2: 21, y2: 6, stroke: color(p), "stroke-width": p.id === "microproxy" ? 3 : 2, "stroke-linecap": "round" }, s);
    marker(s, line ? SHAPES[p.slot % 8] : "circle", 11, 6, line ? 3.5 : 4.5, color(p), { "stroke-width": 1 });
    return s;
  }

  // A checkbox in the controls row.
  function toggle(parent, label, checked, onChange) {
    var l = el("label", { class: "mp-check" }, parent);
    var box = el("input", { type: "checkbox" }, l);
    box.checked = !!checked;
    l.appendChild(document.createTextNode(label));
    box.addEventListener("change", function () {
      onChange(box.checked);
    });
    return box;
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
    this.noteEl = el("p", { class: "mp-note" }, root, spec.note || "");
    if (!spec.note) this.noteEl.hidden = true;
    this.buildLegend(spec.legendLine !== false);
    var self = this;
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

  Chart.prototype.note = function (text) {
    this.noteEl.textContent = text || "";
    this.noteEl.hidden = !text;
  };

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

  // The draw-in: decoration only, never needed to read a value (and skipped under reduced motion).
  Chart.prototype.play = function () {
    var self = this;
    this.started = true;
    if (reducedMotion()) {
      this.progress = 1;
      this.render();
      return;
    }
    if (this.anim) cancelAnimationFrame(this.anim);
    var dur = this.spec.duration || 1400;
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

  // A fresh SVG at the plot's width; returns {svg, w, h, m (margins), pw, ph}.
  Chart.prototype.canvas = function (heightRatio, margins) {
    var old = this.plot.querySelector("svg");
    if (old) old.remove();
    var w = Math.max(280, Math.round(this.plot.clientWidth || 600));
    var h = Math.round(Math.max(240, Math.min(420, w * heightRatio)));
    var m = Object.assign({ l: 48, r: 14, t: 14, b: 40 }, margins || {});
    var svg = sv("svg", { viewBox: "0 0 " + w + " " + h, width: w, height: h, role: "img", "aria-label": this.spec.title });
    this.plot.insertBefore(svg, this.tip);
    return { svg: svg, w: w, h: h, m: m, pw: w - m.l - m.r, ph: h - m.t - m.b };
  };

  // rows: [{color, value, label, detail}]; values lead, labels follow.
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
      if (r.detail) el("div", { class: "mp-tip-d" }, tip, r.detail);
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
          out.push([a[0] + (p[0] - a[0]) * f, a[1] + (p[1] - a[1]) * f, null, true]);
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

  // Labels placed beside points without overlapping each other: items = [{x, y, text, cls}].
  function placeLabels(c, items, obstacles) {
    var placed = (obstacles || []).slice();
    // The page's own series first, so its label lands nearest its line; then top to bottom.
    items.sort(function (a, b) { return (b.cls === "mp-label") - (a.cls === "mp-label") || a.y - b.y; });
    items.forEach(function (it) {
      var w = it.text.length * 6.4 + 4;
      var right = it.x + 8 + w <= c.m.l + c.pw + c.m.r - 2;
      var x0 = right ? it.x + 8 : it.x - 8 - w;
      var offsets = [-9, 13, -22, 26, -35, 39, -48, 52, -61, 65];
      for (var i = 0; i < offsets.length; i++) {
        var y = it.y + offsets[i];
        if (y < c.m.t + 8 || y > c.m.t + c.ph + 2) continue;
        var box = { x0: x0, x1: x0 + w, y0: y - 10, y1: y + 2 };
        var clash = placed.some(function (b) { return box.x0 < b.x1 && box.x1 > b.x0 && box.y0 < b.y1 && box.y1 > b.y0; });
        if (!clash) {
          placed.push(box);
          sv("text", { class: it.cls || "mp-label", x: right ? x0 : x0 + w, y: y, "text-anchor": right ? "start" : "end" }, c.svg, it.text);
          return;
        }
      }
    });
  }

  /*
   * A line chart with a crosshair. series = [{p, points: [[x, y, info, transient]], runs: [[x, y]],
   * endMark}]: points are medians, runs (optional) each run's value, drawn as small dots behind the
   * lines; a point flagged transient is drawn hollow; endMark rings the last point (the last offered
   * rate every run sustained). opts: xMin, xMax, yMax or yLog {min, max}, xFmt, yFmt, xTitle,
   * yTitle, yRef {value, label} (a reference line), yCap {value, label} (a hard limit), endLabels,
   * tipHeader(x), tipRow(series, point) -> {value, detail}, progress (0..1 of the x range),
   * heightRatio, margins.
   */
  function lineChart(chart, series, opts) {
    var narrow = (chart.plot.clientWidth || 600) < 520;
    var c = chart.canvas(opts.heightRatio || 0.5, Object.assign({ r: opts.endLabels && !narrow ? 96 : 14 }, opts.margins || {}));
    var xMin = opts.xMin || 0;
    // A logarithmic x axis spaces the sweep's geometric steps evenly.
    var tx = opts.xLog ? function (x) { return Math.log(x); } : function (x) { return x; };
    var X = function (x) {
      return c.m.l + (c.pw * (tx(x) - tx(xMin))) / (tx(opts.xMax) - tx(xMin));
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
      yTicks = logTicks(opts.yLog.min, opts.yLog.max);
    } else {
      Y = function (y) {
        return c.m.t + c.ph - (c.ph * Math.min(y, opts.yMax)) / opts.yMax;
      };
      yTicks = opts.yTickCount ? linTicks(opts.yMax, opts.yTickCount) : niceTicks(opts.yMax, c.ph < 220);
    }
    var xTicks = opts.xTicks || (opts.xLog ? logTicks(xMin, opts.xMax) : niceTicks(opts.xMax, c.pw < 360).filter(function (v) { return v >= xMin; }));
    axes(c, yTicks, Y, opts.yFmt, xTicks, X, opts.xFmt, opts.xTitle, opts.yTitle);
    var xLimit = opts.xLog ? Math.exp(tx(xMin) + (tx(opts.xMax) - tx(xMin)) * opts.progress) : xMin + (opts.xMax - xMin) * opts.progress;
    if (opts.progress >= 1) xLimit = Infinity;
    [["yRef", "mp-refline", "mp-ref-text"], ["yCap", "mp-capline", "mp-cap-text"]].forEach(function (k) {
      var ref = opts[k[0]];
      if (!ref) return;
      var cy = Y(ref.value);
      sv("line", { class: k[1], x1: c.m.l, x2: c.m.l + c.pw, y1: cy, y2: cy }, c.svg);
      sv("text", { class: k[2], x: c.m.l + 4, y: cy - 5, "text-anchor": "start" }, c.svg, ref.label);
    });
    // Each run's values first, behind the medians.
    series.forEach(function (s) {
      (s.runs || []).forEach(function (r) {
        if (r[0] > xLimit) return;
        sv("circle", { class: "mp-run", cx: X(r[0]), cy: Y(r[1]), r: 2.6, fill: color(s.p) }, c.svg);
      });
    });
    var drawn = [];
    series.forEach(function (s) {
      var pts = clipTo(s.points, xLimit);
      if (!pts.length) return;
      var main = s.p.id === "microproxy";
      sv("path", { d: pathOf(pts, X, Y), fill: "none", stroke: color(s.p), "stroke-width": main ? 3 : 2, "stroke-linejoin": "round", "stroke-linecap": "round" }, c.svg);
      drawn.push({ s: s, pts: pts, complete: pts.length === s.points.length && !pts[pts.length - 1][3] });
    });
    var labels = [];
    var obstacles = [];
    drawn.forEach(function (d) {
      d.pts.forEach(function (pt) { obstacles.push({ x0: X(pt[0]) - 6, x1: X(pt[0]) + 6, y0: Y(pt[1]) - 6, y1: Y(pt[1]) + 6 }); });
    });
    drawn.forEach(function (d) {
      var shape = SHAPES[d.s.p.slot % 8];
      var main = d.s.p.id === "microproxy";
      d.pts.forEach(function (pt, i) {
        if (pt[3] === true) return; // the interpolated head of an animated line
        var last = d.complete && i === d.pts.length - 1;
        if (last && d.s.endMark) {
          // The last offered rate every run sustained: the knee lies beyond it.
          sv("circle", { cx: X(pt[0]), cy: Y(pt[1]), r: 6, fill: "var(--mp-surface)", stroke: color(d.s.p), "stroke-width": 2.5 }, c.svg);
        } else if (pt[4]) {
          sv("circle", { cx: X(pt[0]), cy: Y(pt[1]), r: 4, fill: "var(--mp-surface)", stroke: color(d.s.p), "stroke-width": 2, "stroke-dasharray": "2 2" }, c.svg);
        } else {
          marker(c.svg, shape, X(pt[0]), Y(pt[1]), main ? 4.5 : 3.6, color(d.s.p));
        }
      });
      if (opts.endLabels !== false && (!narrow || main || opts.endLabels === "all")) {
        var head = d.pts[d.pts.length - 1];
        labels.push({ x: X(head[0]), y: Y(head[1]), text: d.s.p.label, cls: main ? "mp-label" : "mp-label-2" });
      }
    });
    placeLabels(c, labels, obstacles);
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
        var r = opts.tipRow(s, pt);
        rows.push({ color: color(s.p), value: r.value, label: s.p.label, detail: r.detail, y: pt[1] });
      });
      rows.sort(function (a, b) { return a.y - b.y; });
      chart.showTip(X(x), c.m.t + c.ph / 3, opts.tipHeader(x, rows.length), rows);
    }
    function nearest(evt) {
      var r = c.svg.getBoundingClientRect();
      var px = ((evt.clientX - r.left) * c.w) / r.width;
      var best = 0;
      for (var i = 1; i < xs.length; i++) if (Math.abs(X(xs[i]) - px) < Math.abs(X(xs[best]) - px)) best = i;
      return best;
    }
    hit.addEventListener("pointermove", function (evt) { show(nearest(evt)); });
    hit.addEventListener("pointerdown", function (evt) { show(nearest(evt)); });
    hit.addEventListener("pointerleave", function () {
      cross.setAttribute("visibility", "hidden");
      chart.hideTip();
    });
    hit.addEventListener("focus", function () { show(idx < 0 ? xs.length - 1 : idx); });
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

  /*
   * A strip plot: one row per proxy, one dot per run (offset vertically so that equal runs stay
   * visible), a tick at the median with its value. rows = [{p, values, brackets, med, note,
   * tip: [{value, label}]}]; a run's bracket (the range its true value lies in) is a faint bar behind
   * its dot. opts: tickFmt, valueFmt, xTitle, progress.
   */
  function dotPlot(chart, rows, opts) {
    var old = chart.plot.querySelector("svg");
    if (old) old.remove();
    var w = Math.max(280, Math.round(chart.plot.clientWidth || 600));
    var narrow = w < 480;
    var rowH = 34;
    var labelW = narrow ? 92 : Math.min(130, Math.round(w * 0.24));
    var m = { l: labelW, r: narrow ? 52 : 70, t: 6, b: 42 };
    var h = m.t + m.b + rowH * rows.length;
    var svg = sv("svg", { viewBox: "0 0 " + w + " " + h, width: w, height: h, role: "list", "aria-label": chart.spec.title });
    chart.plot.insertBefore(svg, chart.tip);
    var pw = w - m.l - m.r;
    var top = 0;
    rows.forEach(function (r) {
      (r.values || []).forEach(function (v) { if (present(v)) top = Math.max(top, v); });
      (r.brackets || []).forEach(function (b) { if (b) top = Math.max(top, b[1]); });
    });
    var vmax = niceMax(top || 1);
    var X = function (v) { return m.l + (pw * v) / vmax; };
    var f = opts.progress;
    niceTicks(vmax, narrow).forEach(function (v) {
      sv("line", { class: "mp-grid", x1: X(v), x2: X(v), y1: m.t, y2: m.t + rowH * rows.length }, svg);
      sv("text", { class: "mp-tick", x: X(v), y: m.t + rowH * rows.length + 15, "text-anchor": "middle" }, svg, opts.tickFmt(v));
    });
    sv("text", { class: "mp-axis-title", x: m.l + pw / 2, y: h - 6, "text-anchor": "middle" }, svg, opts.xTitle);
    sv("line", { class: "mp-axis", x1: m.l, x2: m.l, y1: m.t, y2: m.t + rowH * rows.length }, svg);
    rows.forEach(function (r, i) {
      var y = m.t + rowH * i + rowH / 2;
      var vals = (r.values || []).filter(present);
      var g = sv("g", { tabindex: 0, role: "listitem", "aria-label": r.p.label + ": " + (vals.length ? opts.aria(r) : r.note || "not measured") }, svg);
      sv("rect", { class: "mp-hit", x: 0, y: y - rowH / 2 + 1, width: w, height: rowH - 2, fill: "transparent", rx: 4 }, g);
      var name = narrow && r.p.label.length > 13 ? r.p.label.replace(/ \(.*\)$/, "") : r.p.label;
      sv("text", { class: r.p.id === "microproxy" ? "mp-label" : "mp-value", x: m.l - 8, y: y + 4, "text-anchor": "end" }, g, name);
      sv("line", { class: "mp-guide", x1: m.l, x2: m.l + pw, y1: y, y2: y }, g);
      if (!vals.length) {
        sv("text", { class: "mp-value", x: m.l + 6, y: y + 4 }, g, r.note || "not measured");
      } else {
        var n = r.values.length;
        var spacing = n > 1 ? Math.min(6, 20 / (n - 1)) : 0;
        r.values.forEach(function (v, k) {
          if (!present(v)) return;
          var dy = (k - (n - 1) / 2) * spacing;
          var b = (r.brackets || [])[k];
          if (b && f >= 1) sv("rect", { x: X(b[0]), y: y + dy - 2, width: Math.max(1, X(b[1]) - X(b[0])), height: 4, rx: 2, fill: color(r.p), "fill-opacity": 0.3 }, g);
          sv("circle", { cx: m.l + (X(v) - m.l) * f, cy: y + dy, r: 4.5, fill: color(r.p), stroke: "var(--mp-surface)", "stroke-width": 1.5 }, g);
        });
        if (present(r.med) && f >= 1) {
          sv("line", { class: "mp-medtick", x1: X(r.med), x2: X(r.med), y1: y - 12, y2: y + 12 }, g);
          var right = Math.max.apply(null, vals.map(X).concat((r.brackets || []).filter(Boolean).map(function (b) { return X(b[1]); })));
          sv("text", { class: "mp-value", x: right + 8, y: y + 4 }, g, opts.valueFmt(r.med));
        }
      }
      function tip() {
        if (!vals.length) return;
        var rowsT = [{ color: color(r.p), value: opts.valueFmt(r.med), label: "median of " + vals.length + " run" + (vals.length > 1 ? "s" : "") }];
        r.values.forEach(function (v, k) {
          if (!present(v)) return;
          var b = (r.brackets || [])[k];
          rowsT.push({ color: "transparent", value: opts.valueFmt(v), label: "run " + (k + 1) + (b ? " · offered " + nf0.format(b[0]) + " held, " + nf0.format(b[1]) + " not" : "") });
        });
        chart.showTip(Math.min(w - 40, X(Math.max.apply(null, vals))), y, r.p.label, rowsT.concat(r.tip || []));
      }
      g.addEventListener("pointerenter", tip);
      g.addEventListener("focus", tip);
      g.addEventListener("pointerleave", function () { chart.hideTip(); });
      g.addEventListener("blur", function () { chart.hideTip(); });
    });
  }

  // --- the sweep's data ---

  // A proxy's sweep steps on its curve: every run used sustained the offered rate (see aggregate.py).
  function curve(d, p) {
    var s = d.sweep[p.id];
    return s && !s.unsupported ? s.steps.filter(function (st) { return st.inCurve; }) : [];
  }

  function sweepRuns(d, p) {
    return (d.sweep[p.id].runs || []).filter(function (r) { return r.included; });
  }

  function excludedNote(d) {
    var parts = d.proxies.filter(function (p) {
      return (d.sweep[p.id].runs || []).some(function (r) { return !r.included; });
    }).map(function (p) {
      var rs = d.sweep[p.id].runs;
      return p.label + " " + sweepRuns(d, p).length + " of " + rs.length;
    });
    return parts.length ? " Runs whose sweep the load generator ended are left out (runs used: " + parts.join("; ") + ")." : "";
  }

  function curveSeries(d, p, key, withRuns) {
    var s = d.sweep[p.id];
    var steps = curve(d, p).filter(function (st) { return st[key]; });
    var runs = [];
    if (withRuns) {
      steps.forEach(function (st) {
        ((st.perRun || {})[key] || []).forEach(function (v) { if (present(v)) runs.push([st.rate, v]); });
      });
    }
    return {
      p: p,
      points: steps.map(function (st) { return [st.rate, st[key].med, st, false, st.sustained < st.runs]; }),
      runs: runs,
      endMark: s.curveEndRate != null
    };
  }

  function curveTip(d, key, f) {
    return function (s, pt) {
      var st = pt[2];
      var parts = [];
      var each = runList((st.perRun || {})[key], f);
      if (st.runs > 1 && each) parts.push("runs " + each);
      if (st.sustained < st.runs) parts.push("not sustained in " + (st.runs - st.sustained) + " of " + st.runs + " runs");
      var sw = d.sweep[s.p.id];
      if (pt[0] === sw.curveEndRate && sw.maxSustainable) parts.push("last rate every run sustained; max sustainable " + nf0.format(sw.maxSustainable.med) + " req/s");
      return { value: f(pt[1]), detail: parts.join(" · ") };
    };
  }

  function rateDomain(d, key) {
    var top = 0;
    var bottom = Infinity;
    d.proxies.forEach(function (p) {
      curve(d, p).forEach(function (st) {
        if (!st[key]) return;
        top = Math.max(top, st.rate);
        bottom = Math.min(bottom, st.rate);
      });
    });
    // A little room either side of the first and last step, on the logarithmic axis.
    return { min: bottom === Infinity ? 1 : bottom / 1.15, max: (top || 1) * 1.15 };
  }

  // The highest (and lowest) median, and each run's value when shown, of a measure on the curves.
  function valueDomain(d, key, withRuns) {
    var lo = Infinity;
    var hi = 0;
    d.proxies.forEach(function (p) {
      curve(d, p).forEach(function (st) {
        if (!st[key]) return;
        lo = Math.min(lo, withRuns ? st[key].min : st[key].med);
        hi = Math.max(hi, withRuns ? st[key].max : st[key].med);
      });
    });
    return { lo: lo === Infinity ? 1 : lo, hi: hi || 1 };
  }

  // --- the charts ---

  var SPECS = {};

  SPECS.cpu = function (root, d) {
    var state = { runs: false };
    var sampled = d.proxies.some(function (p) {
      return curve(d, p).some(function (st) { return /sampled/.test(st.cpuSource || ""); });
    });
    var chart = new Chart(root, d, {
      title: "Proxy CPU time per request (µs, lower is better)",
      sub: "The CPU time each proxy process spends per completed request (every thread: the JVMs' garbage collector and JIT compiler included), at each offered rate of the rate sweep. Each proxy has one CPU, so at N µs a request it can serve at most 1,000,000 ÷ N requests a second. Median of the runs; each line stops at the last offered rate every run sustained (ring).",
      note: (sampled ? "These runs predate the harness's per-step CPU time: each value is the step's mean sampled CPU% divided by its achieved rate." : "Read from /proc before and after each step.") + " A dashed ring marks a step one run did not sustain (a lone noisy step the sweep recovered from)." + excludedNote(d)
    });
    toggle(chart.controls, "Show each run", false, function (v) {
      state.runs = v;
      chart.render();
    });
    var dom = rateDomain(d, "cpuUsPerReq");
    chart.render = function () {
      var series = chart.visible().map(function (p) { return curveSeries(d, p, "cpuUsPerReq", state.runs); });
      lineChart(chart, series, {
        xMin: dom.min,
        xMax: dom.max,
        xLog: true,
        progress: chart.progress,
        yMax: niceMax(valueDomain(d, "cpuUsPerReq", state.runs).hi * 1.05),
        heightRatio: 0.52,
        endLabels: true,
        xFmt: compact,
        yFmt: function (v) { return String(Math.round(v)); },
        xTitle: "offered load (requests/s, log scale)",
        yTitle: "CPU per request (µs)",
        tipHeader: function (x) { return fmtRate(x) + " offered · CPU per request"; },
        tipRow: curveTip(d, "cpuUsPerReq", fmtUs)
      });
    };
    return chart;
  };

  SPECS.maxrate = function (root, d) {
    var factor = Number(d.settings["sweep-factor"] || 1.25);
    var unrefined = d.proxies.some(function (p) { return sweepRuns(d, p).some(function (r) { return !r.refined; }); });
    var widths = [];
    d.proxies.forEach(function (p) { if (d.sweep[p.id].bracketWidth != null) widths.push(d.sweep[p.id].bracketWidth); });
    var chart = new Chart(root, d, {
      title: "Max sustainable rate (requests/s, higher is better)",
      sub: "The highest offered rate each proxy kept within a p99 of " + d.sloP99Ms + " ms, with no errors and no backlog, on one CPU. Each dot is one run; the tick is the median.",
      note: (unrefined
        ? "Not refined: these runs predate knee refinement, so each run's maximum is known only to within one ×" + factor + " sweep step, the faint bar behind its dot. Equal dots mean the same step, not the same rate."
        : "The faint bar behind each dot is the range of offered rates the run's maximum lies in (at most " + nf1.format(Math.max.apply(null, widths.concat([0])) * 100) + "% wide).") + excludedNote(d),
      legendLine: false,
      duration: 900
    });
    chart.render = function () {
      var rows = chart.visible().map(function (p) {
        var s = d.sweep[p.id];
        var runs = sweepRuns(d, p);
        var out = (s.runs || []).length - runs.length;
        return {
          p: p,
          values: runs.map(function (r) { return r.max; }),
          brackets: runs.map(function (r) { return r.bracket; }),
          med: s.maxSustainable ? s.maxSustainable.med : null,
          note: s.unsupported ? "not supported" : "none sustained",
          tip: out ? [{ color: "transparent", value: String(out), label: "run" + (out > 1 ? "s" : "") + " left out (load generator behind)" }] : null
        };
      });
      dotPlot(chart, rows, {
        progress: chart.progress,
        tickFmt: compact,
        xTitle: "requests per second",
        valueFmt: function (v) { return nf0.format(v) + "/s"; },
        aria: function (r) { return "median " + nf0.format(r.med) + " requests per second; runs: " + runList(r.values, nf0.format); }
      });
    };
    return chart;
  };

  SPECS.latency = function (root, d) {
    var state = { metric: "p99", log: true, runs: false };
    var names = { p50: "p50", p99: "p99", p999: "p99.9" };
    var chart = new Chart(root, d, {
      title: "Latency below each proxy's knee (lower is better)",
      sub: "Latency at each offered rate a proxy sustained in every run, measured from each request's intended send time (no coordinated omission). Median of the runs; each line stops at the last offered rate every run sustained (ring): past it, a proxy is overloaded and its latency is its queue.",
      note: "Logarithmic latency axis: equal distances are equal ratios. A dashed ring marks a step one run did not sustain (a lone noisy step the sweep recovered from)." + excludedNote(d)
    });
    segmented(chart.controls, "Percentile", [{ value: "p50", label: "p50" }, { value: "p99", label: "p99" }, { value: "p999", label: "p99.9" }], "p99", function (v) {
      state.metric = v;
      chart.render();
    });
    segmented(chart.controls, "Axis", [{ value: true, label: "log" }, { value: false, label: "linear" }], true, function (v) {
      state.log = v;
      chart.note(v ? chart.spec.note : "Linear latency axis. A dashed ring marks a step one run did not sustain (a lone noisy step the sweep recovered from)." + excludedNote(d));
      chart.render();
    });
    toggle(chart.controls, "Show each run", false, function (v) {
      state.runs = v;
      chart.render();
    });
    var dom = rateDomain(d, "p99");
    chart.render = function () {
      var key = state.metric;
      var series = chart.visible().map(function (p) { return curveSeries(d, p, key, state.runs); });
      var vd = valueDomain(d, key, state.runs);
      var lo = vd.lo;
      var hi = key === "p99" ? Math.max(vd.hi, d.sloP99Ms) : vd.hi;
      lineChart(chart, series, {
        xMin: dom.min,
        xMax: dom.max,
        xLog: true,
        progress: chart.progress,
        yLog: state.log ? { min: Math.pow(10, Math.floor(Math.log10(Math.max(lo, 0.01)))), max: Math.pow(10, Math.ceil(Math.log10(Math.max(hi, 1)))) } : null,
        yMax: niceMax(hi * 1.05),
        yRef: key === "p99" ? { value: d.sloP99Ms, label: "SLO: p99 " + d.sloP99Ms + " ms" } : null,
        heightRatio: 0.52,
        endLabels: true,
        xFmt: compact,
        yFmt: function (v) { return v < 1 ? String(v) : compact(v); },
        xTitle: "offered load (requests/s, log scale)",
        yTitle: names[key] + " latency (ms)",
        tipHeader: function (x, n) { return fmtRate(x) + " offered · " + names[key] + (n > 1 ? " · lowest first" : ""); },
        tipRow: curveTip(d, key, fmtMs)
      });
    };
    return chart;
  };

  SPECS.percentiles = function (root, d) {
    var rates = [];
    d.proxies.forEach(function (p) {
      curve(d, p).forEach(function (s) { if (s.percentiles && rates.indexOf(s.rate) < 0) rates.push(s.rate); });
    });
    rates.sort(function (a, b) { return a - b; });
    var state = { rate: d.commonRate || rates[0] };
    var chart = new Chart(root, d, {
      title: "Latency by percentile at one offered rate (lower is better)",
      sub: "The whole latency distribution at one offered rate, as an HDR-style plot: each step right adds a nine (90%, 99%, 99.9%, …), so the far right is the tail and the maximum. Per-percentile median of the runs; only proxies that sustained the rate in every run are drawn.",
      note: "",
      duration: 1200
    });
    var label = el("label", null, chart.controls, "Offered rate ");
    var select = el("select", { class: "mp-select" }, label);
    rates.forEach(function (r) {
      el("option", { value: r, selected: r === state.rate ? "" : null }, select, nf0.format(r) + " req/s" + (r === d.commonRate ? " (highest every proxy sustained)" : ""));
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
      var past = [];
      var series = [];
      chart.visible().forEach(function (p) {
        var s = curve(d, p).find(function (x) { return x.rate === state.rate; });
        if (!s || !s.percentiles) {
          if (!d.sweep[p.id].unsupported) past.push(p.label);
          return;
        }
        series.push({ p: p, points: s.percentiles.map(function (q) { return [nines(q[0]), q[1], q]; }) });
      });
      var maxY = 0;
      series.forEach(function (s) { s.points.forEach(function (pt) { maxY = Math.max(maxY, pt[1]); }); });
      var names = { 0: "min", 1: "90%", 2: "99%", 3: "99.9%", 4: "99.99%", 5: "99.999%", 5.6: "max" };
      var narrow = (chart.plot.clientWidth || 600) < 480;
      lineChart(chart, series, {
        xMin: 0,
        xMax: 5.6,
        progress: chart.progress,
        yMax: niceMax(maxY * 1.05),
        heightRatio: 0.48,
        endLabels: false,
        xTicks: narrow ? [0, 2, 4, 5.6] : [0, 1, 2, 3, 4, 5, 5.6],
        xFmt: function (v) { return names[v] || ""; },
        yFmt: function (v) { return String(Math.round(v * 10) / 10); },
        xTitle: "percentile",
        yTitle: "latency (ms)",
        tipHeader: function (x) {
          var any = series.find(function (s) { return s.points.find(function (q) { return q[0] === x; }); });
          var q = any ? any.points.find(function (q2) { return q2[0] === x; })[2] : null;
          return (q ? (q[0] >= 100 ? "maximum" : q[0] <= 0 ? "minimum" : q[0] + "th percentile") : "") + " at " + fmtRate(state.rate);
        },
        tipRow: function (s, pt) {
          var q = pt[2];
          return { value: fmtMs(q[1]), detail: q[2] !== q[3] ? "runs from " + fmtMs(q[2]) + " to " + fmtMs(q[3]) : "" };
        }
      });
      chart.note("The percentile axis is logarithmic in 1/(1 − percentile), the usual way to show latency tails; the latency axis is linear." + (past.length ? " Past their knee at this rate in some run, so not drawn: " + past.join(", ") + "." : ""));
    };
    return chart;
  };

  SPECS.idle = function (root, d) {
    var chart = new Chart(root, d, {
      title: "Idle memory: resident set size (MB, lower is better)",
      sub: "RSS after start-up and a few validation requests, before any load: what the OS charges for the proxy doing nothing. Each dot is one run; the tick is the median.",
      note: "The JVM proxies' RSS depends on heap sizing (here -Xmx1g, G1, Native Memory Tracking on); a native process has no such floor.",
      legendLine: false,
      duration: 900
    });
    chart.render = function () {
      dotPlot(chart, chart.visible().map(function (p) {
        var st = d.ramp[p.id].idleRssMb;
        return { p: p, values: st ? st.values : [], med: st ? st.med : null };
      }), {
        progress: chart.progress,
        tickFmt: function (v) { return Math.round(v) + " MB"; },
        xTitle: "resident set size (MB)",
        valueFmt: function (v) { return nf1.format(v) + " MB"; },
        aria: function (r) { return "median " + nf1.format(r.med) + " megabytes; runs: " + runList(r.values, nf1.format); }
      });
    };
    return chart;
  };

  SPECS.ramp = function (root, d) {
    var state = { runs: false };
    var chart = new Chart(root, d, {
      title: "Memory as idle keep-alive connections pile up (lower is better)",
      sub: "RSS while the load generator opens idle keep-alive connections in steps, each after one request (so the proxy has also connected upstream). Median of " + d.runs.length + " runs.",
      note: "The largest step is bounded by this container's open-file limit, not by any proxy. Proxies that pool upstream connections (Envoy, goproxy, Squid) keep fewer upstream sockets than those that hold one per client connection.",
      duration: 1400
    });
    toggle(chart.controls, "Show each run", false, function (v) {
      state.runs = v;
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
        var runs = [];
        if (state.runs) steps.forEach(function (s) { (s.rssMb.values || []).forEach(function (v) { runs.push([s.held.med, v]); }); });
        return { p: p, points: steps.map(function (s) { return [s.held.med, s.rssMb.med, s]; }), runs: runs };
      });
      lineChart(chart, series, {
        xMin: 0,
        xMax: niceMax(maxX),
        progress: chart.progress,
        yMax: niceMax(maxY * 1.05),
        heightRatio: 0.48,
        endLabels: true,
        xFmt: compact,
        yFmt: function (v) { return String(Math.round(v)); },
        xTitle: "idle connections held",
        yTitle: "RSS (MB)",
        tipHeader: function (x) { return nf0.format(x) + " idle connections"; },
        tipRow: function (s, pt) {
          var st = pt[2].rssMb;
          return { value: nf1.format(st.med) + " MB", detail: st.n > 1 ? "runs " + runList(st.values, nf1.format) : "" };
        }
      });
    };
    return chart;
  };

  SPECS.race = function (root, d) {
    var attacks = Object.keys(d.memory);
    var names = { slowread: "slow readers", slowloris: "slowloris", updown: "large uploads and downloads" };
    var state = { attack: attacks.indexOf("slowread") >= 0 ? "slowread" : attacks[0] };
    var baseNote = "✕ marks a proxy that ran out of memory (an OutOfMemoryError, or the cgroup's OOM killer) or crashed. Samples are 5 s apart. The verdicts and per-connection figures are in the table below.";
    var gone = Object.keys(d.memoryNotMeasured || {});
    if (gone.length) {
      baseNote += " Not measured on this machine: " + gone.map(function (a) { return names[a] || a; }).join(", ") + " (the reason is under the table).";
    }
    var chart = new Chart(root, d, {
      title: "Memory under adversarial clients, in a 512 MB cgroup (lower is better)",
      sub: "RSS over time while the workload runs, every proxy's memory capped at 512 MB in a memory cgroup (the JVMs additionally capped at a 256 MB heap and 128 MB of direct memory inside it; the kernel's socket buffers for the proxy's connections are kept out of the cap where the table shows them). One line per proxy: the run with the median peak.",
      note: baseNote,
      duration: 1800
    });
    segmented(chart.controls, "Workload", attacks.map(function (a) { return { value: a, label: names[a] || a }; }), state.attack, function (v) {
      state.attack = v;
      chart.render();
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
        series.push({ p: p, points: m.series.points.map(function (q) { return [q[0], q[1], m]; }), end: m.series.end });
      });
      var c = lineChart(chart, series, {
        xMin: 0,
        xMax: niceMax(maxT),
        progress: chart.progress,
        yMax: 600,
        yTickCount: 6,
        yCap: { value: 512, label: "512 MB cgroup limit" },
        heightRatio: 0.5,
        endLabels: true,
        xFmt: function (v) { return Math.round(v) + " s"; },
        yFmt: function (v) { return String(Math.round(v)); },
        xTitle: "seconds since the workload started",
        yTitle: "RSS (MB)",
        tipHeader: function (x) { return nf1.format(x) + " s into " + (names[state.attack] || state.attack); },
        tipRow: function (s, pt) {
          var m = pt[2];
          return { value: nf1.format(pt[1]) + " MB", detail: Object.keys(m.verdicts).map(function (k) { return k + " ×" + m.verdicts[k]; }).join(", ") };
        }
      });
      // Out of memory or crashed: a cross at the line's end, named in the note and the tooltip.
      var failed = [];
      series.forEach(function (s) {
        if (!s.end || chart.progress < 1) return;
        var last = s.points[s.points.length - 1];
        var ex = c.m.l + (c.pw * last[0]) / niceMax(maxT);
        var ey = c.m.t + c.ph - (c.ph * Math.min(last[1], 600)) / 600;
        var d7 = "M" + (ex - 7) + " " + (ey - 7) + "L" + (ex + 7) + " " + (ey + 7) + "M" + (ex + 7) + " " + (ey - 7) + "L" + (ex - 7) + " " + (ey + 7);
        sv("path", { d: d7, stroke: "var(--mp-surface)", "stroke-width": 6, "stroke-linecap": "round" }, c.svg);
        sv("path", { d: d7, stroke: color(s.p), "stroke-width": 3, "stroke-linecap": "round" }, c.svg);
        failed.push(s.p.label + " " + (s.end.verdict === "oom" ? "ran out of memory" + (/still running/.test(s.end.state || "") ? " (and kept running)" : "") : "crashed"));
      });
      var skipped = chart.visible().filter(function (p) { return per[p.id] && per[p.id].skipped; });
      chart.note(baseNote + (failed.length ? " Here: " + failed.join("; ") + "." : "") + (skipped.length ? " Not supported here: " + skipped.map(function (p) { return p.label; }).join(", ") + "." : ""));
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
