#!/usr/bin/env node
/*
 * Renders the static fallbacks of the architecture page's animated diagrams
 * (docs/assets/arch/<scene>.svg) from the diagrams themselves, so the two never disagree. It opens
 * the built page in headless Chromium with reduced motion (each diagram shows its last step),
 * copies every panel's SVG with its computed light-scheme styles inlined, puts the panels side by
 * side on an opaque background (readable on light and dark pages alike), and writes one file per
 * diagram. Development only: it needs Playwright, which neither the build nor CI uses.
 *
 *   mkdocs build -d /tmp/site && python3 -m http.server 8000 --directory /tmp/site &
 *   node docs/scripts/render_arch_svgs.js http://127.0.0.1:8000/ docs/assets/arch
 */
"use strict";

const fs = require("fs");
const path = require("path");
const { chromium } = require("playwright");

async function main() {
  const [base, outDir] = process.argv.slice(2);
  if (!base || !outDir) {
    console.error("usage: render_arch_svgs.js <site base url> <output dir>");
    process.exit(2);
  }
  const browser = await chromium.launch();
  const page = await browser.newPage({ viewport: { width: 1200, height: 900 }, reducedMotion: "reduce", colorScheme: "light" });
  await page.goto(new URL("architecture/", base).href, { waitUntil: "networkidle" });
  await page.waitForSelector(".mp-arch[data-ready] svg");
  const files = await page.evaluate(() => {
    const PROPS = ["fill", "stroke", "stroke-width", "opacity", "font-size", "font-weight", "font-family", "fill-opacity", "stroke-linecap"];
    const out = {};
    document.querySelectorAll(".mp-arch[data-scene]").forEach((scene) => {
      const name = scene.getAttribute("data-scene");
      const title = scene.querySelector("h4").textContent;
      const svgs = Array.from(scene.querySelectorAll(".mp-a-panel > svg"));
      const gap = 16;
      let x = 0;
      const height = Math.max(...svgs.map((s) => s.viewBox.baseVal.height));
      const groups = svgs.map((s) => {
        const vb = s.viewBox.baseVal;
        const clone = s.cloneNode(true);
        const src = [s, ...s.querySelectorAll("*")];
        const dst = [clone, ...clone.querySelectorAll("*")];
        src.forEach((el, i) => {
          const d = dst[i];
          const cs = getComputedStyle(el);
          const style = PROPS.map((p) => p + ":" + cs.getPropertyValue(p)).join(";");
          d.setAttribute("style", style);
          d.removeAttribute("class");
          const t = cs.transform;
          if (t && t !== "none") {
            if (el.classList.contains("mp-a-fill")) {
              // A gauge's fill scales from its own left edge: bake the scale into its width.
              const a = new DOMMatrix(t).a;
              d.setAttribute("width", String(parseFloat(el.getAttribute("width")) * a));
            } else {
              d.setAttribute("transform", new DOMMatrix(t).toString());
            }
          }
        });
        const g = document.createElementNS("http://www.w3.org/2000/svg", "g");
        g.setAttribute("transform", "translate(" + x + ",0)");
        while (clone.firstChild) g.appendChild(clone.firstChild);
        x += vb.width + gap;
        return g.outerHTML;
      });
      const width = x - gap;
      const pad = 10;
      out[name] =
        '<svg xmlns="http://www.w3.org/2000/svg" viewBox="' + -pad + " " + -pad + " " + (width + 2 * pad) + " " + (height + 2 * pad) +
        '" width="' + (width + 2 * pad) + '" height="' + (height + 2 * pad) + '" role="img" aria-label="' + title.replace(/"/g, "&quot;") + '">' +
        "<title>" + title.replace(/&/g, "&amp;").replace(/</g, "&lt;") + " (the last step of the animated diagram)</title>" +
        '<rect x="' + -pad + '" y="' + -pad + '" width="' + (width + 2 * pad) + '" height="' + (height + 2 * pad) + '" rx="8" fill="#fcfcfb"/>' +
        groups.join("") + "</svg>\n";
    });
    return out;
  });
  for (const [name, svg] of Object.entries(files)) {
    fs.writeFileSync(path.join(outDir, name + ".svg"), svg);
    console.log("wrote " + path.join(outDir, name + ".svg"));
  }
  await browser.close();
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
