// F-006 T-04 (F-006-AC-15; ADR-014): series colours meet 3:1 against every
// background in both themes, and series differ without colour.
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import { contrast, markerPath, SERIES } from "./palette.ts";

const css = readFileSync(new URL("../styles.css", import.meta.url), "utf8");
const dark = css.slice(css.indexOf("@media (prefers-color-scheme: dark)"));
const light = css.slice(0, css.indexOf("@media (prefers-color-scheme: dark)"));

function token(block: string, name: string): string {
  const m = new RegExp(`${name}:\\s*(#[0-9a-fA-F]{6})`).exec(block);
  assert.ok(m, `${name} is not defined`);
  return m[1]!;
}

for (const [theme, block] of [
  ["light", light],
  ["dark", dark],
] as const) {
  test(`${theme} theme: every series colour has 3:1 against the backgrounds`, () => {
    for (const bg of ["--bg", "--surface", "--surface-2"]) {
      const b = token(block, bg);
      for (const s of SERIES) {
        const c = contrast(token(block, s.token), b);
        assert.ok(c >= 3, `${s.token} on ${bg}: ${c.toFixed(2)}:1`);
      }
    }
  });
}

test("series differ by dash and marker, not only colour", () => {
  assert.equal(SERIES.length, 6);
  assert.equal(new Set(SERIES.map((s) => s.dash)).size, 6);
  assert.equal(new Set(SERIES.map((s) => s.marker)).size, 6);
  assert.equal(new Set(SERIES.map((s) => s.look)).size, 6);
  assert.equal(SERIES[0]!.dash, "", "the first (current) series is solid");
  for (const s of SERIES) assert.match(markerPath(s.marker, 10, 10), /^M/);
});

test("contrast follows WCAG", () => {
  assert.equal(contrast("#000000", "#ffffff").toFixed(0), "21");
  assert.equal(contrast("#777777", "#777777"), 1);
});
