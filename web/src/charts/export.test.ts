// F-006 T-04 (F-006-AC-17; design §7): an exported SVG carries nothing
// that could act in a viewer. The browser escapes text when it serializes
// (web/e2e/results.spec.ts downloads a chart of a scenario named with
// markup); checkExport refuses whatever is not plain drawing.
import assert from "node:assert/strict";
import { test } from "node:test";
import { checkExport, fileName } from "./export.ts";

const ok = `<svg xmlns="http://www.w3.org/2000/svg" width="640" height="400"><rect width="100%" height="100%" fill="rgb(255, 255, 255)"/>` +
  `<path d="M0,0L10,10" stroke="rgb(11, 87, 196)" stroke-dasharray="8 4"/><text x="8" y="20">&lt;script&gt;alert(1)&lt;/script&gt; v1 · Current</text></svg>`;

test("a plain drawing passes, escaped markup in text included", () => {
  assert.deepEqual(checkExport(ok), []);
});

test("anything that acts or loads is refused", () => {
  const cases: Record<string, string> = {
    "script element": `<svg><script>alert(1)</script></svg>`,
    "foreignObject element": `<svg><foreignObject><div/></foreignObject></svg>`,
    "style element": `<svg><style>*{}</style></svg>`,
    "event attribute": `<svg><rect onload="x()"/></svg>`,
    "style attribute": `<svg><rect style="fill:red"/></svg>`,
    "reference outside the file": `<svg><a href="https://example.test/">x</a></svg>`,
    "element that loads or links content": `<svg><image href="#a"/></svg>`,
    "url() outside the file": `<svg><rect fill="url(https://example.test/p.svg#g)"/></svg>`,
    "javascript: URL": `<svg><rect fill="javascript:x"/></svg>`,
    "document type declaration": `<!DOCTYPE svg [<!ENTITY x "y">]><svg/>`,
  };
  for (const [problem, markup] of Object.entries(cases)) {
    assert.ok(checkExport(markup).includes(problem), `${problem}: ${JSON.stringify(checkExport(markup))}`);
  }
  assert.ok(checkExport(`<svg><SCRIPT>x</SCRIPT></svg>`).includes("script element"), "case does not matter");
});

test("file names hold no user text", () => {
  assert.equal(fileName("run", "1a2b3c4d-0000-4000-8000-000000000000", "curve", "png"), "run-1a2b3c4d-curve.png");
  assert.equal(fileName("run", "<x>/../", "a b", "svg"), "run-x-ab.svg");
});
