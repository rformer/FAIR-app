// F-006 T-04 (F-006-AC-17; design §4, §6.3; ADR-014): SVG and PNG exports
// of a drawn chart. The chart is cloned, the theme's computed colours and
// fonts are written onto it as presentation attributes (no style
// attributes or elements), a footer with the download's facts is added as
// text nodes, and the result is serialized by the browser (which escapes
// text). checkExport refuses anything that could act in a viewer: script,
// foreignObject, event attributes, style, and references outside the
// file. PNG output draws the checked SVG on a canvas through a data: URL
// (the UI's CSP allows `img-src 'self' data:`).

/** Problems that make an exported SVG unsafe to hand out; empty when safe. */
export function checkExport(markup: string): string[] {
  const out: string[] = [];
  const lower = markup.toLowerCase();
  if (/<script[\s>/]/.test(lower)) out.push("script element");
  if (/<foreignobject[\s>/]/.test(lower)) out.push("foreignObject element");
  if (/<style[\s>/]/.test(lower)) out.push("style element");
  if (/<(iframe|object|embed|image|use|a)[\s>/]/.test(lower)) out.push("element that loads or links content");
  if (/\son[a-z]+\s*=/.test(lower)) out.push("event attribute");
  if (/\sstyle\s*=/.test(lower)) out.push("style attribute");
  if (/(?:href|src)\s*=\s*["'](?!#)/.test(lower)) out.push("reference outside the file");
  if (/url\(\s*["']?(?!#)/.test(lower)) out.push("url() outside the file");
  if (/javascript:/.test(lower)) out.push("javascript: URL");
  if (/<!doctype|<!entity/.test(lower)) out.push("document type declaration");
  return out;
}

/** The presentation properties written onto each exported element. */
const PROPS = [
  "fill",
  "fill-opacity",
  "stroke",
  "stroke-width",
  "stroke-dasharray",
  "stroke-opacity",
  "opacity",
  "font-family",
  "font-size",
  "font-weight",
  "text-anchor",
  "dominant-baseline",
] as const;

export interface ExportFooter {
  /** Lines drawn under the chart: title, subject, sets, currency, ids, digests, independence, download id. */
  lines: string[];
}

const LINE = 16;

/**
 * The chart as a standalone, checked SVG document: computed styles inlined,
 * the background drawn, the footer added. Throws when the result fails
 * checkExport (nothing is handed out then).
 */
export function serializeChart(svg: SVGSVGElement, footer: ExportFooter): string {
  const clone = svg.cloneNode(true) as SVGSVGElement;
  const live = [svg, ...Array.from(svg.querySelectorAll("*"))];
  const copies = [clone, ...Array.from(clone.querySelectorAll("*"))];
  copies.forEach((el, i) => {
    const src = live[i];
    if (!src) return;
    const cs = getComputedStyle(src);
    for (const p of PROPS) {
      const v = cs.getPropertyValue(p);
      if (v && v !== "normal" && v !== "auto") el.setAttribute(p, v);
    }
    el.removeAttribute("class");
    el.removeAttribute("style");
    el.removeAttribute("tabindex");
    el.removeAttribute("focusable");
    for (const a of Array.from(el.attributes)) {
      if (a.name.startsWith("on") || a.name.startsWith("aria-") || a.name === "role") el.removeAttribute(a.name);
    }
  });
  for (const el of Array.from(clone.querySelectorAll("script, foreignObject, style, title"))) el.remove();

  const vb = svg.viewBox.baseVal;
  const width = vb && vb.width ? vb.width : svg.clientWidth || 640;
  const height = vb && vb.height ? vb.height : svg.clientHeight || 320;
  const extra = LINE * (footer.lines.length + 1);
  const ns = "http://www.w3.org/2000/svg";
  const root = document.createElementNS(ns, "svg");
  root.setAttribute("xmlns", ns);
  root.setAttribute("width", String(width));
  root.setAttribute("height", String(height + extra));
  root.setAttribute("viewBox", `0 0 ${width} ${height + extra}`);
  const page = getComputedStyle(document.body);
  const bg = document.createElementNS(ns, "rect");
  bg.setAttribute("width", "100%");
  bg.setAttribute("height", "100%");
  bg.setAttribute("fill", page.backgroundColor || "#ffffff");
  root.appendChild(bg);
  clone.removeAttribute("width");
  clone.removeAttribute("height");
  clone.setAttribute("width", String(width));
  clone.setAttribute("height", String(height));
  root.appendChild(clone);
  footer.lines.forEach((line, i) => {
    const t = document.createElementNS(ns, "text");
    t.setAttribute("x", "8");
    t.setAttribute("y", String(height + LINE * (i + 1)));
    t.setAttribute("font-size", "11");
    t.setAttribute("font-family", page.fontFamily || "sans-serif");
    t.setAttribute("fill", page.color || "#1b1f24");
    t.textContent = line;
    root.appendChild(t);
  });
  const markup = new XMLSerializer().serializeToString(root);
  const problems = checkExport(markup);
  if (problems.length > 0) throw new Error(`the export is not safe: ${problems.join(", ")}`);
  return markup;
}

/** The SVG drawn as PNG at `scale` times its size. */
export async function pngOf(markup: string, scale = 2): Promise<Blob> {
  const img = new Image();
  const loaded = new Promise<void>((resolve, reject) => {
    img.onload = () => resolve();
    img.onerror = () => reject(new Error("the chart could not be drawn as an image"));
  });
  img.src = `data:image/svg+xml;charset=utf-8,${encodeURIComponent(markup)}`;
  await loaded;
  const canvas = document.createElement("canvas");
  canvas.width = Math.ceil(img.width * scale);
  canvas.height = Math.ceil(img.height * scale);
  const ctx = canvas.getContext("2d");
  if (!ctx) throw new Error("no canvas");
  ctx.scale(scale, scale);
  ctx.drawImage(img, 0, 0);
  return new Promise((resolve, reject) => canvas.toBlob((b) => (b ? resolve(b) : reject(new Error("no PNG"))), "image/png"));
}

/** Saves data under name through a temporary link. */
export function save(data: Blob, name: string): void {
  const url = URL.createObjectURL(data);
  const a = document.createElement("a");
  a.href = url;
  a.download = name;
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 10_000);
}

/** A file name with no user text: subject, the id's first 8 characters, view, extension. */
export function fileName(subject: string, id: string, view: string, ext: string): string {
  const safe = (s: string) => s.replace(/[^a-z0-9-]/gi, "").slice(0, 32);
  return `${safe(subject)}-${safe(id).slice(0, 8)}-${safe(view)}.${ext}`;
}
