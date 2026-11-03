// F-001 T-42: the convention rules catch what they are for. Each case breaks
// testdata/ok.yaml in one way; the named rule must fire on it, and ok.yaml
// itself must lint clean. Run by scripts/openapi-lint.sh.
import { execFileSync } from 'node:child_process';
import { mkdtempSync, readFileSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const root = join(here, '..', '..');
const cli = join(here, 'node_modules', '@stoplight', 'spectral-cli', 'dist', 'index.js');
const ok = readFileSync(join(here, 'testdata', 'ok.yaml'), 'utf8');

const cases = [
  ['ok', null, null],
  ['mutation without Idempotency-Key', 'fair-idempotency-key',
    ['      x-audit-events: [widget.changed]\n      parameters: [{ $ref: "#/components/parameters/IdempotencyKey" }]\n      requestBody:\n        content:\n          application/json:\n            schema: { type: object, properties: { colour',
     '      x-audit-events: [widget.changed]\n      requestBody:\n        content:\n          application/json:\n            schema: { type: object, properties: { colour']],
  ['empty idempotency exemption', 'fair-idempotency-key', ['x-idempotency-exempt: a lookup; it changes nothing', 'x-idempotency-exempt: ""']],
  ['admin mutation without a reason', 'fair-reason', ['colour: { type: string }, reason: { type: string }', 'colour: { type: string }']],
  ['reason field that is not there', 'fair-reason', ['x-reason-field: explanation', 'x-reason-field: justification']],
  ['empty reason exemption', 'fair-reason', ['      x-reason-field: explanation\n', '      x-reason-field: explanation\n      x-reason-exempt: " "\n']],
  ['id without 404', 'fair-not-found', ['        "200": { description: Tuned }\n        "404": { description: "No such widget, or out of reach" }\n', '        "200": { description: Tuned }\n']],
  ['no x-permission', 'fair-permission', ['      x-permission: widget.view\n', '']],
  ['unauthenticated with the session security', 'fair-unauthenticated-security', ['      security: []\n      x-unauthenticated: true', '      x-unauthenticated: true']],
  ['mutation without audit events', 'fair-audit-events', ['      x-permission: widget.manage\n      x-audit-events: [widget.changed]\n      parameters', '      x-permission: widget.manage\n      parameters']],
  ['no summary', 'fair-summary', ['      summary: A widget\n', '']],
  ['no operationId', 'operation-operationId', ['      operationId: getWidget\n', '']],
];

const dir = mkdtempSync(join(tmpdir(), 'fair-spectral-'));
let failed = 0;
try {
  for (const [name, rule, edit] of cases) {
    let doc = ok;
    if (edit) {
      if (doc.split(edit[0]).length !== 2) throw new Error(`${name}: the edit does not apply exactly once`);
      doc = doc.replace(edit[0], edit[1]);
    }
    const file = join(dir, 'case.yaml');
    writeFileSync(file, doc);
    let out;
    try {
      out = execFileSync(process.execPath, [cli, 'lint', file, '--ruleset', join(root, '.spectral.yaml'), '-f', 'json', '--quiet'],
        { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] });
    } catch (e) {
      out = e.stdout; // findings make the CLI exit non-zero
    }
    const codes = JSON.parse(out || '[]').map((r) => r.code);
    const pass = rule === null ? codes.length === 0 : codes.includes(rule);
    console.log(`${pass ? 'ok' : 'FAIL'} - ${name}${rule ? ` (${rule})` : ''}${pass ? '' : `: got ${JSON.stringify(codes)}`}`);
    if (!pass) failed++;
  }
} finally {
  rmSync(dir, { recursive: true, force: true });
}
if (failed) {
  console.error(`${failed} case(s) failed`);
  process.exit(1);
}
