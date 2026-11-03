// F-001 T-42 (design §6): the API conventions, as Spectral rules over every
// operation of a path item (path-level parameters count). The ruleset is
// .spectral.yaml at the repository root; each rule picks one check.
//
// Exemptions are explicit and carry their reason as a non-empty string:
// x-idempotency-exempt, x-reason-exempt. x-reason-field names the body
// property that carries the reason when it is not `reason`.

const METHODS = ['get', 'put', 'post', 'delete', 'patch'];
const MUTATING = new Set(['put', 'post', 'delete', 'patch']);

function exemption(op, key, at, out) {
  const v = op[key];
  if (v === undefined) return false;
  if (typeof v !== 'string' || v.trim() === '') {
    out.push({ message: `${key} must give the reason as a string`, path: [...at, key] });
  }
  return true;
}

function params(item, op) {
  return [...(item.parameters || []), ...(op.parameters || [])].filter((p) => p && typeof p === 'object');
}

const checks = {
  // Every operation says who may call it.
  permission(item, op, method, at, out) {
    if (op['x-unauthenticated'] === true) return;
    if (typeof op['x-permission'] !== 'string' || op['x-permission'].trim() === '') {
      out.push({ message: 'declare x-permission (or x-unauthenticated: true)', path: at });
    }
  },
  // An operation without a session says so in its security, too.
  unauthenticated(item, op, method, at, out) {
    if (op['x-unauthenticated'] === true && !(Array.isArray(op.security) && op.security.length === 0)) {
      out.push({ message: 'x-unauthenticated operations declare security: []', path: at });
    }
  },
  // Every mutating call requires an Idempotency-Key (design §6).
  idempotency(item, op, method, at, out) {
    if (!MUTATING.has(method) || exemption(op, 'x-idempotency-exempt', at, out)) return;
    const ok = params(item, op).some((p) => p.in === 'header' && p.name === 'Idempotency-Key' && p.required === true);
    if (!ok) out.push({ message: 'mutations require the Idempotency-Key header (or x-idempotency-exempt: <why>)', path: at });
  },
  // Admin mutations take a reason (design §6).
  reason(item, op, method, at, out) {
    if (!MUTATING.has(method) || op['x-unauthenticated'] === true || exemption(op, 'x-reason-exempt', at, out)) return;
    // The reason is `reason`, or the field the operation names with
    // x-reason-field (explanation, justification, comment), which must exist.
    const field = op['x-reason-field'] === undefined ? 'reason' : op['x-reason-field'];
    if (typeof field !== 'string' || field.trim() === '') {
      out.push({ message: 'x-reason-field names the body property that carries the reason', path: [...at, 'x-reason-field'] });
      return;
    }
    const query = params(item, op).some((p) => p.in === 'query' && p.name === field);
    const content = (op.requestBody && op.requestBody.content) || {};
    const body = Object.values(content).some((c) => {
      const s = c && c.schema;
      return !!(s && s.properties && s.properties[field]);
    });
    if (!query && !body) {
      out.push({ message: `admin mutations take a reason (${field}: body property or query parameter), or x-reason-exempt: <why>`, path: at });
    }
  },
  // Out-of-scope ids answer 404 (design §6, AC-25): an operation on an id
  // documents it.
  notFound(item, op, method, at, out) {
    if (!params(item, op).some((p) => p.in === 'path')) return;
    if (!op.responses || !op.responses['404']) out.push({ message: 'operations on an id document 404 (out of scope or missing)', path: [...at, 'responses'] });
  },
  // Every mutation declares its security events (T-37).
  audit(item, op, method, at, out) {
    if (!MUTATING.has(method)) return;
    if (!Array.isArray(op['x-audit-events'])) out.push({ message: 'mutations declare x-audit-events (T-37)', path: at });
  },
  // A summary for every operation: the published reference lists them.
  summary(item, op, method, at, out) {
    if (typeof op.summary !== 'string' || op.summary.trim() === '') out.push({ message: 'operations have a summary', path: at });
  },
};

export default function fairConventions(item, options, context) {
  const out = [];
  const check = checks[options && options.check];
  if (!check) return [{ message: `unknown check ${options && options.check}` }];
  if (!item || typeof item !== 'object') return out;
  for (const method of METHODS) {
    const op = item[method];
    if (op && typeof op === 'object') check(item, op, method, [...context.path, method], out);
  }
  return out;
}
