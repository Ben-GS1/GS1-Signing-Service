// Small HTTP helpers shared by the router. RFC 9457 problem+json error format.
import { randomUUID } from 'node:crypto';

export class HttpError extends Error {
  constructor(status, title, detail, extra = {}) {
    super(detail || title);
    this.status = status; this.title = title; this.detail = detail; this.extra = extra;
  }
}
export const newRequestId = incoming => (/^[A-Za-z0-9._-]{8,64}$/.test(incoming || '') ? incoming : randomUUID());

export function corsHeaders(origin, allowedOrigins) {
  if (origin === undefined || (!allowedOrigins.includes(origin) && !allowedOrigins.includes('*'))) return {};
  return {
    'Access-Control-Allow-Origin': allowedOrigins.includes('*') ? '*' : origin,
    'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Authorization, Content-Type, X-Api-Key, X-Request-Id',
    'Access-Control-Expose-Headers': 'X-Request-Id, Retry-After, X-Signing-Backend',
    'Access-Control-Max-Age': '600',
    Vary: 'Origin',
  };
}
export const baseHeaders = requestId => ({
  'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff', 'X-Request-Id': requestId,
});
export const json = (status, body, headers = {}) => ({ status, headers: { 'Content-Type': 'application/json; charset=utf-8', ...headers }, body: JSON.stringify(body) });
export const problem = (err, requestId, headers = {}) => ({
  status: err.status,
  headers: { 'Content-Type': 'application/problem+json; charset=utf-8', ...(err.extra?.headers || {}), ...headers },
  body: JSON.stringify({ type: 'about:blank', title: err.title, status: err.status, detail: err.detail, requestId, ...(err.extra?.problems ? { problems: err.extra.problems } : {}) }),
});
