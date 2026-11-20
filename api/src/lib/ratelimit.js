// Sliding window per principal, in memory (per function instance). For hard global limits put Azure Front Door / API Management in front.
export class RateLimiter {
  constructor(defaultPerMinute, now = () => Date.now()) { this.def = defaultPerMinute; this.now = now; this.hits = new Map(); }
  check(id, limit) {
    const max = limit || this.def, t = this.now(), arr = (this.hits.get(id) || []).filter(x => t - x < 60000);
    if (arr.length >= max) { this.hits.set(id, arr); return { ok: false, retryAfter: Math.max(1, Math.ceil((60000 - (t - arr[0])) / 1000)) }; }
    arr.push(t); this.hits.set(id, arr);
    if (this.hits.size > 5000) for (const [k, v] of this.hits) if (!v.length || t - v[v.length - 1] > 60000) this.hits.delete(k);
    return { ok: true };
  }
}
