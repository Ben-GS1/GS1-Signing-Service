fetch('/api/v1/health', { cache: 'no-store' }).then(r => r.json().then(b => ({ ok: r.ok, b }))).then(({ ok, b }) => {
  const el = document.getElementById('st');
  el.textContent = ok ? `ok (version ${b.version}, ${b.environment})` : 'misconfigured';
  el.className = ok ? 'ok' : 'bad';
}).catch(() => { const el = document.getElementById('st'); el.textContent = 'unreachable'; el.className = 'bad'; });
