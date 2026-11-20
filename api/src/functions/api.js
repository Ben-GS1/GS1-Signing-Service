import { app } from '@azure/functions';
import { loadConfig } from '../lib/config.js';
import { createService } from '../lib/service.js';

let service;
function getService(context) {
  if (!service) {
    const config = loadConfig();
    if (!config.ok) context.error(JSON.stringify({ event: 'misconfigured', errors: config.errors }));
    service = createService(config);
  }
  return service;
}

app.http('api', {
  route: 'v1/{*path}',
  methods: ['GET', 'POST', 'OPTIONS'],
  authLevel: 'anonymous',            // authentication is done by the service itself (API key / Entra ID token), see lib/auth.js
  handler: async (request, context) => {
    const headers = Object.fromEntries(request.headers);
    const rawBody = request.method === 'POST' ? await request.text() : '';
    return getService(context).handle(
      { method: request.method, path: '/v1/' + (request.params.path || ''), headers, rawBody }, m => context.log(m));
  },
});
