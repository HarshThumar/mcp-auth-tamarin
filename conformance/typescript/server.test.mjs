// MCP authorization conformance checks, TypeScript server side: @modelcontextprotocol/sdk 1.32.2.
// In-process: the bearer-auth middleware is called with fake request/response objects. No sockets, no network.
// IDs (CT-xx) are defined in conformance/spec.md. Run: npm test
import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as V1x from '@modelcontextprotocol/sdk/client/auth-extensions.js';
import { requireBearerAuth } from '@modelcontextprotocol/sdk/server/auth/middleware/bearerAuth.js';
import * as jose from 'jose';

const SERVER = 'https://mcp.example/mcp';
const HONEST = 'https://as.honest.example';
const OTHER = 'https://as.other.example';

// CT-01: resource-server audience check (model 02 NO_AUD, R1; GHSA-w4fh-qvv9-3v23, GHSA-rvq5-wwqv-78pq).
// `expectedResource` is opt-in (off by default per the published advisory), so these tests set it.
function runBearer(expectedResource, tokenResource) {
  const verifier = {
    verifyAccessToken: async (token) => ({
      token, clientId: 'c', scopes: [], expiresAt: Math.floor(Date.now() / 1000) + 600, resource: tokenResource,
    }),
  };
  const mw = requireBearerAuth({ verifier, expectedResource });
  const req = { headers: { authorization: 'Bearer t' } };
  const out = { status: 200, nexted: false };
  const res = { set() { return res; }, status(c) { out.status = c; return res; }, json() { return res; } };
  return mw(req, res, () => { out.nexted = true; }).then(() => out);
}

test('CT-01 token for another resource rejected (expectedResource set)', async () => {
  const r = await runBearer(new URL(SERVER), new URL('https://other-rs.example/mcp'));
  assert.equal(r.status, 401);
  assert.equal(r.nexted, false);
});
test('CT-01 token without a resource claim rejected (expectedResource set)', async () => {
  const r = await runBearer(new URL(SERVER), undefined);
  assert.equal(r.status, 401);
  assert.equal(r.nexted, false);
});
test('CT-01 token for this resource accepted (trailing slash tolerated)', async () => {
  assert.equal((await runBearer(new URL(SERVER), new URL(SERVER))).nexted, true);
  assert.equal((await runBearer(new URL(SERVER), new URL(SERVER + '/'))).nexted, true);
});

// CT-07 (same check as in client.test.mjs, for the sdk 1.32.2 client helper): the assertion `aud` is the AS issuer.
test('CT-07 [sdk 1.32.2] assertion aud = metadata issuer, not the token endpoint listed in the metadata', async () => {
  const { privateKey } = await jose.generateKeyPair('ES256', { extractable: true });
  const jwk = await jose.exportJWK(privateKey);
  const add = V1x.createPrivateKeyJwtAuth({ issuer: 'cid', subject: 'cid', privateKey: jwk, alg: 'ES256' });
  const params = new URLSearchParams();
  const md = { issuer: OTHER, authorization_endpoint: `${OTHER}/authorize`, token_endpoint: `${HONEST}/token`, response_types_supported: ['code'] };
  await add(new Headers(), params, `${HONEST}/token`, md);
  assert.equal(jose.decodeJwt(params.get('client_assertion')).aud, OTHER);
});
