// MCP authorization conformance checks, TypeScript client: @modelcontextprotocol/client 2.4.0.
// In-process: mocked fetch, no sockets, no network. IDs (CT-xx) are defined in conformance/spec.md.
// Run: npm test
import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as V2 from '@modelcontextprotocol/client';
import * as jose from 'jose';

const HONEST = 'https://as.honest.example';
const OTHER = 'https://as.other.example';
const SERVER = 'https://mcp.example/mcp';
const CB = 'http://localhost:3000/cb';

const json = (o, s = 200) => new Response(JSON.stringify(o), { status: s, headers: { 'content-type': 'application/json' } });
const metaFor = (issuer) => ({ issuer, authorization_endpoint: `${issuer}/authorize`, token_endpoint: `${issuer}/token`, response_types_supported: ['code'] });

// A mocked world: protected-resource metadata, one honest AS (advertising RFC 9207 support), registration, token.
function world({ prmResource = SERVER } = {}) {
  const w = { log: [] };
  w.fetchFn = async (input, init = {}) => {
    const url = String(input instanceof Request ? input.url : input);
    const u = new URL(url);
    w.log.push({ path: u.pathname, body: init.body ? String(init.body) : '' });
    const host = `https://${u.host}`;
    if (u.pathname.startsWith('/.well-known/oauth-protected-resource'))
      return json({ resource: prmResource, authorization_servers: [HONEST] });
    if (u.pathname === '/.well-known/oauth-authorization-server')
      return json({ ...metaFor(host), registration_endpoint: `${host}/register`, authorization_response_iss_parameter_supported: true });
    if (u.pathname === '/register') return json({ client_id: 'CID', redirect_uris: [CB], token_endpoint_auth_method: 'none' }, 201);
    if (u.pathname === '/token') return json({ access_token: 'AT', token_type: 'Bearer' });
    return new Response('nope', { status: 404 });
  };
  return w;
}
function provider(store) {
  return {
    get redirectUrl() { return CB; },
    get clientMetadata() { return { client_name: 't', redirect_uris: [CB], grant_types: ['authorization_code'], response_types: ['code'], token_endpoint_auth_method: 'none' }; },
    state() { return 'S1'; },
    clientInformation() { return store.ci; }, saveClientInformation(ci) { store.ci = ci; },
    tokens() { return store.t; }, saveTokens(x) { store.t = x; },
    redirectToAuthorization(u) { store.redirect = String(u); },
    saveCodeVerifier(v) { store.v = v; }, codeVerifier() { return store.v; },
  };
}
const quiet = async (fn) => { const w = console.warn; console.warn = () => {}; try { return await fn(); } finally { console.warn = w; } };

// CT-02 / CT-03: RFC 9207 handling of `iss` against validated AS metadata (model 02 NO_ISS / ISS_OPTIONAL; R2, R3).
test('CT-02 iss of another AS rejected', () => {
  assert.throws(() => V2.validateAuthorizationResponseIssuer({ iss: OTHER, expectedIssuer: HONEST, issParameterSupported: false }));
});
test('CT-02 matching iss accepted', () => {
  V2.validateAuthorizationResponseIssuer({ iss: HONEST, expectedIssuer: HONEST, issParameterSupported: true });
});
test('CT-03 absent iss rejected when the AS advertises support', () => {
  assert.throws(() => V2.validateAuthorizationResponseIssuer({ iss: undefined, expectedIssuer: HONEST, issParameterSupported: true }));
});
test('CT-03 absent iss accepted when the AS does not advertise support (RFC 9207 section 2.4 table)', () => {
  V2.validateAuthorizationResponseIssuer({ iss: undefined, expectedIssuer: HONEST, issParameterSupported: false });
});

// CT-02 / CT-03 through the auth() orchestrator: the code is not sent to the token endpoint.
test('CT-02 auth(): iss of another AS rejected before any token request', async () => quiet(async () => {
  const w = world(), store = {}, p = provider(store);
  await V2.auth(p, { serverUrl: SERVER, fetchFn: w.fetchFn });
  await assert.rejects(V2.auth(p, { serverUrl: SERVER, authorizationCode: 'C', iss: OTHER, fetchFn: w.fetchFn }));
  assert.ok(!w.log.some((x) => x.path === '/token'));
}));
test('CT-03 auth(): missing iss rejected before any token request when the AS advertises support', async () => quiet(async () => {
  const w = world(), store = {}, p = provider(store);
  await V2.auth(p, { serverUrl: SERVER, fetchFn: w.fetchFn });
  await assert.rejects(V2.auth(p, { serverUrl: SERVER, authorizationCode: 'C', fetchFn: w.fetchFn }));
  assert.ok(!w.log.some((x) => x.path === '/token'));
}));
test('CT-02 auth(): matching iss completes the flow', async () => quiet(async () => {
  const w = world(), store = {}, p = provider(store);
  await V2.auth(p, { serverUrl: SERVER, fetchFn: w.fetchFn });
  assert.equal(await V2.auth(p, { serverUrl: SERVER, authorizationCode: 'C', iss: HONEST, fetchFn: w.fetchFn }), 'AUTHORIZED');
  assert.ok(w.log.some((x) => x.path === '/token'));
}));

// CT-04: AS metadata `issuer` must equal the issuer it was fetched for (RFC 8414 section 3.3; R0, R8).
test('CT-04 metadata issuer mismatch rejected', async () => {
  const fetchFn = async () => json(metaFor(HONEST));       // OTHER serves metadata that claims to be HONEST
  await assert.rejects(V2.discoverAuthorizationServerMetadata(OTHER, { fetchFn }), (e) => e instanceof V2.IssuerMismatchError);
});
test('CT-04 metadata issuer match accepted', async () => {
  const fetchFn = async () => json(metaFor(HONEST));
  const md = await V2.discoverAuthorizationServerMetadata(HONEST, { fetchFn });
  assert.equal(md.issuer, HONEST);
});

// CT-06: RFC 8707 `resource` is sent on /authorize and /token, taken from protected-resource metadata (model 02 NO_RESOURCE; R4).
test('CT-06 resource sent on /authorize and /token, value from PRM', async () => quiet(async () => {
  const w = world(), store = {}, p = provider(store);
  assert.equal(await V2.auth(p, { serverUrl: SERVER, fetchFn: w.fetchFn }), 'REDIRECT');
  assert.equal(new URL(store.redirect).searchParams.get('resource'), SERVER);
  assert.equal(await V2.auth(p, { serverUrl: SERVER, authorizationCode: 'C', iss: HONEST, fetchFn: w.fetchFn }), 'AUTHORIZED');
  const tok = w.log.find((x) => x.path === '/token');
  assert.equal(new URLSearchParams(tok.body).get('resource'), SERVER);
}));
test('CT-06 PRM resource for a different server is refused before any redirect', async () => quiet(async () => {
  const w = world({ prmResource: 'https://other-rs.example/mcp' }), store = {};
  await assert.rejects(V2.auth(provider(store), { serverUrl: SERVER, fetchFn: w.fetchFn }), /does not match expected/);
  assert.equal(store.redirect, undefined);
}));

// CT-07: private_key_jwt assertion `aud` is the validated AS issuer, even if the metadata lists
// another AS's token endpoint (model 06 AUD_TOKEN_ENDPOINT; R12).
test('CT-07 assertion aud = metadata issuer, not the token endpoint listed in the metadata', async () => {
  const { privateKey } = await jose.generateKeyPair('ES256', { extractable: true });
  const jwk = await jose.exportJWK(privateKey);
  const add = V2.createPrivateKeyJwtAuth({ issuer: 'cid', subject: 'cid', privateKey: jwk, alg: 'ES256' });
  const params = new URLSearchParams();
  await add(new Headers(), params, `${HONEST}/token`, { ...metaFor(OTHER), token_endpoint: `${HONEST}/token` });
  assert.equal(jose.decodeJwt(params.get('client_assertion')).aud, OTHER);
});
