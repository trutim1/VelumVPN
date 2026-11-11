import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';
import ts from 'typescript';

const source = await readFile(new URL('../src/server-capabilities.ts', import.meta.url), 'utf8');
const compiled = ts.transpileModule(source, {
  compilerOptions: { module: ts.ModuleKind.ESNext, target: ts.ScriptTarget.ES2022 },
}).outputText;
const { deriveServers, derivePeerChoices, normalizeEndpoint, validatePeerDraft, validatePeerProvisioning, isPeerProvisionable, IMPORTABLE_PROTOCOL_CATALOG } =
  await import(`data:text/javascript;base64,${Buffer.from(compiled).toString('base64')}`);

const profile = (name, endpoint, protocol = 'amnezia_wg_legacy', extraEndpoints = []) => ({
  name, protocol,
  summary: { fingerprint: `public:${name}`, addresses: ['10.8.1.2/32'], endpoints: endpoint ? [endpoint, ...extraEndpoints] : [], awg_parameters: ['S1', 'S2', 'S3', 'S4', 'I1'] },
});
const draft = (server, patch = {}) => ({ name: 'New client', serverId: server.id, protocol: server.protocols[0]?.id ?? '', ...patch });

test('groups imported profiles by endpoint', () => {
  const input = [profile('sample-desktop', 'VPN.Example.com:42015'), profile('sample-linux', ' vpn.example.com:42015 ')];
  const servers = deriveServers(input);
  assert.equal(servers.length, 1);
  assert.equal(servers[0].id, 'vpn.example.com:42015');
  assert.equal(servers[0].label, 'sample-desktop');
  assert.deepEqual(servers[0].profiles, input);
  assert.equal(servers[0].canManagePeers, false);
  assert.equal(servers[0].source, 'imported');
  assert.equal(servers[0].sourceInfoKey, 'server_imported_profiles_only');
});

test('different ports and primary endpoints remain different targets', () => {
  const servers = deriveServers([
    profile('old', 'vpn.example.com:42015', 'amnezia_wg_legacy', ['vpn.example.com:42016']),
    profile('new', 'vpn.example.com:42016', 'amnezia_wg3'),
  ]);
  assert.equal(servers.length, 2);
  assert.deepEqual(servers.map(({ id }) => id), ['vpn.example.com:42015', 'vpn.example.com:42016']);
});

test('missing or malformed primary endpoints remain separate unknown targets', () => {
  const servers = deriveServers([profile('one'), profile('two'), profile('three', 'bad endpoint'), profile('four', '', 'wire_guard', ['valid.example:12'])]);
  assert.equal(servers.length, 4);
  assert.equal(new Set(servers.map(({ id }) => id)).size, 4);
  assert.ok(servers.every(({ endpoint }) => endpoint === null));
  assert.equal(validatePeerDraft(draft(servers[0]), servers).reason, 'endpoint_unavailable');
});

test('protocol choices are only the imported union, never the global catalog or inferred AWG2', () => {
  const servers = deriveServers([
    profile('legacy', 'host.example:42'), profile('v3', 'host.example:42', 'amnezia_wg3'),
    profile('unsupported', 'host.example:42', 'open_vpn'), profile('duplicate', 'host.example:42'),
  ]);
  assert.deepEqual(servers[0].protocols.map(({ id }) => id), ['amnezia_wg_legacy', 'amnezia_wg3']);
  assert.ok(servers[0].protocols.every(({ source }) => source === 'imported'));
  assert.ok(IMPORTABLE_PROTOCOL_CATALOG.every(({ source }) => source === 'catalog'));
  assert.equal(servers[0].protocols[0].labelKey, 'protocol_amnezia_wg_legacy');
  const onlyUnsupported = deriveServers([profile('unsupported', 'host.example:99', 'open_vpn')]);
  assert.deepEqual(onlyUnsupported[0].protocols, []);
});

test('single server and protocol lock to known choices; multiple targets require selection', () => {
  const one = deriveServers([profile('a', 'host.example:42'), profile('b', 'host.example:42')]);
  assert.deepEqual(derivePeerChoices(one), { serverId: one[0].id, serverLocked: true, protocol: 'amnezia_wg_legacy', protocolLocked: true, protocols: one[0].protocols });
  const multiple = deriveServers([profile('a', 'host.example:42'), profile('b', 'host.example:43', 'wire_guard')]);
  assert.deepEqual(derivePeerChoices(multiple), { serverId: '', serverLocked: false, protocol: '', protocolLocked: false, protocols: [] });
  assert.equal(derivePeerChoices(multiple, multiple[1].id).protocol, 'wire_guard');
});

test('a forged arbitrary protocol or server is rejected despite visible choice locks', () => {
  const servers = deriveServers([profile('a', 'host.example:42')]);
  assert.equal(validatePeerDraft(draft(servers[0], { protocol: 'wire_guard' }), servers).reason, 'protocol_unavailable');
  assert.equal(validatePeerDraft(draft(servers[0], { protocol: 'attacker_value' }), servers).reason, 'protocol_unavailable');
  assert.equal(validatePeerDraft(draft(servers[0], { serverId: 'host.example:43' }), servers).reason, 'server_unavailable');
});

test('valid draft normalizes whitespace and counts Unicode code points', () => {
  const servers = deriveServers([profile('a', 'host.example:42')]);
  assert.equal(validatePeerDraft(draft(servers[0], { name: '  Тестовый телефон  ' }), servers).value.name, 'Тестовый телефон');
  assert.equal(validatePeerDraft(draft(servers[0], { name: '😀'.repeat(64) }), servers).valid, true);
  assert.equal(validatePeerDraft(draft(servers[0], { name: '😀'.repeat(65) }), servers).reason, 'name_too_long');
});

test('malicious controls, newlines, bidi overrides and blank names are rejected', () => {
  const servers = deriveServers([profile('a', 'host.example:42')]);
  for (const name of ['admin\nother', '\nadmin', 'a\0b', 'a\tb', 'admin\u202Eevil', 'a\u2028b', 'a\u0085b']) {
    assert.equal(validatePeerDraft(draft(servers[0], { name }), servers).reason, 'name_invalid_characters');
  }
  assert.equal(validatePeerDraft(draft(servers[0], { name: '   ' }), servers).reason, 'name_required');
});

test('an imported valid draft never authorizes provisioning, including a forged boolean', () => {
  const servers = deriveServers([profile('a', 'host.example:42')]);
  const validDraft = draft(servers[0]);
  assert.equal(validatePeerDraft(validDraft, servers).valid, true);
  assert.equal(validatePeerProvisioning(validDraft, servers).reason, 'management_required');
  assert.equal(isPeerProvisionable(validDraft, servers), false);
  servers[0].canManagePeers = true;
  assert.equal(isPeerProvisionable(validDraft, servers), false);
  assert.equal(validatePeerProvisioning(draft(servers[0], { protocol: 'open_vpn' }), servers).reason, 'protocol_unavailable');
});

test('endpoint normalization preserves ports and rejects URL/credential syntax', () => {
  assert.equal(normalizeEndpoint('[2001:0db8::1]:42015'), '[2001:db8::1]:42015');
  assert.equal(normalizeEndpoint('vpn.example:00080'), 'vpn.example:80');
  for (const input of ['https://vpn.example:42', 'user@vpn.example:42', 'vpn.example:0', 'vpn.example:65536', 'vpn.example:42/path', '127.1:42', '127.00.0.1:42', '256.0.0.1:42', 'vpn..example:42', 'vpn.example:42\ntrick', '[::1%25eth0]:42']) {
    assert.equal(normalizeEndpoint(input), null, input);
  }
});
