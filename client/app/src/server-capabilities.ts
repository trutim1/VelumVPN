/** Safe summaries returned by the local profile store. No private keys or SSH credentials. */
export type ProfileSummary = {
  fingerprint: string;
  addresses: string[];
  endpoints: string[];
  awg_parameters: string[];
};

export type StoredProfile = { name: string; protocol: string; summary: ProfileSummary };
export type ImportedProtocolId = 'wire_guard' | 'amnezia_wg_legacy' | 'amnezia_wg3';
export type ProtocolLabelKey = 'protocol_wire_guard' | 'protocol_amnezia_wg_legacy' | 'protocol_amnezia_wg3';
export type ImportedProtocol = {
  id: ImportedProtocolId;
  labelKey: ProtocolLabelKey;
  source: 'imported';
};

/** Supported import formats. This catalogue does NOT describe installed server protocols. */
export const IMPORTABLE_PROTOCOL_CATALOG = [
  { id: 'wire_guard', labelKey: 'protocol_wire_guard', source: 'catalog' },
  { id: 'amnezia_wg_legacy', labelKey: 'protocol_amnezia_wg_legacy', source: 'catalog' },
  { id: 'amnezia_wg3', labelKey: 'protocol_amnezia_wg3', source: 'catalog' },
] as const;

export type ServerTarget = {
  id: string;
  /** The first imported profile's label, not a discovered server name. */
  label: string;
  endpoint: string | null;
  profiles: StoredProfile[];
  protocols: ImportedProtocol[];
  canManagePeers: false;
  source: 'imported';
  sourceInfoKey: 'server_imported_profiles_only';
};

/**
 * Only normalizes a complete host:port endpoint. Never resolves DNS or merges
 * endpoints merely because they share a host. Ambiguous/malformed values stay
 * unknown; they cannot accidentally acquire another profile's server identity.
 */
export function normalizeEndpoint(endpoint: string | undefined): string | null {
  if (typeof endpoint !== 'string') return null;
  const input = endpoint.trim();
  if (!input || /[\s\p{Cc}\p{Cf}]/u.test(input)) return null;

  let host: string;
  let portText: string;
  if (input.startsWith('[')) {
    const match = /^\[([0-9a-fA-F:.]+)\]:(\d{1,5})$/.exec(input);
    if (!match) return null;
    try {
      // WHATWG parses bracketed IPv6 without network access. Keep our explicit
      // port below; URL's default-port removal must not affect server identity.
      host = new URL(`http://[${match[1]}]/`).hostname.toLowerCase();
      if (!host.startsWith('[')) return null;
    } catch {
      return null;
    }
    portText = match[2];
  } else {
    const match = /^([^:]+):(\d{1,5})$/.exec(input);
    if (!match) return null;
    host = match[1].toLowerCase();
    portText = match[2];
    // ASCII hostnames / IPv4 only. Do not reinterpret URL credentials, paths,
    // integer IPv4, backslashes, or arbitrary user-supplied schemes as a host.
    if (host.length > 253 || !/^[a-z0-9](?:[a-z0-9.-]*[a-z0-9.])?$/.test(host)) return null;
    const labels = host.replace(/\.$/, '').split('.');
    if (labels.some((label) => label.length === 0 || label.length > 63 || label.startsWith('-') || label.endsWith('-'))) return null;
    if (/^[0-9.]+$/.test(host)) {
      if (labels.length !== 4 || labels.some((label) => !/^(0|[1-9][0-9]{0,2})$/.test(label) || Number(label) > 255)) return null;
    }
  }
  const port = Number(portText);
  if (port < 1 || port > 65535) return null;
  return `${host}:${port}`;
}

export function deriveServers(profiles: readonly StoredProfile[]): ServerTarget[] {
  const groups = new Map<string, ServerTarget>();
  profiles.forEach((profile, index) => {
    // Only the primary peer endpoint identifies this imported target. Secondary
    // endpoints must not merge unrelated servers or imply an inventory scan.
    const endpoint = normalizeEndpoint(profile.summary.endpoints[0]);
    const id = endpoint ?? `unknown:${index}:${encodeURIComponent(profile.name)}`;
    let server = groups.get(id);
    if (!server) {
      server = {
        id,
        label: profile.name,
        endpoint,
        profiles: [],
        protocols: [],
        canManagePeers: false,
        source: 'imported',
        sourceInfoKey: 'server_imported_profiles_only',
      };
      groups.set(id, server);
    }
    server.profiles.push(profile);
    const known = IMPORTABLE_PROTOCOL_CATALOG.find(({ id: protocolId }) => protocolId === profile.protocol);
    if (known && !server.protocols.some(({ id: protocolId }) => protocolId === known.id)) {
      // Parameter names alone cannot reliably distinguish AWG 1 from AWG 2;
      // preserve the legacy label rather than upgrading a user's protocol.
      server.protocols.push({ id: known.id, labelKey: known.labelKey, source: 'imported' });
    }
  });
  return [...groups.values()];
}

export type PeerDraft = { name: string; serverId: string; protocol: string };
export type ValidPeerDraft = { name: string; serverId: string; protocol: ImportedProtocolId };
export type PeerValidationReason =
  | 'name_required'
  | 'name_invalid_characters'
  | 'name_too_long'
  | 'server_required'
  | 'server_unavailable'
  | 'endpoint_unavailable'
  | 'protocol_required'
  | 'protocol_unavailable'
  | 'management_required';
export type PeerValidationFailure = {
  valid: false;
  reason: PeerValidationReason;
  field: keyof PeerDraft;
};
export type PeerValidationResult = { valid: true; value: ValidPeerDraft } | PeerValidationFailure;

/** Local form validation only. A valid draft is NOT permission to create a peer. */
export function validatePeerDraft(draft: PeerDraft, servers: readonly ServerTarget[]): PeerValidationResult {
  if (typeof draft.name !== 'string' || !draft.name.trim()) return { valid: false, reason: 'name_required', field: 'name' };
  if (/[\p{Cc}\p{Cf}\p{Zl}\p{Zp}]/u.test(draft.name)) return { valid: false, reason: 'name_invalid_characters', field: 'name' };
  const name = draft.name.trim();
  if ([...name].length > 64) return { valid: false, reason: 'name_too_long', field: 'name' };
  if (!draft.serverId) return { valid: false, reason: 'server_required', field: 'serverId' };
  const server = servers.find(({ id }) => id === draft.serverId);
  if (!server) return { valid: false, reason: 'server_unavailable', field: 'serverId' };
  if (!server.endpoint) return { valid: false, reason: 'endpoint_unavailable', field: 'serverId' };
  if (!draft.protocol) return { valid: false, reason: 'protocol_required', field: 'protocol' };
  const protocol = server.protocols.find(({ id }) => id === draft.protocol);
  if (!protocol) return { valid: false, reason: 'protocol_unavailable', field: 'protocol' };
  return { valid: true, value: { name, serverId: server.id, protocol: protocol.id } };
}

/**
 * Imported client configs never grant server-management authority. A future
 * authenticated management flow must define and verify its own capabilities;
 * it must not flip this imported-only boolean or trust a client-side object.
 */
export function validatePeerProvisioning(draft: PeerDraft, servers: readonly ServerTarget[]): PeerValidationResult {
  const validation = validatePeerDraft(draft, servers);
  if (!validation.valid) return validation;
  return { valid: false, reason: 'management_required', field: 'serverId' };
}

export function isPeerProvisionable(draft: PeerDraft, servers: readonly ServerTarget[]): boolean {
  return validatePeerProvisioning(draft, servers).valid;
}

/** Select the sole known choice automatically; never invent another server/protocol. */
export function derivePeerChoices(servers: readonly ServerTarget[], serverId = '', protocol = '') {
  const selected = servers.length === 1 ? servers[0] : servers.find(({ id }) => id === serverId);
  const protocols = selected?.protocols ?? [];
  const selectedProtocol = protocols.length === 1 ? protocols[0] : protocols.find(({ id }) => id === protocol);
  return {
    serverId: selected?.id ?? '',
    serverLocked: servers.length === 1,
    protocol: selectedProtocol?.id ?? '',
    protocolLocked: protocols.length === 1,
    protocols,
  };
}
