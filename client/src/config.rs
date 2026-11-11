use std::{
    collections::BTreeMap,
    fmt,
    net::SocketAddr,
    ops::{Deref, DerefMut},
    str::FromStr,
};

use base64::{Engine as _, engine::general_purpose::STANDARD};
use curve25519_dalek::montgomery::MontgomeryPoint;
use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct Secret(String);

impl Secret {
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("[REDACTED]")
    }
}

#[derive(Clone)]
pub struct Interface {
    pub private_key: Secret,
    client_public_key: [u8; 32],
    pub addresses: Vec<IpNet>,
    pub dns: Vec<String>,
    pub mtu: Option<u16>,
    pub obfuscation: SensitiveValues,
}

#[derive(Clone, Default)]
pub struct SensitiveValues(BTreeMap<String, String>);

impl Deref for SensitiveValues {
    type Target = BTreeMap<String, String>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for SensitiveValues {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl Drop for SensitiveValues {
    fn drop(&mut self) {
        for value in self.0.values_mut() {
            value.zeroize();
        }
    }
}

impl fmt::Debug for Interface {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Interface")
            .field("private_key", &self.private_key)
            .field("addresses", &self.addresses)
            .field("dns", &self.dns)
            .field("mtu", &self.mtu)
            .field(
                "obfuscation_parameters",
                &self.obfuscation.keys().collect::<Vec<_>>(),
            )
            .finish()
    }
}

#[derive(Debug, Clone)]
pub struct Peer {
    pub public_key: String,
    pub preshared_key: Option<Secret>,
    pub endpoint: SocketAddr,
    pub allowed_ips: Vec<IpNet>,
    pub persistent_keepalive: Option<String>,
}

#[derive(Debug, Clone)]
pub struct AwgProfile {
    pub interface: Interface,
    pub peers: Vec<Peer>,
}

#[derive(Error)]
pub enum ConfigError {
    #[error("line {line}: expected key = value")]
    InvalidLine { line: usize },
    #[error("line {line}: unknown configuration section")]
    UnknownSection { line: usize, section: String },
    #[error("line {line}: duplicate configuration directive")]
    DuplicateDirective { line: usize, directive: String },
    #[error("unsupported configuration directive in {section}")]
    UnknownDirective {
        section: &'static str,
        directive: String,
    },
    #[error("missing required field {0}")]
    Missing(&'static str),
    #[error("invalid {field}")]
    Invalid { field: &'static str, value: String },
    #[error("AWG parameter is outside the supported range")]
    AwgRange { field: String, value: String },
    #[error("unsafe configuration directive is not allowed")]
    UnsafeDirective(String),
}

// Error chains and Result::unwrap diagnostics must never print input-derived
// fields, even when Debug formatting is selected instead of Display.
impl fmt::Debug for ConfigError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, formatter)
    }
}

impl Drop for ConfigError {
    fn drop(&mut self) {
        match self {
            Self::UnknownSection { section, .. } | Self::UnsafeDirective(section) => {
                section.zeroize();
            }
            Self::DuplicateDirective { directive, .. }
            | Self::UnknownDirective { directive, .. } => directive.zeroize(),
            Self::Invalid { value, .. } => value.zeroize(),
            Self::AwgRange { field, value } => {
                field.zeroize();
                value.zeroize();
            }
            Self::InvalidLine { .. } | Self::Missing(_) => {}
        }
    }
}

enum Section {
    None,
    Interface,
    Peer,
}

impl AwgProfile {
    pub fn parse(input: &str) -> Result<Self, ConfigError> {
        let mut section = Section::None;
        let mut interface = SensitiveValues::default();
        let mut peer_maps: Vec<SensitiveValues> = Vec::new();

        for (index, raw) in input.lines().enumerate() {
            let line_no = index + 1;
            let line = raw.split_once('#').map_or(raw, |(before, _)| before).trim();
            if line.is_empty() {
                continue;
            }
            if line.starts_with('[') && line.ends_with(']') {
                section = match &line[1..line.len() - 1].to_ascii_lowercase()[..] {
                    "interface" => Section::Interface,
                    "peer" => {
                        peer_maps.push(SensitiveValues::default());
                        Section::Peer
                    }
                    other => {
                        return Err(ConfigError::UnknownSection {
                            line: line_no,
                            section: other.into(),
                        });
                    }
                };
                continue;
            }
            let (key, value) = line
                .split_once('=')
                .ok_or(ConfigError::InvalidLine { line: line_no })?;
            let normalized_key = key.trim().to_ascii_lowercase();
            if matches!(
                normalized_key.as_str(),
                "preup" | "postup" | "predown" | "postdown" | "saveconfig" | "table"
            ) {
                return Err(ConfigError::UnsafeDirective(key.trim().to_string()));
            }
            let target = match section {
                Section::Interface => &mut interface,
                Section::Peer => peer_maps.last_mut().expect("peer section exists"),
                Section::None => return Err(ConfigError::InvalidLine { line: line_no }),
            };
            if target.contains_key(&normalized_key) {
                return Err(ConfigError::DuplicateDirective {
                    line: line_no,
                    directive: normalized_key,
                });
            }
            target.insert(normalized_key, value.trim().to_string());
        }

        let private_key = Secret(take_required(
            &mut interface,
            "privatekey",
            "Interface.PrivateKey",
        )?);
        let private_key_bytes =
            Zeroizing::new(decode_key("Interface.PrivateKey", private_key.expose())?);
        let client_public_key = MontgomeryPoint::mul_base_clamped(*private_key_bytes).to_bytes();
        let addresses = parse_nets(
            &take_required(&mut interface, "address", "Interface.Address")?,
            "Interface.Address",
        )?;
        let dns = take_csv(interface.remove("dns"));
        let mtu = parse_optional(interface.remove("mtu"), "Interface.MTU")?;
        let mut obfuscation = SensitiveValues::default();
        for key in [
            "jc",
            "jmin",
            "jmax",
            "s1",
            "s2",
            "s3",
            "s4",
            "h1",
            "h2",
            "h3",
            "h4",
            "i1",
            "i2",
            "i3",
            "i4",
            "i5",
            "headerprotectionkey",
            "contentpaddingaddition",
            "rekeyaftertime",
            "rekeytimeout",
            "rejectaftertime",
            "keepalivetimeout",
            "maxhandshakeattempts",
        ] {
            if let Some(value) = interface.remove(key) {
                let value = zeroize::Zeroizing::new(value);
                validate_awg(key, &value)?;
                obfuscation.insert(canonical_awg_key(key), value.to_string());
            }
        }
        validate_junk_bounds(&obfuscation)?;
        validate_header_protection(&obfuscation)?;
        interface.remove("listenport");
        if let Some(directive) = interface.keys().next().cloned() {
            return Err(ConfigError::UnknownDirective {
                section: "Interface",
                directive,
            });
        }

        let mut peers = Vec::new();
        for mut map in peer_maps {
            let public_key = take_required(&mut map, "publickey", "Peer.PublicKey")?;
            let _public_key_bytes = Zeroizing::new(decode_key("Peer.PublicKey", &public_key)?);
            let endpoint_text = take_required(&mut map, "endpoint", "Peer.Endpoint")?;
            let endpoint =
                SocketAddr::from_str(&endpoint_text).map_err(|_| ConfigError::Invalid {
                    field: "Peer.Endpoint",
                    value: endpoint_text,
                })?;
            let allowed_ips = parse_nets(
                &take_required(&mut map, "allowedips", "Peer.AllowedIPs")?,
                "Peer.AllowedIPs",
            )?;
            let preshared_key = map
                .remove("presharedkey")
                .map(|value| {
                    let secret = Secret(value);
                    let _decoded =
                        Zeroizing::new(decode_key("Peer.PresharedKey", secret.expose())?);
                    Ok(secret)
                })
                .transpose()?;
            let persistent_keepalive = map.remove("persistentkeepalive");
            if let Some(value) = persistent_keepalive.as_deref() {
                validate_u32_range("PersistentKeepalive", value)?;
            }
            if let Some(directive) = map.keys().next().cloned() {
                return Err(ConfigError::UnknownDirective {
                    section: "Peer",
                    directive,
                });
            }
            peers.push(Peer {
                public_key,
                preshared_key,
                endpoint,
                allowed_ips,
                persistent_keepalive,
            });
        }
        if peers.is_empty() {
            return Err(ConfigError::Missing("Peer"));
        }
        Ok(Self {
            interface: Interface {
                private_key,
                client_public_key,
                addresses,
                dns,
                mtu,
                obfuscation,
            },
            peers,
        })
    }

    pub fn fingerprint(&self) -> String {
        let mut hash = Sha256::new();
        hash.update(b"velum-client-public-identity-v1\0");
        hash.update(self.interface.client_public_key);
        format!("{:x}", hash.finalize())
    }

    pub fn summary(&self) -> ProfileSummary {
        ProfileSummary {
            fingerprint: self.fingerprint(),
            addresses: self.interface.addresses.clone(),
            endpoints: self.peers.iter().map(|p| p.endpoint.to_string()).collect(),
            awg_parameters: self.interface.obfuscation.keys().cloned().collect(),
        }
    }
}

#[derive(Debug, Serialize, Deserialize, PartialEq)]
pub struct ProfileSummary {
    pub fingerprint: String,
    pub addresses: Vec<IpNet>,
    pub endpoints: Vec<String>,
    pub awg_parameters: Vec<String>,
}

fn canonical_awg_key(key: &str) -> String {
    match key {
        "jc" => "Jc".into(),
        "jmin" => "Jmin".into(),
        "jmax" => "Jmax".into(),
        "headerprotectionkey" => "HeaderProtectionKey".into(),
        "contentpaddingaddition" => "ContentPaddingAddition".into(),
        "rekeyaftertime" => "RekeyAfterTime".into(),
        "rekeytimeout" => "RekeyTimeout".into(),
        "rejectaftertime" => "RejectAfterTime".into(),
        "keepalivetimeout" => "KeepaliveTimeout".into(),
        "maxhandshakeattempts" => "MaxHandshakeAttempts".into(),
        other => other.to_ascii_uppercase(),
    }
}

fn validate_junk_bounds(values: &BTreeMap<String, String>) -> Result<(), ConfigError> {
    let Some(min) = values.get("Jmin") else {
        return Ok(());
    };
    let Some(max) = values.get("Jmax") else {
        return Ok(());
    };
    let min_value: u16 = min.parse().expect("numeric values validated earlier");
    let max_value: u16 = max.parse().expect("numeric values validated earlier");
    if min_value > max_value {
        return Err(ConfigError::AwgRange {
            field: "Jmin/Jmax".into(),
            value: format!("{min_value}/{max_value}"),
        });
    }
    Ok(())
}

fn validate_awg(key: &str, value: &str) -> Result<(), ConfigError> {
    if key == "headerprotectionkey" {
        let _decoded = Zeroizing::new(decode_key("HeaderProtectionKey", value)?);
    }
    if key == "jc" {
        let parsed: u16 = value.parse().map_err(|_| ConfigError::AwgRange {
            field: key.into(),
            value: value.into(),
        })?;
        if parsed > 128 {
            return Err(ConfigError::AwgRange {
                field: key.into(),
                value: value.into(),
            });
        }
    }
    if matches!(key, "jmin" | "jmax") {
        value.parse::<u16>().map_err(|_| ConfigError::AwgRange {
            field: key.into(),
            value: value.into(),
        })?;
    }
    if matches!(
        key,
        "s1" | "s2"
            | "s3"
            | "s4"
            | "contentpaddingaddition"
            | "rekeyaftertime"
            | "rekeytimeout"
            | "rejectaftertime"
            | "keepalivetimeout"
            | "maxhandshakeattempts"
    ) {
        validate_u32_range(key, value)?;
    }
    Ok(())
}

fn decode_key(field: &'static str, value: &str) -> Result<[u8; 32], ConfigError> {
    let decoded = Zeroizing::new(STANDARD.decode(value).map_err(|_| ConfigError::Invalid {
        field,
        value: String::new(),
    })?);
    let key: [u8; 32] = decoded
        .as_slice()
        .try_into()
        .map_err(|_| ConfigError::Invalid {
            field,
            value: String::new(),
        })?;
    if STANDARD.encode(key) != value {
        return Err(ConfigError::Invalid {
            field,
            value: String::new(),
        });
    }
    Ok(key)
}

fn validate_u32_range(field: &str, value: &str) -> Result<(), ConfigError> {
    if value == "(off)" {
        return Ok(());
    }
    let mut parts = value.split('-');
    let first = parts.next().and_then(|v| v.parse::<u32>().ok());
    let second = parts.next().map(|v| v.parse::<u32>().ok());
    if first.is_none() || parts.next().is_some() || second.is_some_and(|v| v.is_none()) {
        return Err(ConfigError::AwgRange {
            field: field.into(),
            value: value.into(),
        });
    }
    if let (Some(start), Some(Some(end))) = (first, second)
        && start > end
    {
        return Err(ConfigError::AwgRange {
            field: field.into(),
            value: value.into(),
        });
    }
    Ok(())
}

fn validate_header_protection(values: &BTreeMap<String, String>) -> Result<(), ConfigError> {
    if !values.contains_key("HeaderProtectionKey") {
        return Ok(());
    }
    for field in ["S1", "S2", "S3", "S4"] {
        let value = values.get(field).ok_or_else(|| ConfigError::AwgRange {
            field: field.into(),
            value: "missing for HeaderProtectionKey".into(),
        })?;
        let minimum = value
            .split('-')
            .next()
            .and_then(|v| v.parse::<u32>().ok())
            .unwrap_or(0);
        if minimum < 12 {
            return Err(ConfigError::AwgRange {
                field: field.into(),
                value: value.clone(),
            });
        }
    }
    Ok(())
}

fn take_required(
    map: &mut BTreeMap<String, String>,
    key: &str,
    field: &'static str,
) -> Result<String, ConfigError> {
    map.remove(key)
        .filter(|v| !v.is_empty())
        .ok_or(ConfigError::Missing(field))
}
fn take_csv(value: Option<String>) -> Vec<String> {
    value
        .map(|v| {
            v.split(',')
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default()
}
fn parse_nets(value: &str, field: &'static str) -> Result<Vec<IpNet>, ConfigError> {
    value
        .split(',')
        .map(|v| {
            v.trim().parse().map_err(|_| ConfigError::Invalid {
                field,
                value: v.trim().into(),
            })
        })
        .collect()
}
fn parse_optional<T: FromStr>(
    value: Option<String>,
    field: &'static str,
) -> Result<Option<T>, ConfigError> {
    value
        .map(|v| {
            v.parse()
                .map_err(|_| ConfigError::Invalid { field, value: v })
        })
        .transpose()
}

#[cfg(test)]
mod tests {
    use super::*;
    const CONFIG: &str = "[Interface]\nPrivateKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\nAddress = 10.8.0.2/32\nDNS = 1.1.1.1\nJc = 5\nJmin = 40\nJmax = 70\nS1 = 10\nH1 = 100-200\nI1 = <r 16>\n\n[Peer]\nPublicKey = AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=\nEndpoint = 203.0.113.1:51820\nAllowedIPs = 0.0.0.0/0, ::/0\nPersistentKeepalive = 25\n";

    #[test]
    fn parses_awg_without_exposing_secret() {
        let p = AwgProfile::parse(CONFIG).unwrap();
        assert_eq!(p.peers.len(), 1);
        assert!(format!("{p:?}").contains("[REDACTED]"));
        assert!(!format!("{p:?}").contains("AAAAAAAA"));
        assert!(p.interface.obfuscation.contains_key("I1"));
    }

    #[test]
    fn error_display_and_debug_redact_all_input_derived_fields() {
        let marker = "sensitive-config-sentinel";
        let errors = [
            ConfigError::UnknownSection {
                line: 1,
                section: marker.into(),
            },
            ConfigError::DuplicateDirective {
                line: 2,
                directive: marker.into(),
            },
            ConfigError::UnknownDirective {
                section: "Interface",
                directive: marker.into(),
            },
            ConfigError::Invalid {
                field: "Interface.PrivateKey",
                value: marker.into(),
            },
            ConfigError::AwgRange {
                field: marker.into(),
                value: marker.into(),
            },
            ConfigError::UnsafeDirective(marker.into()),
        ];
        for error in errors {
            assert!(!format!("{error} {error:?} {error:#?}").contains(marker));
            assert!(!format!("{:?}", Err::<(), _>(error)).contains(marker));
        }
        let invalid = CONFIG.replace("Jmin = 40", &format!("Jmin = {marker}"));
        assert!(!format!("{:?}", AwgProfile::parse(&invalid)).contains(marker));
    }
    #[test]
    fn fingerprint_changes_with_client_identity() {
        let a = AwgProfile::parse(CONFIG).unwrap();
        let b = AwgProfile::parse(&CONFIG.replace(
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
            "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=",
        ))
        .unwrap();
        assert_ne!(a.fingerprint(), b.fingerprint());
    }

    #[test]
    fn fingerprint_does_not_depend_on_endpoint() {
        let a = AwgProfile::parse(CONFIG).unwrap();
        let b =
            AwgProfile::parse(&CONFIG.replace("203.0.113.1:51820", "198.51.100.9:443")).unwrap();
        assert_eq!(a.fingerprint(), b.fingerprint());
    }

    #[test]
    fn rejects_inverted_junk_range() {
        let invalid = CONFIG.replace("Jmin = 40", "Jmin = 80");
        assert!(matches!(
            AwgProfile::parse(&invalid),
            Err(ConfigError::AwgRange { .. })
        ));
    }

    #[test]
    fn rejects_privileged_shell_hooks() {
        let malicious = CONFIG.replace("DNS = 1.1.1.1", "DNS = 1.1.1.1\nPostUp = powershell evil");
        assert!(matches!(
            AwgProfile::parse(&malicious),
            Err(ConfigError::UnsafeDirective(_))
        ));
    }

    #[test]
    fn rejects_duplicate_directives_instead_of_overwriting_validated_values() {
        let duplicate = CONFIG.replace(
            "Address = 10.8.0.2/32",
            "Address = 10.8.0.2/32\nAddress = 192.0.2.9/32",
        );
        assert!(matches!(
            AwgProfile::parse(&duplicate),
            Err(ConfigError::DuplicateDirective { .. })
        ));
    }

    #[test]
    fn rejects_unknown_directives_before_privileged_handoff() {
        let unknown = CONFIG.replace("DNS = 1.1.1.1", "DNS = 1.1.1.1\nFutureCommand = value");
        assert!(matches!(
            AwgProfile::parse(&unknown),
            Err(ConfigError::UnknownDirective {
                section: "Interface",
                ..
            })
        ));
    }

    #[test]
    fn parses_awg3_header_protection_and_ranges() {
        let source = CONFIG.replace(
            "S1 = 10",
            "S1 = 12-16\nS2 = 12\nS3 = 12\nS4 = 12\nHeaderProtectionKey = AwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwM=\nContentPaddingAddition = 50-100\nRekeyAfterTime = 90-120",
        );
        let profile = AwgProfile::parse(&source).unwrap();
        assert!(
            profile
                .interface
                .obfuscation
                .contains_key("HeaderProtectionKey")
        );

        let too_short = source.replace("S2 = 12", "S2 = 8");
        assert!(matches!(
            AwgProfile::parse(&too_short),
            Err(ConfigError::AwgRange { ref field, .. }) if field == "S2"
        ));
    }
}
