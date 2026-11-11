use std::{
    fmt,
    io::{Cursor, Read},
};

use base64::{Engine as _, engine::general_purpose};
use flate2::bufread::ZlibDecoder;
use serde::{
    Deserialize,
    de::{IgnoredAny, MapAccess, Visitor},
};
use thiserror::Error;
use zeroize::{Zeroize, Zeroizing};

use crate::config::AwgProfile;

const PREFIX: &[u8] = b"vpn://";
const MAX_FILE: usize = 256 * 1024;
const MAX_PACKED: usize = 192 * 1024;
const MAX_UNCOMPRESSED: usize = 1024 * 1024;
const MAX_LAST_CONFIG: usize = 128 * 1024;
const MAX_NATIVE_CONFIG: usize = 64 * 1024;
const MAX_CONTAINERS: usize = 16;

#[derive(Debug, Error)]
pub enum AmneziaShareError {
    #[error("Amnezia share-файл слишком большой")]
    FileTooLarge,
    #[error("ожидался точный префикс vpn://")]
    Prefix,
    #[error("некорректная Base64URL-кодировка")]
    Base64,
    #[error("некорректный qCompress-контейнер")]
    Compression,
    #[error("заявленный размер qCompress недопустим")]
    DeclaredSize,
    #[error("внешняя структура Amnezia share повреждена")]
    OuterJson,
    #[error("вложенная структура last_config повреждена")]
    NestedJson,
    #[error("share-файл содержит management credentials; используйте отдельный SSH-сценарий")]
    ManagementCredentials,
    #[error("ожидался ровно один AWG-контейнер")]
    AwgContainerCount,
    #[error("вложенная конфигурация превышает безопасный лимит")]
    NestedTooLarge,
    #[error("вложенная AWG-конфигурация отклонена")]
    Config,
}

#[derive(Clone)]
struct SensitiveString(String);

impl<'de> Deserialize<'de> for SensitiveString {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        String::deserialize(deserializer).map(Self)
    }
}

impl Drop for SensitiveString {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

#[derive(Deserialize)]
struct ShareEnvelope {
    containers: Vec<ShareContainer>,
}

#[derive(Deserialize)]
struct ShareContainer {
    container: String,
    awg: Option<ShareAwg>,
}

#[derive(Deserialize)]
struct ShareAwg {
    last_config: SensitiveString,
    protocol_version: Option<ProtocolVersion>,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum ProtocolVersion {
    Number(u8),
    Text(String),
}

impl ProtocolVersion {
    fn as_u8(&self) -> Option<u8> {
        match self {
            Self::Number(value) => Some(*value),
            Self::Text(value) => value.parse().ok(),
        }
    }
}

#[derive(Deserialize)]
struct NestedConfig {
    config: SensitiveString,
}

#[derive(Default)]
struct CredentialScan {
    found: bool,
}

impl<'de> Deserialize<'de> for CredentialScan {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct CredentialScanVisitor;

        impl<'de> Visitor<'de> for CredentialScanVisitor {
            type Value = CredentialScan;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("an Amnezia share JSON object")
            }

            fn visit_map<M>(self, mut map: M) -> Result<Self::Value, M::Error>
            where
                M: MapAccess<'de>,
            {
                let mut found = false;
                while let Some(key) = map.next_key::<String>()? {
                    if is_management_credential_key(&key) {
                        found = true;
                    }
                    map.next_value::<IgnoredAny>()?;
                }
                Ok(CredentialScan { found })
            }
        }

        deserializer.deserialize_map(CredentialScanVisitor)
    }
}

fn is_management_credential_key(key: &str) -> bool {
    let normalized: String = key
        .chars()
        .filter(|character| character.is_ascii_alphanumeric())
        .map(|character| character.to_ascii_lowercase())
        .collect();
    matches!(
        normalized.as_str(),
        "username"
            | "user"
            | "login"
            | "password"
            | "passphrase"
            | "keypassphrase"
            | "secretdata"
            | "sshuser"
            | "sshusername"
            | "sshlogin"
            | "sshpassword"
            | "sshpassphrase"
            | "sshkey"
            | "sshprivatekey"
            | "privatekey"
            | "privatekeypath"
    )
}

fn is_supported_awg_container(container: &str) -> bool {
    matches!(container, "amnezia-awg" | "amnezia-awg2")
}

pub struct DecodedAmneziaShare {
    config: SensitiveString,
    pub protocol_version: Option<u8>,
}

impl DecodedAmneziaShare {
    pub fn expose_config(&self) -> &str {
        &self.config.0
    }
}

pub fn decode_amnezia_share(input: &[u8]) -> Result<DecodedAmneziaShare, AmneziaShareError> {
    if input.len() > MAX_FILE {
        return Err(AmneziaShareError::FileTooLarge);
    }
    let encoded = input
        .strip_prefix(PREFIX)
        .ok_or(AmneziaShareError::Prefix)?;
    if encoded.is_empty()
        || !encoded
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'='))
    {
        return Err(AmneziaShareError::Base64);
    }
    let engine = if encoded.contains(&b'=') {
        &general_purpose::URL_SAFE
    } else {
        &general_purpose::URL_SAFE_NO_PAD
    };
    let packed = Zeroizing::new(
        engine
            .decode(encoded)
            .map_err(|_| AmneziaShareError::Base64)?,
    );
    if packed.len() < 12 || packed.len() > MAX_PACKED {
        return Err(AmneziaShareError::Compression);
    }
    let declared = u32::from_be_bytes(
        packed[..4]
            .try_into()
            .map_err(|_| AmneziaShareError::Compression)?,
    ) as usize;
    if declared == 0 || declared > MAX_UNCOMPRESSED {
        return Err(AmneziaShareError::DeclaredSize);
    }

    let mut decoder = ZlibDecoder::new(Cursor::new(&packed[4..]));
    let mut clear = Zeroizing::new(Vec::with_capacity(declared));
    decoder
        .by_ref()
        .take((declared + 1) as u64)
        .read_to_end(&mut clear)
        .map_err(|_| AmneziaShareError::Compression)?;
    if clear.len() != declared || decoder.total_in() as usize != packed.len() - 4 {
        return Err(AmneziaShareError::Compression);
    }

    let credential_scan: CredentialScan =
        serde_json::from_slice(&clear).map_err(|_| AmneziaShareError::OuterJson)?;
    if credential_scan.found {
        return Err(AmneziaShareError::ManagementCredentials);
    }
    let envelope: ShareEnvelope =
        serde_json::from_slice(&clear).map_err(|_| AmneziaShareError::OuterJson)?;
    if envelope.containers.len() > MAX_CONTAINERS {
        return Err(AmneziaShareError::OuterJson);
    }
    let mut candidates = envelope
        .containers
        .into_iter()
        .filter(|container| is_supported_awg_container(&container.container))
        .filter_map(|container| container.awg);
    let candidate = candidates
        .next()
        .ok_or(AmneziaShareError::AwgContainerCount)?;
    if candidates.next().is_some() {
        return Err(AmneziaShareError::AwgContainerCount);
    }
    if candidate.last_config.0.len() > MAX_LAST_CONFIG {
        return Err(AmneziaShareError::NestedTooLarge);
    }
    let nested: NestedConfig = serde_json::from_str(&candidate.last_config.0)
        .map_err(|_| AmneziaShareError::NestedJson)?;
    if nested.config.0.len() > MAX_NATIVE_CONFIG {
        return Err(AmneziaShareError::NestedTooLarge);
    }
    AwgProfile::parse(&nested.config.0).map_err(|_| AmneziaShareError::Config)?;
    Ok(DecodedAmneziaShare {
        config: nested.config,
        protocol_version: candidate
            .protocol_version
            .as_ref()
            .and_then(ProtocolVersion::as_u8),
    })
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use flate2::{Compression, write::ZlibEncoder};

    use super::*;

    const CONFIG: &str = "[Interface]\nPrivateKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\nAddress = 10.8.1.2/32\nJc = 4\nJmin = 10\nJmax = 30\nS1 = 20\nS2 = 24\nH1 = 100\nH2 = 101\nH3 = 102\nH4 = 103\n[Peer]\nPublicKey = AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=\nEndpoint = 203.0.113.7:42015\nAllowedIPs = 0.0.0.0/0\n";

    fn share(root_extra: &str) -> Vec<u8> {
        share_with("amnezia-awg", CONFIG, root_extra)
    }

    fn share_with(container: &str, config: &str, root_extra: &str) -> Vec<u8> {
        let nested = serde_json::json!({ "config": config }).to_string();
        let json = format!(
            r#"{{"containers":[{{"container":{},"awg":{{"last_config":{},"protocol_version":2}}}}]{} }}"#,
            serde_json::to_string(container).unwrap(),
            serde_json::to_string(&nested).unwrap(),
            root_extra
        );
        let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(json.as_bytes()).unwrap();
        let compressed = encoder.finish().unwrap();
        let mut framed = (json.len() as u32).to_be_bytes().to_vec();
        framed.extend(compressed);
        format!("vpn://{}", general_purpose::URL_SAFE_NO_PAD.encode(framed)).into_bytes()
    }

    #[test]
    fn decodes_connection_only_share() {
        let decoded = decode_amnezia_share(&share("")).unwrap();
        assert_eq!(decoded.protocol_version, Some(2));
        assert!(decoded.expose_config().contains("[Interface]"));
    }

    #[test]
    fn rejects_management_credentials() {
        let result = decode_amnezia_share(&share(r#", "userName":"root", "password":"secret""#));
        assert!(matches!(
            result,
            Err(AmneziaShareError::ManagementCredentials)
        ));
    }

    #[test]
    fn rejects_management_credential_presence_and_aliases() {
        for extra in [
            r#", "userName":"""#,
            r#", "password":null"#,
            r#", "ssh_private_key":"secret""#,
            r#", "secretData":{}"#,
        ] {
            assert!(matches!(
                decode_amnezia_share(&share(extra)),
                Err(AmneziaShareError::ManagementCredentials)
            ));
        }
    }

    #[test]
    fn requires_exact_awg_container_discriminator() {
        assert!(matches!(
            decode_amnezia_share(&share_with("amnezia-wireguard", CONFIG, "")),
            Err(AmneziaShareError::AwgContainerCount)
        ));
    }

    #[test]
    fn accepts_exact_awg2_container_discriminator() {
        assert!(decode_amnezia_share(&share_with("amnezia-awg2", CONFIG, "")).is_ok());
    }

    #[test]
    fn redacts_nested_parser_values() {
        let config = CONFIG.replace("Jc = 4", "Jc = do-not-leak");
        let error = decode_amnezia_share(&share_with("amnezia-awg", &config, ""))
            .err()
            .expect("invalid AWG config must be rejected");
        let message = error.to_string();
        assert_eq!(message, "вложенная AWG-конфигурация отклонена");
        assert!(!message.contains("do-not-leak"));
    }
}
