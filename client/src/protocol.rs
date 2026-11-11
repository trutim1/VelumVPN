use serde::{Deserialize, Serialize};
use thiserror::Error;
use zeroize::Zeroizing;

use crate::config::AwgProfile;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProtocolId {
    AmneziaWg3,
    AmneziaWgLegacy,
    WireGuard,
    OpenVpn,
    Ikev2,
    XrayVlessReality,
    Shadowsocks2022,
    OpenVpnCloak,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReleaseTrack {
    GeneralAvailability,
    Preview,
    Beta,
    Experimental,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ImplementationState {
    ImportAndStorage,
    Catalogued,
    DesktopResearch,
}

#[derive(Debug, Clone, Serialize)]
pub struct ProtocolDescriptor {
    pub id: ProtocolId,
    pub name: &'static str,
    pub summary: &'static str,
    pub target_release_track: ReleaseTrack,
    pub implementation: ImplementationState,
    pub target_platforms: &'static [&'static str],
    pub config_formats: &'static [&'static str],
    pub docker_server: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct ProtocolInspection {
    pub protocol: ProtocolId,
    pub warnings: Vec<String>,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ProtocolError {
    #[error("формат конфигурации не распознан")]
    Unknown,
    #[error("OpenVPN-конфигурация содержит запрещённую исполняемую директиву: {0}")]
    UnsafeOpenVpnDirective(String),
    #[error("VLESS-профиль не использует REALITY")]
    RealityRequired,
    #[error("разрешены только Shadowsocks 2022 AEAD-методы")]
    Shadowsocks2022Required,
    #[error("некорректная конфигурация WireGuard/AmneziaWG: {0}")]
    WireGuard(String),
}

pub fn protocol_catalog() -> Vec<ProtocolDescriptor> {
    vec![
        ProtocolDescriptor {
            id: ProtocolId::AmneziaWg3,
            name: "AmneziaWG 3.0",
            summary: "WireGuard-криптография с DPI-обфускацией AWG 3",
            target_release_track: ReleaseTrack::Preview,
            implementation: ImplementationState::ImportAndStorage,
            target_platforms: &["windows", "linux", "android", "ios", "macos"],
            config_formats: &["conf"],
            docker_server: true,
        },
        ProtocolDescriptor {
            id: ProtocolId::AmneziaWgLegacy,
            name: "AmneziaWG 1/2",
            summary: "Совместимость с существующими профилями AmneziaWG",
            target_release_track: ReleaseTrack::GeneralAvailability,
            implementation: ImplementationState::ImportAndStorage,
            target_platforms: &["windows", "linux", "android", "ios", "macos"],
            config_formats: &["conf", "vpn"],
            docker_server: true,
        },
        ProtocolDescriptor {
            id: ProtocolId::WireGuard,
            name: "WireGuard",
            summary: "Быстрый базовый VPN-транспорт",
            target_release_track: ReleaseTrack::GeneralAvailability,
            implementation: ImplementationState::ImportAndStorage,
            target_platforms: &["windows", "linux", "android", "ios", "macos"],
            config_formats: &["conf"],
            docker_server: true,
        },
        ProtocolDescriptor {
            id: ProtocolId::OpenVpn,
            name: "OpenVPN",
            summary: "Совместимый TLS VPN для ограниченных сетей",
            target_release_track: ReleaseTrack::GeneralAvailability,
            implementation: ImplementationState::Catalogued,
            target_platforms: &["windows", "linux", "android", "ios", "macos"],
            config_formats: &["ovpn"],
            docker_server: true,
        },
        ProtocolDescriptor {
            id: ProtocolId::Ikev2,
            name: "IKEv2/IPsec",
            summary: "Системный fallback с сертификатной аутентификацией",
            target_release_track: ReleaseTrack::GeneralAvailability,
            implementation: ImplementationState::Catalogued,
            target_platforms: &["windows", "linux", "android", "ios", "macos"],
            config_formats: &["mobileconfig", "p12", "json"],
            docker_server: true,
        },
        ProtocolDescriptor {
            id: ProtocolId::XrayVlessReality,
            name: "VLESS + REALITY",
            summary: "Антиблокировочный прокси через системный TUN",
            target_release_track: ReleaseTrack::Beta,
            implementation: ImplementationState::Catalogued,
            target_platforms: &["windows", "linux", "android", "ios", "macos"],
            config_formats: &["json", "txt"],
            docker_server: true,
        },
        ProtocolDescriptor {
            id: ProtocolId::Shadowsocks2022,
            name: "Shadowsocks 2022",
            summary: "SIP022 AEAD proxy через системный TUN",
            target_release_track: ReleaseTrack::Beta,
            implementation: ImplementationState::Catalogued,
            target_platforms: &["windows", "linux", "android", "ios", "macos"],
            config_formats: &["json", "txt"],
            docker_server: true,
        },
        ProtocolDescriptor {
            id: ProtocolId::OpenVpnCloak,
            name: "OpenVPN + Cloak",
            summary: "Экспериментальный desktop camouflage transport",
            target_release_track: ReleaseTrack::Experimental,
            implementation: ImplementationState::DesktopResearch,
            target_platforms: &["windows", "linux"],
            config_formats: &["ovpn", "json"],
            docker_server: true,
        },
    ]
}

pub fn inspect_protocol_config(
    file_name: &str,
    text: &str,
) -> Result<ProtocolInspection, ProtocolError> {
    let lower_name = Zeroizing::new(file_name.to_ascii_lowercase());
    // Classification needs a case-folded view of the whole input, which also
    // contains credentials. Wipe this allocation on every return path.
    let lower = Zeroizing::new(text.to_ascii_lowercase());

    if lower.contains("[interface]") && lower.contains("[peer]") {
        // Parser diagnostics can contain untrusted section names. Do not let
        // copied config values escape through Display or Debug of this error.
        let profile = AwgProfile::parse(text)
            .map_err(|_| ProtocolError::WireGuard("профиль отклонён".into()))?;
        let summary = profile.summary();
        let is_awg = !summary.awg_parameters.is_empty();
        let is_awg3 = summary.awg_parameters.iter().any(|value| {
            matches!(
                value.as_str(),
                "HeaderProtectionKey"
                    | "ContentPaddingAddition"
                    | "RekeyAfterTime"
                    | "RekeyTimeout"
                    | "RejectAfterTime"
                    | "KeepaliveTimeout"
                    | "MaxHandshakeAttempts"
            )
        });
        return Ok(ProtocolInspection {
            protocol: if is_awg3 {
                ProtocolId::AmneziaWg3
            } else if is_awg {
                ProtocolId::AmneziaWgLegacy
            } else {
                ProtocolId::WireGuard
            },
            warnings: if is_awg && !is_awg3 {
                vec!["Профиль распознан как совместимый AmneziaWG 1/2, а не AWG 3.0".into()]
            } else {
                Vec::new()
            },
        });
    }

    if lower_name.ends_with(".ovpn") || lower.lines().any(|line| line.trim() == "client") {
        for line in lower
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty() && !line.starts_with('#') && !line.starts_with(';'))
        {
            let directive = line.split_ascii_whitespace().next().unwrap_or_default();
            if matches!(
                directive,
                "up" | "down"
                    | "route-up"
                    | "ipchange"
                    | "client-connect"
                    | "client-disconnect"
                    | "learn-address"
                    | "auth-user-pass-verify"
                    | "plugin"
                    | "script-security"
            ) {
                return Err(ProtocolError::UnsafeOpenVpnDirective(directive.into()));
            }
        }
        return Ok(ProtocolInspection {
            protocol: ProtocolId::OpenVpn,
            warnings: vec![
                "Исполнение OpenVPN-профиля отключено до подключения OpenVPN 3 Core adapter".into(),
            ],
        });
    }

    if lower.contains("vless://") || lower.contains("\"protocol\"") && lower.contains("\"vless\"") {
        if !lower.contains("reality") {
            return Err(ProtocolError::RealityRequired);
        }
        return Ok(ProtocolInspection {
            protocol: ProtocolId::XrayVlessReality,
            warnings: vec![
                "Профиль будет работать только через будущий изолированный TUN-adapter".into(),
            ],
        });
    }

    if lower.contains("ss://") || lower.contains("2022-blake3-aes-") {
        if !lower.contains("2022-blake3-aes-128-gcm") && !lower.contains("2022-blake3-aes-256-gcm")
        {
            return Err(ProtocolError::Shadowsocks2022Required);
        }
        return Ok(ProtocolInspection {
            protocol: ProtocolId::Shadowsocks2022,
            warnings: vec![
                "Shadowsocks является proxy и требует будущий системный TUN-adapter".into(),
            ],
        });
    }

    if lower_name.ends_with(".mobileconfig") && lower.contains("ikev2") {
        return Ok(ProtocolInspection { protocol: ProtocolId::Ikev2, warnings: vec!["Секреты IKEv2 должны импортироваться непосредственно в системное хранилище сертификатов".into()] });
    }

    Err(ProtocolError::Unknown)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_executable_openvpn_directives() {
        let error = inspect_protocol_config(
            "client.ovpn",
            "client\ndev tun\nscript-security 2\nup /tmp/run-me\n",
        )
        .unwrap_err();
        assert_eq!(
            error,
            ProtocolError::UnsafeOpenVpnDirective("script-security".into())
        );
    }

    #[test]
    fn vless_requires_reality() {
        assert_eq!(
            inspect_protocol_config("profile.txt", "vless://abc@example.test:443").unwrap_err(),
            ProtocolError::RealityRequired
        );
    }

    #[test]
    fn recognizes_shadowsocks_2022() {
        let inspection = inspect_protocol_config(
            "profile.txt",
            "ss://2022-blake3-aes-256-gcm:secret@example.test:443",
        )
        .unwrap();
        assert_eq!(inspection.protocol, ProtocolId::Shadowsocks2022);
    }

    #[test]
    fn errors_never_return_private_input_values() {
        let sentinel = "private-config-sentinel";
        for (name, text) in [
            (
                "profile.conf",
                format!("[Interface]\n[Peer]\n[{sentinel}]\n"),
            ),
            (
                "profile.conf",
                format!("[Interface]\nPrivateKey = {sentinel}\nAddress = 10.0.0.2/32\n[Peer]\n"),
            ),
            ("profile.ovpn", format!("client\nup /tmp/{sentinel}\n")),
            (
                "profile.txt",
                format!("vless://{sentinel}@example.test:443"),
            ),
            ("profile.txt", format!("ss://{sentinel}@example.test:443")),
            ("profile.txt", sentinel.into()),
        ] {
            let error = inspect_protocol_config(name, &text).unwrap_err();
            assert!(!error.to_string().contains(sentinel));
            assert!(!format!("{error:?}").contains(sentinel));
        }
    }

    #[test]
    fn protected_case_fold_preserves_protocol_detection() {
        for (name, text, expected) in [
            ("profile.OVPN", "CLIENT\nDEV TUN", ProtocolId::OpenVpn),
            (
                "profile.txt",
                "VLESS://synthetic@example.test:443?security=REALITY",
                ProtocolId::XrayVlessReality,
            ),
            (
                "profile.MOBILECONFIG",
                "<string>IKEV2</string>",
                ProtocolId::Ikev2,
            ),
        ] {
            assert_eq!(
                inspect_protocol_config(name, text).unwrap().protocol,
                expected
            );
        }
    }
}
