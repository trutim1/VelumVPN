//! Read-only evidence from the pinned helper; never a verdict about leak safety.
use serde::{Deserialize, Serialize};

const INVALID: &str = "Системный модуль вернул неподтверждённое состояние";

#[derive(Debug, Deserialize, Serialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum ServiceState {
    Absent,
    Stopped,
    StartPending,
    Running,
    StopPending,
    Unknown,
}

#[derive(Debug, Deserialize, Serialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum UapiState {
    NotRunning,
    Unavailable,
    Available,
}

#[derive(Deserialize)]
struct HelperStatus {
    schema_version: u16,
    name: String,
    config_accepted: bool,
    service_state: ServiceState,
    uapi_state: UapiState,
    tunnel_ready: bool,
    traffic_verified: bool,
    handshake_fresh: bool,
    peer_count: u64,
    last_handshake_unix_seconds: Option<i64>,
    rx_bytes: u64,
    tx_bytes: u64,
}

// This is a projection, NOT a forwarded backend JSON object. Unknown fields,
// including accidental secrets, are never returned to the WebView. Counters
// are decimal strings to avoid losing u64 precision in JavaScript.
#[derive(Debug, Serialize)]
pub struct Observation {
    pub service_state: ServiceState,
    pub uapi_state: UapiState,
    pub config_accepted: bool,
    pub handshake_fresh: bool,
    pub peer_count: String,
    pub rx_bytes: String,
    pub tx_bytes: String,
    pub observed_at_unix_seconds: u64,
    pub traffic_verified: bool,
}

pub fn parse(bytes: &[u8], name: &str, now: u64) -> Result<Observation, String> {
    if bytes.is_empty() || bytes.len() > super::MAX_HELPER_ACK {
        return Err(INVALID.into());
    }
    let status: HelperStatus = serde_json::from_slice(bytes).map_err(|_| INVALID)?;
    if status.schema_version != 1
        || status.name != name
        || status.tunnel_ready
        || status.traffic_verified
    {
        return Err(INVALID.into());
    }
    let live = status.service_state == ServiceState::Running
        && status.uapi_state == UapiState::Available
        && status.config_accepted;
    let timestamp = match status.last_handshake_unix_seconds {
        Some(value) if value > 0 && value as u64 <= now => Some(value as u64),
        Some(_) => return Err(INVALID.into()),
        None => None,
    };
    // Recheck at the receiving boundary, not just against helper's boolean.
    let fresh = timestamp.is_some_and(|value| now - value <= 180);
    if (!live
        && (status.uapi_state == UapiState::Available
            || status.peer_count != 0
            || status.rx_bytes != 0
            || status.tx_bytes != 0
            || timestamp.is_some()
            || status.handshake_fresh))
        || (status.peer_count == 0
            && (timestamp.is_some() || status.rx_bytes != 0 || status.tx_bytes != 0))
        || (status.handshake_fresh && !fresh)
        || (status.service_state == ServiceState::Absent && status.config_accepted)
    {
        return Err(INVALID.into());
    }
    Ok(Observation {
        service_state: status.service_state,
        uapi_state: status.uapi_state,
        config_accepted: status.config_accepted,
        handshake_fresh: live && status.handshake_fresh && fresh,
        peer_count: status.peer_count.to_string(),
        rx_bytes: status.rx_bytes.to_string(),
        tx_bytes: status.tx_bytes.to_string(),
        observed_at_unix_seconds: now,
        traffic_verified: false,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{Value, json};

    fn fixture() -> Value {
        json!({"schema_version":1,"name":"test","config_accepted":true,
            "service_state":"running","uapi_state":"available","tunnel_ready":false,
            "traffic_verified":false,"handshake_fresh":true,"peer_count":1,
            "last_handshake_unix_seconds":1000,"rx_bytes":10,"tx_bytes":20})
    }
    fn check(value: &Value, now: u64) -> Result<Observation, String> {
        parse(&serde_json::to_vec(value).unwrap(), "test", now)
    }

    #[test]
    fn fresh_handshake_is_transport_evidence_not_protection() {
        let observed = check(&fixture(), 1010).unwrap();
        assert!(observed.handshake_fresh);
        assert!(!observed.traffic_verified);
        assert_eq!(observed.observed_at_unix_seconds, 1010);
    }

    #[test]
    fn stale_future_and_contradictory_reports_fail_closed() {
        for (key, value) in [
            ("name", json!("other")),
            ("schema_version", json!(2)),
            ("service_state", json!("injected-state")),
            ("service_state", json!("stopped")),
            ("uapi_state", json!("unavailable")),
            ("config_accepted", json!(false)),
            ("peer_count", json!(0)),
            ("tunnel_ready", json!(true)),
            ("traffic_verified", json!(true)),
            ("last_handshake_unix_seconds", json!(-1)),
            ("last_handshake_unix_seconds", json!(null)),
        ] {
            let mut input = fixture();
            input[key] = value;
            assert!(check(&input, 1010).is_err(), "accepted {key}");
        }
        assert!(check(&fixture(), 999).is_err());
        assert!(check(&fixture(), 1181).is_err());
        assert!(check(&fixture(), 1180).unwrap().handshake_fresh);
        let mut old = fixture();
        old["handshake_fresh"] = json!(false);
        assert!(!check(&old, 2000).unwrap().handshake_fresh);
    }

    #[test]
    fn accepts_unavailable_without_inventing_metrics() {
        for state in [
            "absent",
            "stopped",
            "start_pending",
            "stop_pending",
            "unknown",
            "running",
        ] {
            let input = json!({"schema_version":1,"name":"test","config_accepted":false,
                "service_state":state,"uapi_state":"unavailable","tunnel_ready":false,
                "traffic_verified":false,"handshake_fresh":false,"peer_count":0,
                "last_handshake_unix_seconds":null,"rx_bytes":0,"tx_bytes":0});
            assert!(!check(&input, 1010).unwrap().handshake_fresh);
        }
    }

    #[test]
    fn projects_only_safe_fields_and_preserves_counter_precision() {
        let mut input = fixture();
        input["rx_bytes"] = json!(u64::MAX);
        input["private_key"] = json!("SYNTHETIC_SECRET_MUST_NOT_ESCAPE");
        let observed = check(&input, 1010).unwrap();
        assert_eq!(observed.rx_bytes, u64::MAX.to_string());
        let output = serde_json::to_string(&observed).unwrap();
        assert!(!output.contains("SECRET"));
        assert!(!output.contains("private_key"));
        assert!(!output.contains("name"));
    }

    #[test]
    fn rejects_truncated_oversized_duplicate_or_missing_fields() {
        for input in [
            b"".as_slice(),
            b"{}",
            b"{",
            &vec![b' '; super::super::MAX_HELPER_ACK + 1],
        ] {
            assert!(parse(input, "test", 1010).is_err());
        }
        let input = serde_json::to_string(&fixture()).unwrap();
        let duplicate = input.replacen('{', "{\"name\":\"test\",", 1);
        assert!(parse(duplicate.as_bytes(), "test", 1010).is_err());
        assert!(parse(format!("{input}{input}").as_bytes(), "test", 1010).is_err());
    }
}
