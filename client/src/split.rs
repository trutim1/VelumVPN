use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SplitMode {
    /// Preserve the routes imported with the profile; this is not necessarily a full tunnel.
    #[serde(alias = "full_tunnel")]
    ProfileRoutes,
    OnlySelected,
    BypassSelected,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SplitPolicy {
    pub mode: SplitMode,
    #[serde(default)]
    pub networks: Vec<IpNet>,
    #[serde(default)]
    pub domains: Vec<String>,
    #[serde(default)]
    pub applications: Vec<String>,
    #[serde(default)]
    pub bypass_lan: bool,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum SplitError {
    #[error("only_selected requires at least one network")]
    EmptySelection,
    #[error("application split tunneling is not implemented")]
    AppsUnsupported,
    #[error("domain split tunneling is not implemented")]
    DomainsUnsupported,
    #[error("LAN bypass is not implemented")]
    LanBypassUnsupported,
    #[error("bypass_selected is not implemented")]
    BypassUnsupported,
    #[error("profile_routes cannot contain route overrides")]
    UnexpectedNetworks,
}

#[derive(Debug, Clone, Copy)]
pub enum Platform {
    Windows,
    Linux,
    MacOs,
    Ios,
    Android,
}

impl SplitPolicy {
    pub fn validate(&self, _platform: Platform) -> Result<(), SplitError> {
        self.validate_supported()
    }

    /// Reject every requested feature that the current engine cannot enforce.
    /// Validation is independent of the selected mode: changing modes must not
    /// silently discard an application, domain, or LAN privacy rule.
    pub fn validate_supported(&self) -> Result<(), SplitError> {
        if !self.applications.is_empty() {
            return Err(SplitError::AppsUnsupported);
        }
        if !self.domains.is_empty() {
            return Err(SplitError::DomainsUnsupported);
        }
        if self.bypass_lan {
            return Err(SplitError::LanBypassUnsupported);
        }
        match self.mode {
            SplitMode::BypassSelected => Err(SplitError::BypassUnsupported),
            SplitMode::OnlySelected if self.networks.is_empty() => Err(SplitError::EmptySelection),
            SplitMode::ProfileRoutes if !self.networks.is_empty() => {
                Err(SplitError::UnexpectedNetworks)
            }
            _ => Ok(()),
        }
    }

    pub fn tunnel_routes(&self, imported_routes: &[IpNet]) -> Result<Vec<IpNet>, SplitError> {
        self.validate_supported()?;
        Ok(match self.mode {
            SplitMode::ProfileRoutes => imported_routes.to_vec(),
            SplitMode::OnlySelected => self.networks.clone(),
            SplitMode::BypassSelected => return Err(SplitError::BypassUnsupported),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn selected_networks_become_routes() {
        let p = SplitPolicy {
            mode: SplitMode::OnlySelected,
            networks: vec!["10.0.0.0/8".parse().unwrap()],
            domains: vec![],
            applications: vec![],
            bypass_lan: false,
        };
        assert_eq!(p.tunnel_routes(&[]).unwrap(), p.networks);
    }
    #[test]
    fn unsupported_rules_are_rejected_on_every_mode_and_platform() {
        for mode in [
            SplitMode::ProfileRoutes,
            SplitMode::OnlySelected,
            SplitMode::BypassSelected,
        ] {
            for platform in [
                Platform::Windows,
                Platform::Linux,
                Platform::MacOs,
                Platform::Ios,
                Platform::Android,
            ] {
                let mut p = SplitPolicy {
                    mode: mode.clone(),
                    networks: vec![],
                    domains: vec![],
                    applications: vec!["app".into()],
                    bypass_lan: false,
                };
                assert_eq!(p.validate(platform), Err(SplitError::AppsUnsupported));
                p.applications.clear();
                p.domains.push("example.test".into());
                assert_eq!(p.validate(platform), Err(SplitError::DomainsUnsupported));
                p.domains.clear();
                p.bypass_lan = true;
                assert_eq!(p.validate(platform), Err(SplitError::LanBypassUnsupported));
            }
        }
    }

    #[test]
    fn imported_routes_are_preserved_and_old_mode_is_only_an_input_alias() {
        let p: SplitPolicy = serde_json::from_str(r#"{"mode":"full_tunnel"}"#).unwrap();
        assert_eq!(p.mode, SplitMode::ProfileRoutes);
        assert!(!p.bypass_lan);
        let routes = vec!["192.0.2.0/24".parse().unwrap()];
        assert_eq!(p.tunnel_routes(&routes).unwrap(), routes);
        assert!(
            serde_json::to_string(&p)
                .unwrap()
                .contains("profile_routes")
        );
    }

    #[test]
    fn unsupported_mode_and_ignored_route_overrides_are_rejected() {
        let mut p: SplitPolicy = serde_json::from_str(r#"{"mode":"bypass_selected"}"#).unwrap();
        assert_eq!(p.validate_supported(), Err(SplitError::BypassUnsupported));
        p.mode = SplitMode::OnlySelected;
        assert_eq!(p.validate_supported(), Err(SplitError::EmptySelection));
        p.mode = SplitMode::ProfileRoutes;
        p.networks.push("10.0.0.0/8".parse().unwrap());
        assert_eq!(p.validate_supported(), Err(SplitError::UnexpectedNetworks));
    }
}
