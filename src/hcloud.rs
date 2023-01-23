use log::{debug, info, log_enabled, Level};
use reqwest::blocking::Client;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;
use std::fmt::Display;

const HCLOUD_API: &str = "https://api.hetzner.cloud/v1";

#[derive(Debug)]
pub struct HcloudError(pub String);
impl std::error::Error for HcloudError {}
impl Display for HcloudError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "[Error from Hetzner Cloud API] {}", self.0)
    }
}

#[derive(Clone, Deserialize, Debug)]
struct Firewalls {
    firewalls: Vec<Firewall>,
}

#[derive(Clone, Deserialize, Debug)]
struct FirewallResponse {
    firewall: Firewall,
}

#[derive(Clone, Deserialize, Debug)]
pub struct Firewall {
    pub id: u32,
    pub name: String,
    pub rules: Vec<FirewallRule>,
}

#[derive(Clone, Deserialize, Debug, Serialize, PartialEq)]
pub struct FirewallRule {
    pub description: Option<String>,
    pub destination_ips: Vec<String>,
    pub direction: String,
    pub port: Option<String>,
    pub protocol: String,
    pub source_ips: Vec<String>,
}

#[derive(Deserialize, Debug)]
struct FirewallRuleResponse {
    error: Option<FirewallRuleError>,
}

#[derive(Deserialize, Debug)]
struct FirewallRuleError {
    code: String,
    message: String,
    details: FirewallRuleErrorDetails,
}

#[derive(Deserialize, Debug)]
struct FirewallRuleErrorDetails {
    fields: Vec<Value>,
}

pub fn get_or_create_firewall(client: &Client, token: &String, firewall_name: &String) -> Result<Firewall, reqwest::Error> {
    let firewalls: Firewalls = get_hcloud_firewalls(client, token)?;
    for firewall in firewalls.firewalls {
        if firewall.name == *firewall_name {
            debug!("Exising firewall found '{}'", firewall.name);
            return Ok(firewall);
        }
    }
    match create_hcloud_firewall(client, token, firewall_name) {
        Ok(fw) => {
            info!("Created new firewall '{}'", firewall_name);
            Ok(fw)
        }
        Err(e) => Err(e),
    }
}

fn create_hcloud_firewall(client: &Client, token: &String, firewall_name: &String) -> Result<Firewall, reqwest::Error> {
    let mut params = HashMap::new();
    params.insert("name", firewall_name);
    let firewall_response: FirewallResponse = client.post(format!("{HCLOUD_API}/firewalls")).bearer_auth(token).json(&params).send()?.json()?;
    let firewall = firewall_response.firewall;
    debug!("Created new firewall '{}' (id: {})", firewall.name, firewall.id);
    Ok(firewall)
}

fn get_hcloud_firewalls(client: &Client, token: &String) -> Result<Firewalls, reqwest::Error> {
    let firewalls: Firewalls = client.get(format!("{HCLOUD_API}/firewalls")).bearer_auth(token).send()?.json()?;
    if log_enabled!(Level::Debug) {
        for firewall in &firewalls.firewalls {
            debug!("Firewall '{}' (id: {}) found with {} rules", firewall.name, firewall.id, firewall.rules.len());
        }
    }
    Ok(firewalls)
}

pub fn update_hcloud_firewall(client: &Client, token: &String, firewall_id: u32, firewall_rules: &[FirewallRule]) -> Result<(), Box<dyn std::error::Error>> {
    let mut params = HashMap::new();
    params.insert("rules", firewall_rules);
    let response: FirewallRuleResponse = client
        .post(format!("{HCLOUD_API}/firewalls/{firewall_id}/actions/set_rules"))
        .bearer_auth(token)
        .json(&params)
        .send()?
        .json()?;
    if response.error.is_some() {
        let e = response.error.as_ref().unwrap();
        let error_message = format!("{}: {}, Original error details: {:?}", e.code, e.message, e.details.fields);
        return Err(Box::new(HcloudError(error_message)));
    }
    Ok(())
}
