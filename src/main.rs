use clap::Parser;
use env_logger::Env;
use log::{debug, error, info, log_enabled, Level};
use reqwest::blocking::Client;
use reqwest::Error;
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, thread, time};

const HCLOUD_API: &str = "https://api.hetzner.cloud/v1";

#[derive(Clone, Deserialize, Debug)]
struct Firewalls {
    firewalls: Vec<Firewall>,
}

#[derive(Clone, Deserialize, Debug)]
struct FirewallResponse {
    firewall: Firewall,
}

#[derive(Clone, Deserialize, Debug)]
struct Firewall {
    id: u32,
    name: String,
    rules: Vec<FirewallRule>,
}

#[derive(Clone, Deserialize, Debug, Serialize, PartialEq)]
struct FirewallRule {
    description: Option<String>,
    destination_ips: Vec<String>,
    direction: String,
    port: Option<String>,
    protocol: String,
    source_ips: Vec<String>,
}

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Config {
    #[arg(short = 't', long, help = "Hetzner Cloud API token with read and write permissions", env = "HFC_HCLOUD_TOKEN", hide_env_values = true)]
    hcloud_token: String,
    #[arg(short, long, default_value_t = String::from("https://ip.fotoallerlei.com"), help = "Endpoint to query your public IP from", env = "HFC_IP_ENDPOINT")]
    ip_endpoint: String,
    #[arg(short, long, default_value_t = String::from("hcloud-firewall-controller"), help = "Name of the firewall to create", env = "HFC_FIREWALL_NAME")]
    firewall_name: String,
    #[arg(short = 'w', long, help = "Firewall rules to apply, e.g. 'icmp;tcp:80,443;udp:51820'", env = "HFC_FIREWALL_RULES")]
    firewall_rules: String,
    #[arg(short, long, default_value_t = 60, help = "Reconciliation interval in seconds", env = "HFC_RECONCILIATION_INTERVAL")]
    reconciliation_interval: u64,
}

fn main() {
    env_logger::Builder::from_env(Env::default().default_filter_or("info")).init();
    let config = Config::parse();
    info!("hcloud-firewall-controller started with a reconciliation interval of {} seconds", config.reconciliation_interval);
    controller(&config);
}

fn controller(config: &Config) {
    let client = Client::new();
    loop {
        debug!("Reconciliation loop started");

        let ip = match get_ip(&client, &config.ip_endpoint) {
            Ok(ip) => ip,
            Err(e) => {
                error!("{:?}", e);
                thread::sleep(time::Duration::from_secs(10));
                continue;
            }
        };

        let fw = match get_or_create_firewall(&client, &config.hcloud_token, &config.firewall_name) {
            Ok(fw) => fw,
            Err(e) => {
                error!("{:?}", e);
                thread::sleep(time::Duration::from_secs(10));
                continue;
            }
        };

        let rules = match parse_firewall_rules(&config.firewall_rules, &ip) {
            Ok(rules) => rules,
            Err(e) => {
                error!("{:?}", e);
                thread::sleep(time::Duration::from_secs(10));
                continue;
            }
        };

        if fw.rules != rules {
            match update_hcloud_firewall(&client, &config.hcloud_token, fw.id, rules) {
                Ok(_) => info!("Rules of '{}' have been updates for {}", config.firewall_name, ip),
                Err(e) => {
                    error!("{:?}", e);
                    thread::sleep(time::Duration::from_secs(10));
                    continue;
                }
            };
        } else {
            info!("Rules of '{}' are already up to date for {}", config.firewall_name, ip)
        }

        debug!("Reconciliation loop finished, sleeping for {} seconds", config.reconciliation_interval);
        thread::sleep(time::Duration::from_secs(config.reconciliation_interval));
    }
}

fn get_ip(client: &Client, ip_endpont: &String) -> Result<String, Error> {
    Ok(client.get(ip_endpont).send()?.text()?.trim().to_string())
}

fn get_or_create_firewall(client: &Client, token: &String, firewall_name: &String) -> Result<Firewall, Error> {
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

fn create_hcloud_firewall(client: &Client, token: &String, firewall_name: &String) -> Result<Firewall, Error> {
    let mut params = HashMap::new();
    params.insert("name", firewall_name);
    let firewall_response: FirewallResponse = client.post(format!("{HCLOUD_API}/firewalls")).bearer_auth(token).json(&params).send()?.json()?;
    let firewall = firewall_response.firewall;
    debug!("Created new firewall '{}' (id: {})", firewall.name, firewall.id);
    Ok(firewall)
}

fn get_hcloud_firewalls(client: &Client, token: &String) -> Result<Firewalls, Error> {
    let firewalls: Firewalls = client.get(format!("{HCLOUD_API}/firewalls")).bearer_auth(token).send()?.json()?;
    if log_enabled!(Level::Debug) {
        for firewall in &firewalls.firewalls {
            debug!("Firewall '{}' (id: {}) found with {} rules", firewall.name, firewall.id, firewall.rules.len());
        }
    }
    Ok(firewalls)
}

fn parse_firewall_rules(firewall_rules: &str, ip: &String) -> Result<Vec<FirewallRule>, std::string::ParseError> {
    let mut rules: Vec<FirewallRule> = vec![];
    let split_rules = firewall_rules.split(';');
    for rule in split_rules {
        debug!("rule: {:?}", rule);
        let mut protocol: &str = "tcp";
        for (i, v) in rule.split(':').enumerate() {
            if i == 0 {
                // first element is the protocol
                protocol = v;
                if !(["tcp", "udp"].contains(&v.to_lowercase().as_str())) {
                    // if it is neither tcp nor udp it has no port
                    rules.push(FirewallRule {
                        description: Some(v.to_string()),
                        destination_ips: vec![],
                        direction: "in".to_string(),
                        port: None,
                        protocol: v.to_string(),
                        source_ips: vec![format!("{}/32", ip)],
                    })
                }
            } else {
                for p in v.split(',') {
                    rules.push(FirewallRule {
                        description: Some(format!("{}-{}", protocol, p)),
                        destination_ips: vec![],
                        direction: "in".to_string(),
                        port: Some(p.to_string()),
                        protocol: protocol.to_string(),
                        source_ips: vec![format!("{}/32", ip)],
                    });
                }
            }
        }
    }
    Ok(rules)
}

fn update_hcloud_firewall(client: &Client, token: &String, firewall_id: u32, firewall_rules: Vec<FirewallRule>) -> Result<(), Error> {
    let mut params = HashMap::new();
    params.insert("rules", firewall_rules);
    client.post(format!("{HCLOUD_API}/firewalls/{firewall_id}/actions/set_rules")).bearer_auth(token).json(&params).send()?;
    Ok(())
}
