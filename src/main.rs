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
    #[arg(long, help = "Allow ICMP traffic", env = "HFC_ICMP")]
    icmp: bool,
    #[arg(long, help = "Allow GRE traffic", env = "HFC_GRE")]
    gre: bool,
    #[arg(long, help = "Allow ESP traffic", env = "HFC_ESP")]
    esp: bool,
    #[arg(
        long,
        value_name = "PORT | PORT RANGE",
        use_value_delimiter = true,
        help = "Comma separated list of TCP ports or port ranges to allow traffic for, e.g. '80', '80,443', '80-85' or 80,443-450'. Alternatively the parameter can be specified multiple times.",
        env = "HFC_TCP"
    )]
    tcp: Vec<String>,
    #[arg(
        long,
        value_name = "PORT | PORT RANGE",
        help = "Comma separated list of UDP ports or port ranges to allow traffic for, see --tcp for examples. Alternatively the parameter can be specified multiple times.",
        env = "HFC_UDP"
    )]
    udp: Vec<String>,
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

        let rules = build_firewall_rules(&config.icmp, &config.gre, &config.esp, &config.tcp, &config.udp, &ip);

        if fw.rules != rules {
            match update_hcloud_firewall(&client, &config.hcloud_token, fw.id, rules) {
                Ok(_) => info!("Rules of '{}' have been updated for {}", config.firewall_name, ip),
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

fn update_hcloud_firewall(client: &Client, token: &String, firewall_id: u32, firewall_rules: Vec<FirewallRule>) -> Result<(), Error> {
    let mut params = HashMap::new();
    params.insert("rules", firewall_rules);
    client.post(format!("{HCLOUD_API}/firewalls/{firewall_id}/actions/set_rules")).bearer_auth(token).json(&params).send()?;
    Ok(())
}

fn build_firewall_rules(icmp: &bool, gre: &bool, esp: &bool, tcp: &Vec<String>, udp: &Vec<String>, ip: &String) -> Vec<FirewallRule> {
    let mut rules: Vec<FirewallRule> = vec![];

    if *icmp {
        rules.push(FirewallRule {
            description: Some("ICMP".to_string()),
            destination_ips: vec![],
            direction: "in".to_string(),
            port: None,
            protocol: "icmp".to_string(),
            source_ips: vec![format!("{}/32", ip)],
        })
    };

    if *gre {
        rules.push(FirewallRule {
            description: Some("GRE".to_string()),
            destination_ips: vec![],
            direction: "in".to_string(),
            port: None,
            protocol: "gre".to_string(),
            source_ips: vec![format!("{}/32", ip)],
        })
    };

    if *esp {
        rules.push(FirewallRule {
            description: Some("ESP".to_string()),
            destination_ips: vec![],
            direction: "in".to_string(),
            port: None,
            protocol: "esp".to_string(),
            source_ips: vec![format!("{}/32", ip)],
        })
    };

    for port in tcp {
        rules.push(FirewallRule {
            description: Some(format!("TCP-{port}")),
            destination_ips: vec![],
            direction: "in".to_string(),
            port: Some(port.to_string()),
            protocol: "tcp".to_string(),
            source_ips: vec![format!("{}/32", ip)],
        })
    }

    for port in udp {
        rules.push(FirewallRule {
            description: Some(format!("UDP-{port}")),
            destination_ips: vec![],
            direction: "in".to_string(),
            port: Some(port.to_string()),
            protocol: "udp".to_string(),
            source_ips: vec![format!("{}/32", ip)],
        })
    }

    rules
}
