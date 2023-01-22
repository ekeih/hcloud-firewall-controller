use clap::Parser;
use env_logger::Env;
use ipnet::IpNet;
use log::{debug, error, info, log_enabled, Level};
use reqwest::blocking::{Client, ClientBuilder};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::fmt::Display;
use std::net::IpAddr;
use std::process::ExitCode;
use std::str::FromStr;
use std::{collections::HashMap, thread, time};

const HCLOUD_API: &str = "https://api.hetzner.cloud/v1";

#[derive(Debug)]
struct HcloudError(String);
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

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Config {
    #[arg(short = '1', long, help = "Run only once and exit, useful if run by cron or other tools", env = "HFC_RUN_ONCE")]
    run_once: bool,
    #[arg(
        short = 't',
        long,
        use_value_delimiter = true,
        help = "Hetzner Cloud API token with read and write permissions, can be specified multiple times or passed as comma separated list to manage several projects",
        env = "HFC_HCLOUD_TOKEN",
        hide_env_values = true
    )]
    hcloud_token: Vec<String>,
    #[arg(short, long, default_value_t = String::from("hcloud-firewall-controller"), help = "Name of the firewall to create", env = "HFC_FIREWALL_NAME")]
    firewall_name: String,
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
    #[arg(long, help = "Allow ICMP traffic", env = "HFC_ICMP")]
    icmp: bool,
    #[arg(long, help = "Allow GRE traffic", env = "HFC_GRE")]
    gre: bool,
    #[arg(long, help = "Allow ESP traffic", env = "HFC_ESP")]
    esp: bool,
    #[arg(
        long,
        value_name = "STATIC IP",
        help = "Comma separated list of static IP addresses in CIDR notation to add to all firewall rules in addition to dynamically discovered IP addresses. Alternatively the parameter can be specified multiple times. The Hetzner Cloud API requires that the IP is the network id of the specified network, so 127.0.0.0/24 would work while 127.0.0.1/24 would fail.",
        env = "HFC_IP"
    )]
    ip: Vec<String>,
    #[arg(long, help = "Disable the detection of the public IPv4 address", env = "HFC_DISABLE_IPV4")]
    disable_ipv4: bool,
    #[arg(long, help = "Disable the detection of the public IPv6 address", env = "HFC_DISABLE_IPV6")]
    disable_ipv6: bool,
    #[arg(short, long, default_value_t = 60, help = "Reconciliation interval in seconds", env = "HFC_RECONCILIATION_INTERVAL")]
    reconciliation_interval: u64,
    #[arg(short, long, default_value_t = String::from("https://ip.fotoallerlei.com"), help = "Endpoint to query your public IP from", env = "HFC_IP_ENDPOINT")]
    ip_endpoint: String,
}

fn main() -> ExitCode {
    env_logger::Builder::from_env(Env::default().default_filter_or("info")).init();
    let config = Config::parse();

    let client4 = ClientBuilder::new().local_address(IpAddr::from_str("0.0.0.0").unwrap()).build().unwrap();
    let client6 = ClientBuilder::new().local_address(IpAddr::from_str("::").unwrap()).build().unwrap();

    if config.run_once {
        match reconcile(&config, &client4, &client6) {
            Ok(_) => debug!("Reconciliation succeeded"),
            Err(e) => {
                error!("{e}");
                return ExitCode::FAILURE;
            }
        };
    } else {
        controller(&config, &client4, &client6);
    }
    ExitCode::SUCCESS
}

fn controller(config: &Config, client4: &Client, client6: &Client) {
    loop {
        debug!("Reconciliation loop started");
        match reconcile(config, client4, client6) {
            Ok(_) => debug!("Reconciliation loop finished, sleeping for {} seconds", config.reconciliation_interval),
            Err(e) => error!("{e}"),
        };
        thread::sleep(time::Duration::from_secs(config.reconciliation_interval));
    }
}

fn reconcile(config: &Config, client4: &Client, client6: &Client) -> Result<(), Box<dyn std::error::Error>> {
    let ips = build_ips(client4, client6, &config.ip_endpoint, &config.ip, config.disable_ipv4, config.disable_ipv6)?;
    let rules = build_firewall_rules(&config.icmp, &config.gre, &config.esp, &config.tcp, &config.udp, &ips);

    for token in &config.hcloud_token {
        let fw = get_or_create_firewall(client4, token, &config.firewall_name)?;

        if fw.rules != rules {
            match update_hcloud_firewall(client4, token, fw.id, &rules) {
                Ok(_) => info!("Rules of '{}' (id: {}) have been updated for {:?}", config.firewall_name, fw.id, ips),
                Err(e) => {
                    error!("{e}");
                    continue;
                }
            };
        } else {
            info!("Rules of '{}' (id: {}) are already up to date for {:?}", config.firewall_name, fw.id, ips)
        }
        thread::sleep(time::Duration::from_millis(500));
    }
    Ok(())
}

fn build_ips(client4: &Client, client6: &Client, ip_endpont: &String, static_ips: &[String], disable_ipv4: bool, disable_ipv6: bool) -> Result<Vec<String>, Box<dyn std::error::Error>> {
    let mut ips = static_ips.to_owned();

    if !disable_ipv4 {
        let ip4 = get_ip(client4, ip_endpont)?;
        ips.push(format!("{}/{}", ip4, 32));
    }

    if !disable_ipv6 {
        let ip6 = get_ip(client6, ip_endpont)?;
        let ip6_network = IpNet::new(ip6, 64)?;
        ips.push(format!("{}/{}", ip6_network.network(), ip6_network.prefix_len()));
    }

    ips.sort();
    Ok(ips)
}

fn get_ip(client: &Client, ip_endpont: &String) -> Result<IpAddr, Box<dyn std::error::Error>> {
    Ok(IpAddr::from_str(client.get(ip_endpont).send()?.text()?.trim())?)
}

fn get_or_create_firewall(client: &Client, token: &String, firewall_name: &String) -> Result<Firewall, reqwest::Error> {
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

fn update_hcloud_firewall(client: &Client, token: &String, firewall_id: u32, firewall_rules: &[FirewallRule]) -> Result<(), Box<dyn std::error::Error>> {
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

fn build_firewall_rules(icmp: &bool, gre: &bool, esp: &bool, tcp: &[String], udp: &[String], ips: &[String]) -> Vec<FirewallRule> {
    let mut rules: Vec<FirewallRule> = vec![];

    if ips.is_empty() {
        return rules;
    }

    if *icmp {
        rules.push(FirewallRule {
            description: Some("ICMP".to_string()),
            destination_ips: vec![],
            direction: "in".to_string(),
            port: None,
            protocol: "icmp".to_string(),
            source_ips: ips.to_vec(),
        })
    };

    if *gre {
        rules.push(FirewallRule {
            description: Some("GRE".to_string()),
            destination_ips: vec![],
            direction: "in".to_string(),
            port: None,
            protocol: "gre".to_string(),
            source_ips: ips.to_vec(),
        })
    };

    if *esp {
        rules.push(FirewallRule {
            description: Some("ESP".to_string()),
            destination_ips: vec![],
            direction: "in".to_string(),
            port: None,
            protocol: "esp".to_string(),
            source_ips: ips.to_vec(),
        })
    };

    for port in tcp {
        rules.push(FirewallRule {
            description: Some(format!("TCP-{port}")),
            destination_ips: vec![],
            direction: "in".to_string(),
            port: Some(port.to_string()),
            protocol: "tcp".to_string(),
            source_ips: ips.to_vec(),
        })
    }

    for port in udp {
        rules.push(FirewallRule {
            description: Some(format!("UDP-{port}")),
            destination_ips: vec![],
            direction: "in".to_string(),
            port: Some(port.to_string()),
            protocol: "udp".to_string(),
            source_ips: ips.to_vec(),
        })
    }

    rules
}
