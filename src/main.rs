mod hcloud;
mod ip;

use clap::Parser;
use env_logger::Env;
use hcloud::FirewallRule;
use log::{debug, error, info};
use reqwest::blocking::{Client, ClientBuilder};
use std::net::IpAddr;
use std::process::ExitCode;
use std::str::FromStr;
use std::{thread, time};

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
    let ips = ip::build_ips(client4, client6, &config.ip_endpoint, &config.ip, config.disable_ipv4, config.disable_ipv6)?;
    let rules = build_firewall_rules(&config.icmp, &config.gre, &config.esp, &config.tcp, &config.udp, &ips);

    for token in &config.hcloud_token {
        let fw = hcloud::get_or_create_firewall(client4, token, &config.firewall_name)?;

        if fw.rules != rules {
            match hcloud::update_hcloud_firewall(client4, token, fw.id, &rules) {
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
