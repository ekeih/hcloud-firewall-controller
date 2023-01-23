use ipnet::IpNet;
use reqwest::blocking::Client;
use std::net::IpAddr;
use std::str::FromStr;

pub fn build_ips(client4: &Client, client6: &Client, ip_endpont: &String, static_ips: &[String], disable_ipv4: bool, disable_ipv6: bool) -> Result<Vec<String>, Box<dyn std::error::Error>> {
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
