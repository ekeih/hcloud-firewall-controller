# hcloud-firewall-controller

`hcloud-firewall-controller` determines the current public IP and creates or updates a [Hetzner Cloud](https://www.hetzner.com/cloud) firewall with this IP.

Some internet service providers dynamically change the IP addresses of their customers, especially after router restarts. This makes it hard to use Hetzner Cloud firewalls to limit access to specific ports to your dynamic personal home IP address. This controller periodically determines your current public IP and updates a Hetzner Cloud firewall with this IP. This can be useful for SSH, Kubernetes API servers, other internal APIs or just all non-public services.

Please be aware that IP based firewalling alone is not a sufficient method to secure your infrastructure, especially not with dynamic IP addresses. Connections to all servers should still be encrypted and authenticated to provide proper security. Nevertheless, IP based firewalling can offer a nice additional layer of security by hiding non-public services and blocking bad actors at the edge of your infrastructure.

## Usage
By default the controller creates a new firewall `hcloud-firewall-controller` with the defined rules without applying the firewall to any servers. You can apply the firewall to servers manually or with an infastructure provisioning tool like Terraform based on the firewall ID. The controller prints the firewall ID each reconciliation loop.

```
Usage: hcloud-firewall-controller [OPTIONS] --hcloud-token <HCLOUD_TOKEN> --firewall-rules <FIREWALL_RULES>

Options:
  -t, --hcloud-token <HCLOUD_TOKEN>
          Hetzner Cloud API token with read and write permissions [env: HFC_HCLOUD_TOKEN]
  -i, --ip-endpoint <IP_ENDPOINT>
          Endpoint to query your public IP from [env: HFC_IP_ENDPOINT=] [default: https://ip.fotoallerlei.com]
  -f, --firewall-name <FIREWALL_NAME>
          Name of the firewall to create [env: HFC_FIREWALL_NAME=] [default: hcloud-firewall-controller]
  -w, --firewall-rules <FIREWALL_RULES>
          Firewall rules to apply, e.g. 'icmp;tcp:80,443;udp:51820' [env: HFC_FIREWALL_RULES=]
  -r, --reconciliation-interval <RECONCILIATION_INTERVAL>
          Reconciliation interval in seconds [env: HFC_RECONCILIATION_INTERVAL=] [default: 60]
  -h, --help
          Print help
  -V, --version
          Print version
```

## Planned Features
- IPv6 support
- Add static IP addresses
- Add IP addresses based on dynamic DNS records
- Pagination in case there are many firewalls in the Hetzner Cloud project
- Support multiple Hetzner Cloud projects

## Disclaimer
I am using this project to learn rust, so naturally the code might be filled with beginners mistakes. Especially in the beginning I will break the config format without any notice.

## License
- [MIT](./LICENSE)

_This software is in no way officially associated with Hetzner or Hetzner Cloud._
