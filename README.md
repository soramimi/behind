[![Ask DeepWiki](https://deepwiki.com/badge.svg)](https://deepwiki.com/soramimi/behind)

# BEHIND

a DNS server lesser than BIND - BEHIND is a lightweight DNS forwarding server.

Designed for home networks and small organizations, BEHIND is typically deployed as an intermediate forwarding server between Unbound (primary DNS server) and upstream DNS providers. This architecture allows you to leverage Unbound's robust caching and security features while adding custom domain filtering, static host mappings, and flexible DNS forwarding rules through BEHIND.

## Features

- **DNS Forwarding**: Forward DNS queries to upstream DNS servers with support for multiple forwarders and automatic random selection
- **Dual Stack Support**: Full IPv4 and IPv6 support
- **DNS Cache**: Intelligent response caching with per-record TTL tracking (up to 4096 entries)
- **DNS Compression**: DNS name compression in response packets for reduced bandwidth usage
- **Security**: DNS 0x20 encoding (case randomization) to mitigate DNS spoofing attacks
- **Advanced Domain Filtering**: Block domains using exact match, prefix match, suffix match, or regex patterns (useful for ad-blocking)
- **Static Host Resolution**: Define custom hostname-to-IP mappings in the configuration
- **Modular Configuration**: Support for nested configuration files using include directives
- **Logging**: Automatic log file rotation with date-based filenames
- **High Performance**: epoll-based event handling for improved scalability and minimal resource usage

## Building

### Requirements

- C++17 compatible compiler
- qmake (Qt build system)
- Linux operating system

### Build Instructions

```bash
# Using qmake
cd qmake
qmake behind.pro
make

# The binary will be created in _bin/behind
```

Alternatively, you can use the provided Makefile:

```bash
make
```

## Configuration

The configuration file is located at `scripts/behind.conf`. Create your own configuration based on this template.

Configuration files support the `include` directive to load additional configuration files, allowing you to modularize your settings (e.g., separate filter lists).

### Configuration Options

#### [options]
Specify working directory:

```ini
[options]
directory = /var/lib/behind  ; Working directory for the server
```

#### [logging]
Configure log file location:

```ini
[logging]
file = /var/log/behind/behind.log  ; Log file path
```

#### [forward-zone]
Specify one or more upstream DNS servers to forward queries to. When multiple servers are configured, BEHIND will randomly select one for each query:

```ini
[forward-zone]
forward-addr = 8.8.8.8              ; Google DNS (IPv4)
forward-addr = 2001:4860:4860::8888  ; Google DNS (IPv6)
forward-addr = 1.1.1.1              ; Cloudflare DNS (IPv4)
forward-addr = 2606:4700:4700::1111  ; Cloudflare DNS (IPv6)
```

#### [security]
Enable DNS security features:

```ini
[security]
case-randomize = yes  ; Enable DNS 0x20 encoding for spoofing protection
```

#### [filter]
Block specific domains by returning NXDOMAIN. Supports exact match, prefix match, suffix match, and regex patterns:

```ini
[filter]
nxdomain = doubleclick.net        ; Exact match and sub domains
nxdomain = ads.example.com         ; Exact match and sub domains
nxdomain = ad.*              ; Prefix match (e.g., ad.network.com)
nxdomain = *.tracking.com    ; Suffix match (e.g., tracker.tracking.com)
nxdomain = /^ad[0-9]+\..*/         ; Regex pattern (enclosed in slashes)

; You can also include external filter files
include nxdomain.conf
```

#### [hosts]
Define static hostname-to-IP address mappings:

```ini
[hosts]
printer1.lan = 192.168.123.123
myserver.lan = 192.168.1.100
ipv6host.lan = 2001:db8::1
```

These mappings take precedence over DNS queries and are useful for:
- Local network devices without proper DNS entries
- Testing and development environments
- Overriding public DNS records with local addresses

**Note**: Avoid using `.local` domain names as they are reserved for mDNS (multicast DNS) and may cause conflicts.

## Usage

### Running Manually

```bash
./_bin/behind -C /path/to/behind.conf
```

### Command Line Options

- `-C, --conf <config-file>`: Specify the configuration file path

### Installing as a systemd Service

1. Copy the binary to a system location:
```bash
sudo cp _bin/behind /usr/local/bin/
```

2. Copy the configuration file:
```bash
sudo mkdir -p /etc/behind
sudo cp scripts/behind.conf /etc/behind/
# Edit the configuration as needed
sudo nano /etc/behind/behind.conf
```

3. Install the systemd service:
```bash
sudo cp scripts/behind.service /etc/systemd/system/
sudo systemctl daemon-reload
```

4. Enable and start the service:
```bash
sudo systemctl enable behind
sudo systemctl start behind
```

5. Check the service status:
```bash
sudo systemctl status behind
```

## How It Works

BEHIND acts as a DNS proxy/forwarder:

1. Listens for DNS queries on UDP port 53 using epoll-based event handling for high performance
2. Checks if there's a static host mapping in the [hosts] section
3. Checks if the domain should be blocked using the domain filter (supports exact, prefix, suffix, and regex matching)
4. Checks the local cache for recent responses (with per-record TTL tracking)
5. If not cached, randomly selects one of the configured upstream DNS servers and forwards the query
6. Caches the response based on each record's TTL value
7. Returns the response to the client with DNS name compression for efficiency

The case randomization feature (when enabled) randomly changes the case of letters in domain names to help detect and prevent DNS spoofing attacks.

### Logging

BEHIND automatically manages log files:
- Log files are created in the configured log directory
- The main log file is named `behind.log`
- When rotation occurs, older logs are renamed with suffixes `.0` through `.9` (e.g., `behind.log.0`, `behind.log.1`)
- All DNS queries and responses are logged for troubleshooting

