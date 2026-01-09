# BEHIND

BEHIND is a lightweight DNS forwarding server - a DNS server lesser than BIND.

## Features

- **DNS Forwarding**: Forward DNS queries to upstream DNS servers
- **Dual Stack Support**: Full IPv4 and IPv6 support
- **DNS Cache**: 5-minute response caching with up to 4096 entries
- **Security**: DNS 0x20 encoding (case randomization) to mitigate DNS spoofing attacks
- **Domain Filtering**: Block specific domains by returning NXDOMAIN (useful for ad-blocking)
- **Static Host Resolution**: Define custom hostname-to-IP mappings in the configuration
- **Logging**: Automatic log file rotation with date-based filenames
- **Lightweight**: Minimal resource usage and fast response times

## Building

### Requirements

- Qt 6.x
- C++17 compatible compiler
- Linux operating system

### Build Instructions

```bash
# Using qmake
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

### Configuration Options

#### [forward-zone]
Specify upstream DNS servers to forward queries to:

```ini
[forward-zone]
forward-addr = 8.8.8.8              # Google DNS (IPv4)
forward-addr = 2001:4860:4860::8888  # Google DNS (IPv6)
```

#### [security]
Enable DNS security features:

```ini
[security]
case-randomize = yes  # Enable DNS 0x20 encoding for spoofing protection
```

#### [nxdomain]
Block specific domains by returning NXDOMAIN:

```ini
[nxdomain]
addr = doubleclick.net
addr = ads.example.com
```

#### [hosts]
Define static hostname-to-IP address mappings:

```ini
[hosts]
printer1.lan = 192.168.123.123
myserver.local = 192.168.1.100
ipv6host.local = 2001:db8::1
```

These mappings take precedence over DNS queries and are useful for:
- Local network devices without proper DNS entries
- Testing and development environments
- Overriding public DNS records with local addresses

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

1. Listens for DNS queries on UDP port 53
2. Checks if there's a static host mapping in the [hosts] section
3. Checks if the domain should be blocked (NXDOMAIN list)
4. Checks the local cache for recent responses
5. If not cached, forwards the query to the configured upstream DNS server
6. Caches the response for 5 minutes
7. Returns the response to the client

The case randomization feature (when enabled) randomly changes the case of letters in domain names to help detect and prevent DNS spoofing attacks.

### Logging

BEHIND automatically manages log files:
- Log files are created in the working directory
- Filenames include the date (e.g., `behind_2026-01-10.log`)
- Logs automatically rotate to a new file when the date changes
- All DNS queries and responses are logged for troubleshooting

## License

(Add your license information here)

## Author

(Add author information here)

