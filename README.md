[![Ask DeepWiki](https://deepwiki.com/badge.svg)](https://deepwiki.com/soramimi/behind)

# BEHIND - a DNS server lesser than BIND

BEHIND is a lightweight DNS forwarding server.

Designed for home networks and small organizations, BEHIND is typically deployed as an intermediate forwarding server between Unbound (primary DNS server) and upstream DNS providers. This architecture allows you to leverage Unbound's robust caching and security features while adding custom domain filtering, static host mappings, and flexible DNS forwarding rules through BEHIND.

## Features

- **DNS Forwarding**: Forward DNS queries to upstream DNS servers with support for multiple forwarders and automatic random selection
- **UDP Multiple Forwarding**: Optionally send each UDP query to several upstream forwarders at once and use the first valid response, reducing tail latency
- **TCP/UDP Dual Protocol Support**: Support both UDP and TCP protocols for DNS queries. Large UDP responses are truncated with the TC flag so clients can retry over TCP
- **Randomized Upstream Sockets**: Up to 4 connected UDP sockets are opened per upstream forwarder, each on a kernel-assigned ephemeral source port, and responses are accepted only from the connected endpoint. Note that these sockets are reused for the lifetime of the process, so the source port is not re-randomized per query
- **Dual Stack Support**: Full IPv4 and IPv6 support
- **PTR Record Support**: Forward and cache reverse DNS lookups, including static reverse lookups for hosts entries
- **DNS Cache**: Intelligent response caching with per-record TTL tracking, bounded by `max-cache-bytes` with LRU eviction, supporting A, AAAA, CNAME, NS, MX, PTR, SOA, TXT, and HTTPS responses over both UDP and TCP
- **DNS Compression**: DNS name compression in response packets for reduced bandwidth usage
- **Security**: DNS 0x20 encoding (case randomization), randomized transaction IDs, randomized UDP source ports, upstream response validation, and bounds-checked parsing that rejects malformed DNS packets. All randomness is derived from a ChaCha20-based CSPRNG seeded from the operating system (`getrandom`)
- **Advanced Domain Filtering**: Block domains using exact match, prefix match, suffix match, or regex patterns (useful for ad-blocking)
- **Static Host Resolution**: Define custom hostname-to-IP mappings in the configuration, with reverse PTR answers generated from the same host table
- **Modular Configuration**: Support for nested configuration files using include directives
- **Logging**: Automatic log file rotation with date-based filenames
- **High Performance**: epoll-based event handling with non-blocking I/O, and constant-time (O(1)) lookup of in-flight forwarding tasks, for improved scalability and minimal resource usage

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
Specify runtime behavior and resource limits:

```ini
[options]
directory = /var/lib/behind    ; Working directory for the server
listen = 127.0.0.1@5301        ; IPv4 listen address and port
listen = ::1@5301              ; IPv6 listen address and port
max-tasks = 500                ; Maximum number of active forwarding tasks
max-cache-entry-size = 65535   ; Maximum serialized cache entry size
max-cache-bytes = 67108864     ; Global cache memory limit
max-ttl = 86400                ; Maximum cached TTL in seconds
edns0-buffer-size = 1232       ; Maximum EDNS0 UDP payload size
allow-client = 192.0.2.0/24    ; Allowed client CIDR (repeatable)
rate-limit-qps = 1000          ; Per-client and global sustained query rate
rate-limit-burst = 2000        ; Token-bucket burst size
upstream-timeout-ms = 3000     ; Upstream response timeout
udp-multiple-forwarding = 2    ; Number of upstreams to query in parallel per UDP request (1-4)
```

If no `allow-client` entry is configured, only loopback clients (`127.0.0.0/8`
and `::1/128`) are accepted. Add explicit CIDRs before exposing BEHIND to a
network. `max-tasks` must also fit within the process file-descriptor limit;
startup attempts to raise the soft limit when possible and fails safely when
the resulting limit is insufficient. The hard upper bound for `max-tasks` is
10000. Each in-flight upstream query consumes one task, so a UDP cache miss can
consume up to `udp-multiple-forwarding` tasks. For example, `max-tasks = 10000`
with `udp-multiple-forwarding = 2` permits roughly 5000 simultaneous client
cache misses. Very large values also increase timeout scanning and worst-case
memory use; 500 is a conservative default and values above a few thousand
should be load-tested on the target host.

#### [logging]
Configure log file location and verbosity:

```ini
[logging]
file = /var/log/behind/behind.log  ; Log file path
query-log = yes                    ; Log one line per answered query (default yes)
```

Per-query logging is the largest single CPU cost on the response path. Set
`query-log = no` on a busy resolver; startup, reload, and error messages are
still logged. If the log queue ever backs up (a slow or stalled log filesystem),
lines are dropped rather than buffered without limit, and a
`log lines dropped` warning is written once the queue drains.

#### [forward-zone]
Specify one or more upstream DNS servers to forward queries to. When multiple servers are configured, BEHIND will randomly select one for each query:

```ini
[forward-zone]
forward-addr = 8.8.8.8                ; Google DNS (IPv4)
forward-addr = 8.8.8.8@5353           ; IPv4 with explicit port
forward-addr = 2001:4860:4860::8888   ; Google DNS (IPv6)
forward-addr = [2001:4860:4860::8888]@5353  ; IPv6 with explicit port
forward-addr = 1.1.1.1                ; Cloudflare DNS (IPv4)
forward-addr = 2606:4700:4700::1111   ; Cloudflare DNS (IPv6)
```

You can also specify different upstream DNS servers for specific zones by adding a zone name to the section header. This allows you to route queries for different domains to different DNS servers:

```ini
[forward-zone "example.com."]
forward-addr = 192.168.1.53         ; Internal DNS server for example.com

[forward-zone "corp.local."]
forward-addr = 10.0.0.1             ; Corporate DNS server

[forward-zone]
forward-addr = 8.8.8.8              ; Default DNS for all other queries
forward-addr = 1.1.1.1
```

When a query matches a specific zone, BEHIND uses the forwarders configured for that zone. Otherwise, it uses the default forwarders (configured without a zone name).

Zone selection is a **longest match**: with both `[forward-zone "example.com."]`
and `[forward-zone "sub.example.com."]` configured, a query for
`host.sub.example.com` goes only to the forwarders of `sub.example.com.`. If
several `forward-addr` entries share that same most-specific zone, they are used
as equivalent alternatives (see `udp-multiple-forwarding`).

#### [filter]
Block specific domains by returning NXDOMAIN. Supports exact match, prefix match, suffix match, and regex patterns:

```ini
[filter]
nxdomain = doubleclick.net        ; Exact match and sub domains
nxdomain = ads.example.com         ; Exact match and sub domains
nxdomain = ad.*              ; Prefix match (e.g., ad.network.com)
nxdomain = *.tracking.com    ; Suffix match (e.g., tracker.tracking.com)
nxdomain  = *html-load*      ; Middle match (e.g., html-load.com, html-load.cc)
nxdomain = /^ad[0-9]+\..*/         ; Regex pattern (enclosed in slashes)

; Return NODATA (empty answer) instead of NXDOMAIN, for all query types
nodata = example.org

; Return NODATA for AAAA records only (useful for forcing IPv4)
nodata-aaaa = youtube.com          ; Force YouTube to use IPv4
nodata-aaaa = googlevideo.com      ; Force Google Video to use IPv4

; You can also include external filter files
include nxdomain.conf
```

Filter input is limited to 100000 rules, 4096 bytes per rule, and 256 regular
expressions. Invalid regular expressions make configuration validation fail.
At match time, a `std::regex_error` is handled fail-closed. Because
`std::regex` provides no execution-step limit, operators should still avoid
patterns with nested or ambiguous repetition that can backtrack
catastrophically; prefer the exact and wildcard forms where possible.

#### [hosts]
Define static hostname-to-IP address mappings:

```ini
[hosts]
"printer1.lan" = 192.168.123.123
"myserver.lan" = 192.168.1.100
"ipv6host.lan" = 2001:db8::1

[hosts "lan"]
"printer1" = 192.168.123.123
"myserver" = 192.168.1.100
file = hosts.lan
```

These mappings take precedence over DNS queries and are useful for:
- Local network devices without proper DNS entries
- Testing and development environments
- Overriding public DNS records with local addresses
- Serving PTR responses for reverse lookups such as `123.123.168.192.in-addr.arpa`

**Note**: Avoid using `.local` domain names as they are reserved for mDNS (multicast DNS) and may cause conflicts.

## Usage

### Running Manually

```bash
./_bin/behind -C /path/to/behind.conf
```

Validate a configuration without binding sockets:

```bash
./_bin/behind --check-config -C /path/to/behind.conf
```

### Command Line Options

- `-C, --conf <config-file>`: Specify the configuration file path
- `--check-config`: Validate syntax, referenced hosts files, and forwarder resolution, then exit
- `--log-file <path>`: Override the configured log file path
- `-h, --help`: Show command-line help
- `-v, --version`: Show the version

### Benchmarking

`benchmark.sh` uses `resperf` and the configured server limits. By default, its
maximum QPS is taken from `rate-limit-qps`, and its outstanding-query limit is
90% of `max-tasks / udp-multiple-forwarding`. This avoids benchmarking the
speed of BEHIND's overload/SERVFAIL path instead of successful resolution.
These values can be overridden for an intentional saturation test:

```bash
RESPERF_MAX_QPS=100000 RESPERF_OUTSTANDING=20000 ./benchmark.sh
```

Use the same query file and equivalent cold/warm cache state when comparing
versions. `QUERYFILE` can be used to select the input data set.

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

BEHIND acts as a DNS proxy/forwarder with support for both UDP and TCP protocols:

1. Listens for DNS queries on both UDP and TCP port 53 using epoll-based event handling for high performance
2. Checks if there's a static host mapping in the [hosts] section, including reverse PTR lookups for configured host addresses
3. Checks if the domain should be blocked using the domain filter (supports exact, prefix, suffix, and regex matching)
4. Checks the local cache for recent responses (with per-record TTL tracking)
5. If not cached, randomly selects from the configured upstream DNS servers and forwards the query:
   - **UDP forwarding**: Uses randomized source ports and connected UDP sockets for stronger upstream response validation. When `udp-multiple-forwarding` is greater than 1, the query is sent to that many randomly chosen upstreams at once and the first valid response is used
   - **TCP forwarding**: Uses non-blocking connections with epoll for efficient connection management, always against a single randomly chosen upstream
   - UDP responses that exceed the client's negotiated payload limit are truncated at a record boundary and returned with the TC flag set
6. Caches the response based on each record's TTL value (supports both UDP and TCP responses)
7. Returns the response to the client with DNS name compression for efficiency

The case randomization feature is always enabled and randomly changes the case of letters in domain names to help detect and prevent DNS spoofing attacks.

All security-sensitive randomness (transaction IDs, UDP source ports, and 0x20 case bits) is produced by a ChaCha20-based CSPRNG. Its key and nonce are seeded from the operating system's `getrandom` at startup; if the OS entropy source is unavailable, the server aborts rather than running with a predictable key.

Malformed DNS messages are rejected during parsing. BEHIND validates response transaction IDs, QR/opcode fields, the exact case-randomized question name, type, class, and connected upstream endpoint before accepting a response. Upstream timeouts and exhausted task capacity fail safely with SERVFAIL instead of leaving clients waiting indefinitely. Sustained capacity rejection is normally a sign that the offered load, `max-tasks`, UDP fan-out, or upstream latency needs tuning.

### Protocol Handling

- **UDP Protocol**: The primary protocol for DNS queries. BEHIND uses randomized source ports when forwarding UDP queries to upstream servers, and uses connected UDP sockets so responses are accepted only from the selected upstream endpoint.

- **TCP Protocol**: Automatically used for:
  - Large DNS responses that exceed the client's UDP payload limit
  - Direct TCP queries from clients
  - TCP forwarding uses non-blocking connections managed by epoll, ensuring efficient handling of multiple simultaneous TCP connections without thread overhead

- **EDNS and truncation**: Non-EDNS clients use the 512-byte DNS UDP limit. EDNS clients are limited to the smaller of their advertised payload size and `edns0-buffer-size`. Oversized responses are truncated at the last complete record and returned with the TC flag so the client can retry over TCP. Unsupported EDNS versions receive BADVERS; DNSSEC validation is not performed.

### Logging

BEHIND automatically manages log files:
- The active log is written to the path configured by `[logging] file`
- When rotation occurs, older logs are renamed with suffixes `.0` through `.9` (e.g., `behind.log.0`, `behind.log.1`)
- DNS queries and responses are logged when `query-log = yes`; lifecycle and error messages remain enabled when it is `no`
- The asynchronous queue is bounded; log lines are dropped and later reported if the writer cannot keep up
