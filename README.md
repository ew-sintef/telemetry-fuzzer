# TELEMETRY fuzzing tool - Boofuzz-based fuzzing of network services

## Overview

This repository contains a Docker-based fuzzing environment using boofuzz, along with lightweight monitoring scripts for an OpenWrt target. It is designed for use in a testing lab/cyber range (virtual or physical) where:

- An Ubuntu system runs Docker and the fuzzing container
- An OpenWrt target runs the target services (HTTP, DNS, SSH, etc.)
- Monitoring scripts can run on the target system/device to detect crashes and high resource usage, in addition to restarting services if needed
  
  

The goal is to provide a repeatable, low-overhead test setup for protocol fuzzing against typical network services running on OpenWrt (or on other systems).



In this README file, all example code assumes that the target device has the IP address 192.168.1.1. Replace this value if your target system has a different IP address.

This repository has been developed as part of the TELEMETRY project, a Horizon Europe project funded by the European Union (grant agreement ID 101119747.

---

# Research Architecture

## Architectural Model

```text
Fuzzer - virtual or physical Ubuntu system
│
├── Docker container (fuzz-lab image)
├── Outbound protocol mutation
├── Optional packet capture (tcpdump)
└── Structured output storage (out/<service>/<run_label>/)

                ⇅ network

Target - OpenWrt or other gateway system
│
├── Target service (uhttpd, dnsmasq, dropbear, etc.)
├── Watchdog crash detection
├── System resource monitoring
├── Snapshot generation
└── Controlled service restart
```

---

## Research Philosophy

This framework separates:

### 1. Fuzzing logic (Ubuntu container)

Responsible for:

- Input mutation
- Test case sequencing
- Logging and session management
- Optional packet capture

### 2. Target observability scripts (OpenWrt)

Responsible for:

- Detecting crashes
- Detecting service unavailability
- Resource monitoring (CPU / memory)
- Restarting services when required
- Capturing forensic snapshots

This separation:

- Keeps fuzzing environment reproducible
- Minimizes changes on target
- Prevents logging overload
- Enables controlled recovery
- Preserves test repeatability

---

# Repository Structure

```text
.
├── Dockerfile
├── requirements.txt
├── entrypoint.sh
│
├── config/
│   └── targets.env
│
├── fuzzing_scripts/
│   ├── run_fuzz.sh
│   └── services/
│       ├── http_fuzz.py
│       ├── dns_fuzz.py
│       ├── ssh_fuzz.py
│       ├── sip_fuzz.py
│       └── iperf_fuzz.py
│
├── openwrt/
│   ├── collect_logs_openwrt.sh
│   ├── deploy_scripts_openwrt.sh
│   └── scripts/
│       ├── start_monitors.sh
│       ├── stop_monitors.sh
│       ├── watchdog.sh
│       ├── snapshot.sh
│       ├── process_monitor.sh
│       └── system_monitor.sh
│
├── install-docker-ubuntu.sh
│
└── README.md
```

---

# Quick Start Guide

This fuzzing tool is container based and requires Docker to be installed. If Docker is not installed on the system, it can be installed using the provided install script.

From repository root:

```bash
./install-docker-ubuntu.sh
```

After the installation, add $USER to the docker group:

```bash
sudo usermod -aG docker $USER
```

Restart session (e.g. by logging out and back in) for user group changes to take effect.

## Step 1 - Build the Docker Image

From repository root:

```bash
docker build -t fuzz-lab .
```

Verify:

```bash
docker images | grep fuzz-lab
```

---

## Step 2 - Configure Target Defaults

Edit `config/targets.env`  to set default values for the target IP and port numbers. These values can be overridden when running commands.

Example:

```bash
DEFAULT_TARGET_IP=192.168.1.1
DEFAULT_HTTP_PORT=80
DEFAULT_DNS_PORT=53
DEFAULT_SSH_PORT=22
DEFAULT_SIP_PORT=5060
DEFAULT_IPERF_PORT=5001
```

---

## Step 3 - Deploy Monitoring Scripts to OpenWrt

Deploying and using monitoring scripts requires access to the target system/device.

From Ubuntu:

```bash
cd openwrt
./deploy_openwrt.sh root@192.168.1.1
```

On OpenWrt (first time only):

```sh
chmod +x /tmp/fuzz/*.sh
```

To avoid re-authentication for each ssh or scp command in the script, consider setting up SSH key-based authentication on the target system

---

# Running a Fuzzing Session

Example: HTTP fuzzing.

---

## Step 1 - Start Monitors (OpenWrt)

This step is only possible/relevant if the target is accessible (e.g. via ssh)

```sh
ssh root@192.168.1.1
cd /tmp/fuzz
./start_monitors.sh http
```

This starts:

- System resource monitor
- Process monitor
- Watchdog with restart + snapshot logic

---

## Step 2 - Start Fuzzer (Ubuntu)

```bash
./fuzzing_scripts/run_fuzz.sh http
```

You will be prompted for:

- Target IP
- Target port
- Run label

Output directory:

```text
out/http/<run_label>/
```

View logs:

```bash
docker logs -f fuzz-http-<timestamp>
```

Press `Ctrl+C` to exit log view (container continues running).

Another way to check the progress and status of the fuzzing session is to use the tail command:

```bash
docker logs --tail <number_of_lines> fuzz-http-<timestamp>
```

This dumps raw output from the container and may show more data than what is practical. To filter out e.g. the lines which say "Case XX of YY overall." to see the progress of the fuzzing, the command can be piped to grep:

```bash
docker logs --tail 200 fuzz-http-<timestamp> | grep overall
```

---

## Step 3 - Stop Session

Stop fuzzing container (it is automatically stopped when session completes):

```bash
docker stop fuzz-http-<timestamp>
```

Stop monitors (OpenWrt):

```sh
/tmp/fuzz/stop_monitors.sh
```

---

## Step 4 - Collect OpenWrt Logs

From Ubuntu:

```bash
./tools/collect_openwrt_logs.sh root@192.168.1.1 <session_label_name>
```

Logs stored under:

```text
out/openwrt/session_label_name/
```

---

# Supported Services

| Service | Target Process           | Default Port |
| ------- | ------------------------ | ------------ |
| HTTP    | uhttpd                   | 80           |
| DNS     | dnsmasq                  | 53           |
| SSH     | dropbear                 | 22           |
| SIP     | requires SIP daemon      | 5060         |
| iPerf   | optional server required | 5001         |

Notes:

- SIP requires SIP server installed.
- iPerf requires iperf or iperf3 server running.
- Watchdog restart assumes `/etc/init.d/<service>` exists.

---

# Output Locations

## Fuzzer Output (Ubuntu)

```text
out/<service>/<run_label>/
```

Contains:

- FuzzingLog.txt
- boofuzz session file
- Optional PCAP (if enabled)

---

## OpenWrt Logs

```text
/tmp/fuzz/logs/
```

Contains:

- watchdog logs
- process monitor logs
- system monitor logs
- snapshot files (`snap_*.log`)

Important:
`/tmp` on OpenWrt is RAM-backed. Logs are lost on reboot.

---

# Packet Capture

Packet capture runs inside Docker container (recommended).

Enable capture:

```bash
TCPDUMP_IF=eth0 ./fuzzing_scripts/run_fuzz.sh http
```

The container runs with `NET_ADMIN` and `NET_RAW` capabilities.

This avoids generating heavy PCAP files on OpenWrt.

Packet captures are automatically stored in the output folder (`out/<service>/<run_label>/`)

---

# Passwordless Deployment

To avoid repeated root password prompts:

```bash
ssh-keygen -t ed25519
ssh-copy-id root@192.168.1.1
```

After this, `deploy_openwrt.sh` will run without manual password entry.

---

# Monitoring Design

## Watchdog Features

- Detects port down state
- Optional health checks
- Snapshot cooldown (prevents log explosion)
- Exponential restart backoff
- Restart return code logging

## Snapshot Contents

- `ps` output
- open file descriptors
- memory stats
- kernel messages
- active sockets

This supports post-crash forensic analysis.

---

# Design Notes

- The fuzzing container is made to be fully deterministic.
- Monitoring logic is minimal and ash-compatible.
- Restart logic prevents restart storms.
- Snapshot frequency is controlled.
- Logging kept compact for embedded targets.
- Separation of responsibilities improves reproducibility.

---

# Recommended Workflow

1. Build Docker image
2. Deploy OpenWrt scripts
3. Start monitors
4. Start fuzzing
5. Allow time for edge cases
6. Stop fuzzing (or allow session to complete)
7. Stop monitors and collect logs
8. Analyze snapshots + fuzz logs

---

# Troubleshooting

### Container exits immediately

```bash
docker logs <container_name>
```

Common reasons:

- Python import collision
- Wrong script name
- Target unreachable

---

### Service keeps restarting

On OpenWrt:

```sh
logread | tail -n 100
dmesg | tail -n 100
```

Watch watchdog log:

```text
/tmp/fuzz/logs/<service>_watchdog.log
```

---


