# stealchecker

Measure QEMU/KVM VM CPU usage and steal time from the virtualization host, with both CLI and Prometheus exporter modes.

## About stealchecker

CPU steal time is time a VM was ready to run but waited for physical CPU time on the virtualization host. Guests can see this with tools such as `top` and `vmstat`, but the host does not expose the same guest-facing value directly.

stealchecker estimates per-VM CPU usage and steal time from the host by reading vCPU process scheduler statistics. It can print a one-shot report for operators or run continuously as a Prometheus exporter for monitoring systems.

## How it works

1. Collect active VM metadata from libvirt
2. Get vCPU thread IDs with `virsh qemu-monitor-command --hmp <domain> info cpus`
3. Read runqueue wait times from `/proc/<pid>/schedstat` for each vCPU thread
4. Calculate per-VM CPU usage and steal time from the scheduler deltas

## Requirements

- Python 3.6 or later
- Linux virtualization host running QEMU/KVM and libvirt
- Permission to access `qemu:///system`
- Permission to run `virsh qemu-monitor-command`
- Root privileges for the `stealchecker` command

## How to install

```
$ pip install stealchecker
```

## Usage

CPU percentages are calculated from deltas, so the first run records the initial sample and reports zero values.

```
$ sudo stealchecker check
Domain Name                     %cpu_use      %cpu_steal
instance-00000001                 48.68%           0.78%
instance-00000002                  0.60%           0.02%
instance-00000003                  2.63%           0.23%
instance-00000004                  6.11%           0.86%
instance-00000005                  1.77%           0.10%
instance-00000006                  3.57%           0.07%
instance-00000007                  0.38%           0.01%
instance-00000008                 33.13%           0.88%
instance-00000009                 17.52%           0.05%
instance-0000000a                 26.37%           0.53%
```

Display domain UUIDs instead of names:

```
$ sudo stealchecker check --uuid
Domain UUID                                     %cpu_use      %cpu_steal
2ab6a587-a844-4377-b7e2-a9380db6e167              41.09%           0.67%
04170a61-4289-4f77-9b3d-b8b1b366afe3               0.35%           0.02%
a53e6892-94cf-494d-9b68-bc97842f618f               2.99%           0.19%
5cf50394-eefd-4f9b-bf02-2c764fa4bdd7               6.32%           0.47%
d506ca79-8014-423d-b9bd-62f8e1dc63c0               1.74%           0.09%
3bd0f56e-6efb-4dd1-aadd-0d03a84020b9               3.04%           0.11%
4ff26ab3-de16-4564-ba58-9e4fdb364272               0.76%           0.05%
09c135aa-679c-44a5-aead-14444eb8088c              33.09%           1.04%
2a50a61e-4179-4b71-a26f-61901cf23cd1               0.98%           0.02%
1df6befa-af2a-4534-938b-44c933d2b3b6              26.57%           0.61%
```

Output JSON:

```
$ sudo stealchecker check --json
```

## Prometheus exporter

Run exporter mode to expose the same per-VM measurements as Prometheus text metrics:

```
$ sudo stealchecker exporter --port 9167
Serving metrics on :9167/metrics
```

Metrics are served from `/metrics`. The exporter keeps the previous scheduler sample in the state file, so the first scrape records the initial sample and later scrapes report calculated deltas.

```
steal_cpu_use{name="instance-00000001",uuid="2ab6a587-a844-4377-b7e2-a9380db6e167"} 0.486800
steal_cpu_steal{name="instance-00000001",uuid="2ab6a587-a844-4377-b7e2-a9380db6e167"} 0.007800
```

Example Prometheus scrape config:

```
scrape_configs:
  - job_name: stealchecker
    static_configs:
      - targets:
          - virtualization-host.example.com:9167
```

A sample systemd unit is available at `contrib/systemd/stealchecker-exporter.service`.

## Configuration

The default state file is `/run/stealchecker/last_steal.json`. It can be changed with `STEALCHECKER_STATE_FILE`.

The default command timeout is 10 seconds. It can be changed with `STEALCHECKER_COMMAND_TIMEOUT`.
