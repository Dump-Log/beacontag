# beacontag

Score pcap conversations for C2-beacon-like periodicity and write the verdict
back into the capture as native Wireshark comments. Open the annotated capture
in Wireshark and filter:

```
frame.comment contains "BEACON"
```

> **Docker only.** The image pins the whole stack (OS, tshark, Python, scipy)
> for reproducible results. All instructions assume the container.

---

## How scoring works

Each IP-pair conversation is collapsed into **check-in sessions** (packets
within a short gap = one check-in) and scored `0-1` on three signals:

- **Timing (primary)** — blended from *MAD/median* of intervals (robust to a
  few bad intervals) and a *Lomb-Scargle periodogram* (frequency-domain test
  that survives **missing** check-ins from packet loss or an asleep host).
- **Count** — more sustained check-ins, more confidence.
- **Size** — consistency of **bytes per check-in session**, so occasional large
  "task pull" check-ins don't sink an otherwise constant-size beacon.

Timing dominates; size only reinforces.
---

## Build

Everything beacontag needs is baked into the image — you only need Docker.

```bash
git clone https://github.com/Dump-Log/beacontag.git
cd beacontag
docker build -t beacontag .
```

By default the container runs as uid/gid `1000` (you, on most single-user Linux
desktops incl. Kali). To guarantee output files on `/data` are owned by you —
whatever your uid — build with your own:

```bash
docker build --build-arg PUID=$(id -u) --build-arg PGID=$(id -g) -t beacontag .
```

The image only reads pcap files (never a live interface), so it needs no
privileged / `NET_RAW` / `--net=host` flags and runs as an unprivileged user.

---

## Usage

The container can only see the directory it mounts at `/data`. drop
your pcap(s) in, and it mounts on every run:

The test file Traffic-Test.pcap is included in the /data directory, it's a simulated traffic example with 2 seperate beacons, both utilizing jitter, 15% and 30%.



**Any `--json` / `--annotate` path must be under `/data`, or the output won't
reach your host.**

### Examples

Basic scan (console only):

```bash
docker run --rm -v "$PWD/data:/data" beacontag /data/capture.pcap
```

Full triage run — JSON report + Wireshark annotation:

```bash
docker run --rm -v "$PWD/data:/data" beacontag /data/capture.pcap \
    --json /data/report.json \
    --annotate /data/annotated.pcapng
```

Widen the net for weaker / higher-jitter beacons (more benign noise appears):

```bash
docker run --rm -v "$PWD/data:/data" beacontag /data/capture.pcap --threshold 0.70
```

Long-sleep beacons — don't merge slow check-ins, require fewer to score:

```bash
docker run --rm -v "$PWD/data:/data" beacontag /data/capture.pcap \
    --session-gap 5 --min-conns 6
```

If output files come out owned by the wrong user (you can't delete them without
`sudo`), either rebuild with the `PUID`/`PGID` args above, or run as yourself:

```bash
docker run --rm --user "$(id -u):$(id -g)" -v "$PWD/data:/data" \
    beacontag /data/capture.pcap --json /data/report.json
```

---

## Options

| Flag | Default | Purpose |
|------|---------|---------|
| `--threshold` | `0.85` | `beacon_score >=` this is flagged. Lower toward 0.70 to widen the net. |
| `--min-conns` | `10` | Minimum check-ins for a conversation to be scored. |
| `--session-gap` | `2.0` | Seconds; packets within this gap collapse into one check-in. |
| `--ls-mix` | `0.35` | Timing blend, Lomb-Scargle vs MAD (`0`=MAD only, `1`=LS only). |
| `--w-timing` / `--w-count` / `--w-size` | `0.65` / `0.20` / `0.15` | Blend weights (auto-normalized). |
| `--json FILE` | — | Write full JSON report. |
| `--annotate FILE` | — | Write annotated pcapng for Wireshark. |

---

## Output

**Console** — a ranked table with separate `MAD` and `LS` columns so you can see
which signal carries each detection.

**JSON** (`--json`) — full per-conversation detail (peers, port, check-ins,
median interval/bytes, every sub-score, frame numbers); both `flagged` and `all`.

**Annotated pcapng** (`--annotate`) — every frame of a flagged conversation gets
a Wireshark comment (first frame verbose, rest short-tagged) plus a
capture-level summary. Pair with a coloring rule on
`frame.comment contains "BEACON"` to make hits pop.

---

## Tuning notes

Defaults (`--threshold 0.85 --ls-mix 0.35 --min-conns 10`) are tuned for
Cobalt Strike-style beacons with one-sided jitter in the common 10-30% band,
where they score ~0.91-0.98. For one-sided jitter MAD is the steadier signal
(the spread stays narrow), which is why `--ls-mix` sits below 0.5; Lomb-Scargle
earns its weight on tight-cadence beacons with many **missing** check-ins. For
higher-jitter or longer-sleep hunting, lower `--threshold` and/or raise
`--session-gap`, and watch the `MAD` vs `LS` columns.

---

## Limitations

- **Benign periodic services flag too** (NTP, telemetry, keepalives). Beacon
  timing is a narrowing filter, not a verdict — corroborate with destination
  reputation, JA3, or process context.
- **DNS-based C2 is out of scope** — it collapses onto one `:53` conversation.
- **Scope is IP-pair cadence** — CDN/domain-fronted traffic sharing an IP with
  benign traffic can be masked.

---
