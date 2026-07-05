#!/usr/bin/env python3
"""
beacontag -- C2 beacon scorer that annotates pcaps for Wireshark.
(Reads via tshark; writes annotated pcapng comments programmatically.)

Scores network conversations for C2-beacon-like periodicity using a RITA-style
methodology (Black Hills InfoSec): real beacons check in at a near-constant
cadence with consistent per-check-in payload sizes, while human/web traffic is
bursty and irregular. Writes the verdict back into the capture as native
Wireshark comments -- filter: frame.comment contains "BEACON".

Timing is scored TWO ways and blended:
  * MAD/median of inter-session intervals -- robust to a few bad intervals.
  * Lomb-Scargle periodogram over binned check-ins -- a frequency-domain test
    that stays strong when check-ins are MISSING (host asleep, packet loss),
    the case where consecutive-interval methods degrade.

Size regularity is scored on BYTES-PER-CHECK-IN-SESSION (not per packet): a
beacon's check-ins are near-constant in size, with occasional larger task
pulls that MAD/median shrugs off.

Requires tshark on PATH (ships with Wireshark) for reading, scapy for writing
the annotated pcapng, and scipy+numpy for the Lomb-Scargle timing test.

Usage:
  python3 beacontag.py <capture.pcap> [--annotate out.pcapng]
                       [--json report.json] [--threshold 0.85] [--min-conns 10]
"""
import argparse
import json
import math
import os
import shutil
import statistics
import subprocess
import sys
from collections import defaultdict

import numpy as _np
from scipy.signal import lombscargle as _lombscargle


def require_tool(name):
    path = shutil.which(name)
    if not path:
        print("error: '%s' not found on PATH (install Wireshark CLI tools)." % name,
              file=sys.stderr)
        sys.exit(2)
    return path


# ---------------------------------------------------------------------------
# Ingestion (tshark)
# ---------------------------------------------------------------------------

def ingest(path):
    """Return [(frame_no, epoch_time, src, dst, dport, size)] via tshark."""
    tshark = require_tool("tshark")
    cmd = [
        tshark, "-r", path, "-T", "fields",
        "-e", "frame.number", "-e", "frame.time_epoch",
        "-e", "ip.src", "-e", "ip.dst",
        "-e", "tcp.dstport", "-e", "udp.dstport",
        "-e", "frame.len",
        "-E", "separator=,", "-E", "occurrence=f",
    ]
    out = subprocess.check_output(cmd, stderr=subprocess.DEVNULL).decode("utf-8", "replace")
    rows = []
    for line in out.splitlines():
        parts = line.split(",")
        if len(parts) < 7:
            continue
        fno, tepoch, src, dst, tport, uport, length = parts[:7]
        if not src or not dst:
            continue
        dport = tport or uport
        if not dport:
            continue
        try:
            rows.append((int(fno), float(tepoch), src, dst, int(dport), int(length)))
        except ValueError:
            continue
    return rows


# ---------------------------------------------------------------------------
# Scoring
# ---------------------------------------------------------------------------

def canonical_conv(src, dst, dport):
    """Conversation key = the unordered IP pair (port resolved later per pair)."""
    a, b = sorted([src, dst])
    return (a, b)


def madm_score(values):
    """1 - MAD/median, clamped to [0,1]. High = very regular. Used for both
    interval regularity and per-session byte regularity."""
    if len(values) < 2:
        return 0.0
    med = statistics.median(values)
    if med <= 0:
        return 0.0
    mad = statistics.median([abs(x - med) for x in values])
    return max(0.0, min(1.0, 1.0 - (mad / med)))


def conn_count_score(n):
    """More check-ins -> more confidence. Saturates around 24."""
    return max(0.0, min(1.0, n / 24.0))


def lomb_scargle_score(event_times, min_cycles=3, lo=8.0, hi=100.0):
    """Frequency-domain periodicity score in [0,1] via a Lomb-Scargle
    periodogram of the binned check-in series. Unlike MAD on consecutive
    intervals, a missing check-in (gap) barely dents the dominant spectral
    peak, so this catches gapped/lossy beacons that consecutive-interval
    methods miss.

    Returns (score, best_period_s, prominence). If there is too little signal
    to score, returns (0.0, None, 0.0).

    Scoring: prominence = peak_power / median_power across the frequency grid
    (scale-free, robust). Mapped log-linearly so a noise-floor prominence ~lo
    scores 0 and a sharp beacon peak ~hi scores 1 (calibrated empirically on
    clean/gapped/jitter/bursty synthetic beacons)."""
    t = _np.asarray(event_times, dtype=float)
    if t.size < 6:  # need enough events for a meaningful spectrum
        return 0.0, None, 0.0
    t = t - t[0]
    window = float(t[-1])
    if window <= 0:
        return 0.0, None, 0.0
    med_gap = float(_np.median(_np.diff(t)))
    if med_gap <= 0:
        return 0.0, None, 0.0

    # Bin the point process into a regular count series (cap the bin count so
    # long, sparse captures don't blow up the grid).
    dt = max(med_gap / 8.0, window / 4096.0)
    nbins = int(_np.ceil(window / dt)) + 1
    counts = _np.zeros(nbins)
    for i in _np.clip(_np.floor(t / dt).astype(int), 0, nbins - 1):
        counts[i] += 1.0
    y = counts - counts.mean()
    if not _np.any(y):
        return 0.0, None, 0.0
    x = _np.arange(nbins) * dt

    # Candidate periods: need >= min_cycles cycles in the window (P <= W/min_cycles),
    # down to the bin-grid Nyquist (~2*dt) or half the median gap.
    p_max = window / min_cycles
    p_min = max(2.0 * dt, med_gap / 2.0)
    if p_min >= p_max:
        return 0.0, None, 0.0
    freqs = _np.linspace(1.0 / p_max, 1.0 / p_min, 2000)
    power = _lombscargle(x, y, 2.0 * _np.pi * freqs, precenter=True, normalize=True)

    peak = float(power.max())
    med_power = float(_np.median(power))
    if med_power <= 0:
        return 0.0, None, 0.0
    prominence = peak / med_power
    # Report the FUNDAMENTAL period: the longest period among peaks within 90%
    # of the max, so a strong 2nd/3rd harmonic doesn't misreport the cadence.
    near = freqs[power >= 0.9 * peak]
    best_period = float(1.0 / near.min())

    score = (math.log10(prominence) - math.log10(lo)) / (math.log10(hi) - math.log10(lo))
    return max(0.0, min(1.0, score)), best_period, prominence


def collapse_to_sessions(pkts, gap=2.0):
    """Group time-sorted (t, size, fno) packets into check-in sessions: any
    packets within `gap` seconds of the running session belong to one check-in.
    Returns a list of sessions, each a dict with the session start time, total
    bytes, and packet count. Scoring cadence BETWEEN sessions (not raw packet
    spacing) is what separates a periodic beacon from bursty human traffic;
    aggregating bytes WITHIN a session is what makes the size signal reflect
    real per-check-in payload rather than per-packet noise."""
    if not pkts:
        return []
    sessions = []
    s_start = pkts[0][0]
    s_last = pkts[0][0]
    s_bytes = pkts[0][1]
    s_count = 1
    for t, size, _fno in pkts[1:]:
        if t - s_last > gap:
            sessions.append({"start": s_start, "bytes": s_bytes, "packets": s_count})
            s_start = t
            s_bytes = 0
            s_count = 0
        s_bytes += size
        s_count += 1
        s_last = t
    sessions.append({"start": s_start, "bytes": s_bytes, "packets": s_count})
    return sessions


def service_port_for_pair(ports):
    """Pick the service port: the lowest observed port for the pair. The service
    side is (almost) always numerically lower than the OS-assigned ephemeral
    client port, so min() is a robust, assumption-light choice."""
    return min(ports)


def score_conversations(rows, min_conns, session_gap=2.0,
                        w_timing=0.65, w_count=0.20, w_size=0.15,
                        ls_mix=0.5):
    # Normalise the blend weights so the score stays in [0,1] regardless of the
    # values passed (they need not sum to 1).
    w_total = w_timing + w_count + w_size
    if w_total <= 0:
        w_total = 1.0
    ls_mix = max(0.0, min(1.0, ls_mix))

    pair_pkts = defaultdict(list)   # (a,b) -> [(t,size,fno)]
    pair_ports = defaultdict(set)   # (a,b) -> {ports}
    for fno, t, src, dst, dport, size in rows:
        key = canonical_conv(src, dst, dport)
        pair_pkts[key].append((t, size, fno))
        pair_ports[key].add(dport)

    results = []
    for key, pkts in pair_pkts.items():
        pkts.sort(key=lambda x: x[0])
        sessions = collapse_to_sessions(pkts, gap=session_gap)
        if len(sessions) < min_conns:
            continue

        starts = [s["start"] for s in sessions]
        intervals = [starts[i + 1] - starts[i] for i in range(len(starts) - 1)]
        sess_bytes = [s["bytes"] for s in sessions]

        # --- timing: blend MAD (robust to a few bad intervals) with
        #     Lomb-Scargle (robust to MISSING check-ins). ---
        s_mad = madm_score(intervals)
        s_ls, ls_period, ls_prom = lomb_scargle_score(starts)
        if s_ls > 0:
            s_time = (1.0 - ls_mix) * s_mad + ls_mix * s_ls
        else:
            # Too few check-ins for a meaningful spectrum -- use MAD alone
            # rather than blending in a spurious zero.
            s_time = s_mad

        s_cnt = conn_count_score(len(sessions))
        # --- size: consistency of BYTES PER CHECK-IN SESSION. MAD/median means
        #     a few large "task pull" check-ins don't sink an otherwise
        #     constant-size beacon (RITA's data-skew intuition). ---
        s_size = madm_score(sess_bytes)

        # Timing regularity is the PRIMARY, durable beacon signal (a beacon
        # beacons on a schedule regardless of payload size). Size reinforces;
        # real C2 varies payload to evade size detection, so it can't sink a
        # beacon on its own. Weights configurable and normalised to keep [0,1].
        score = (w_timing * s_time + w_count * s_cnt + w_size * s_size) / w_total

        a, b = key
        results.append({
            "peer_a": a, "peer_b": b,
            "dport": service_port_for_pair(pair_ports[key]),
            "check_ins": len(sessions),
            "median_interval_s": round(statistics.median(intervals), 3),
            "median_session_bytes": int(statistics.median(sess_bytes)),
            "timing_score": round(s_time, 3),
            "timing_mad": round(s_mad, 3),
            "timing_lombscargle": round(s_ls, 3),
            "ls_period_s": round(ls_period, 3) if ls_period else None,
            "ls_prominence": round(ls_prom, 1) if ls_prom else None,
            "count_score": round(s_cnt, 3),
            "size_score": round(s_size, 3),
            "beacon_score": round(score, 3),
            "frames": [p[2] for p in pkts],
        })

    results.sort(key=lambda r: -r["beacon_score"])
    return results


# ---------------------------------------------------------------------------
# Annotation (programmatic pcapng comments -- Wireshark-visible)
# ---------------------------------------------------------------------------

def annotate(in_pcap, out_pcapng, flagged):
    """Write an annotated pcapng where EVERY frame of each flagged conversation
    carries a comment: the first frame gets full verbose detail, every
    subsequent frame a short tag referencing the conversation. An analyst who
    lands anywhere in the capture still sees the flag, and
    `frame.comment contains "BEACON"` returns the whole conversation. Done
    programmatically (not via editcap) so there is no command-line-length limit
    when a conversation has thousands of frames."""
    from pcapng_writer import write_pcapng_with_comments

    comment_by_frame = {}
    for f in flagged:
        frames = sorted(f["frames"])
        conv = "%s<->%s:%d" % (f["peer_a"], f["peer_b"], f["dport"])
        # Full breakdown on the first frame of the conversation: the blended
        # score plus every sub-signal, so an analyst has the complete picture
        # inside Wireshark without needing the JSON report alongside.
        ls_period = f["ls_period_s"] if f["ls_period_s"] is not None else 0.0
        ls_prom = f["ls_prominence"] if f["ls_prominence"] is not None else 0.0
        comment_by_frame[frames[0]] = (
            "BEACON suspect  score=%.2f  peers=%s\n"
            "check-ins=%d  median_interval=%.1fs  median_session_bytes=%d\n"
            "timing_score=%.2f (MAD=%.2f, Lomb-Scargle=%.2f)  "
            "size_score=%.2f  count_score=%.2f\n"
            "LS_period=%.1fs  LS_prominence=%.1f" % (
                f["beacon_score"], conv,
                f["check_ins"], f["median_interval_s"], f["median_session_bytes"],
                f["timing_score"], f["timing_mad"], f["timing_lombscargle"],
                f["size_score"], f["count_score"],
                ls_period, ls_prom))
        short = "BEACON %s" % conv
        for fr in frames[1:]:
            comment_by_frame[fr] = short

    if flagged:
        summary = "beacontag: %d beacon suspect(s): " % len(flagged) + "; ".join(
            "%s<->%s:%d score=%.2f interval=%.1fs bytes=%d" % (
                f["peer_a"], f["peer_b"], f["dport"], f["beacon_score"],
                f["median_interval_s"], f["median_session_bytes"])
            for f in flagged)
    else:
        summary = "beacontag: no beacon suspects found"

    write_pcapng_with_comments(in_pcap, out_pcapng, comment_by_frame,
                               capture_comment=summary)


# ---------------------------------------------------------------------------

def main():
    ap = argparse.ArgumentParser(description="Score conversations for C2 beaconing and annotate for Wireshark.")
    ap.add_argument("pcap", help="input capture (.pcap/.pcapng)")
    ap.add_argument("--annotate", metavar="OUT.pcapng", help="write annotated pcapng for Wireshark")
    ap.add_argument("--json", metavar="REPORT.json", help="write full JSON report")
    ap.add_argument("--threshold", type=float, default=0.85, help="beacon_score >= this is flagged (default 0.85)")
    ap.add_argument("--min-conns", type=int, default=10, help="min check-ins to score a conversation (default 10)")
    ap.add_argument("--session-gap", type=float, default=2.0,
                    help="seconds; packets within this gap collapse into one check-in event (default 2.0)")
    ap.add_argument("--w-timing", type=float, default=0.65,
                    help="scoring weight for timing regularity (default 0.65)")
    ap.add_argument("--w-count", type=float, default=0.20,
                    help="scoring weight for connection count (default 0.20)")
    ap.add_argument("--w-size", type=float, default=0.15,
                    help="scoring weight for per-session size regularity (default 0.15)")
    ap.add_argument("--ls-mix", type=float, default=0.35,
                    help="within timing, blend of Lomb-Scargle vs MAD: 0=MAD only, "
                         "1=Lomb-Scargle only (default 0.35)")
    args = ap.parse_args()

    if not os.path.isfile(args.pcap):
        print("no such file: %s" % args.pcap, file=sys.stderr)
        sys.exit(1)

    rows = ingest(args.pcap)
    results = score_conversations(rows, args.min_conns,
                                  session_gap=args.session_gap,
                                  w_timing=args.w_timing,
                                  w_count=args.w_count,
                                  w_size=args.w_size,
                                  ls_mix=args.ls_mix)
    flagged = [r for r in results if r["beacon_score"] >= args.threshold]

    print("=" * 84)
    print("beacontag  --  %s" % os.path.basename(args.pcap))
    print("=" * 84)
    print("Scored %d conversations (>= %d check-ins). Threshold=%.2f"
          % (len(results), args.min_conns, args.threshold))
    print("")
    print("%-38s %6s %9s %7s %5s %5s %6s" % ("conversation", "chkins", "interval",
                                             "bytes", "MAD", "LS", "score"))
    print("-" * 84)
    for r in results:
        tag = "  <== BEACON" if r["beacon_score"] >= args.threshold else ""
        conv = "%s<->%s:%d" % (r["peer_a"], r["peer_b"], r["dport"])
        print("%-38s %6d %8.1fs %7d %5.2f %5.2f %6.2f%s" % (
            conv[:38], r["check_ins"], r["median_interval_s"],
            r["median_session_bytes"], r["timing_mad"], r["timing_lombscargle"],
            r["beacon_score"], tag))
    print("")
    print("Flagged %d beacon suspect(s)." % len(flagged))

    if args.json:
        with open(args.json, "w") as fh:
            json.dump({"pcap": os.path.basename(args.pcap),
                       "threshold": args.threshold,
                       "flagged": flagged, "all": results}, fh, indent=2)
        print("JSON report: %s" % args.json)

    if args.annotate:
        annotate(args.pcap, args.annotate, flagged)
        print("Annotated capture written: %s" % args.annotate)
        print("  Open in Wireshark and filter: frame.comment contains \"BEACON\"")

    print("=" * 84)


if __name__ == "__main__":
    main()
