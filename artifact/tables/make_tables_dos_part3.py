#!/usr/bin/env python3
"""Builds every table of part 2 (DoS flood grid) from <stage dir>/raw/dos_flood.json.

Run: python3 make_tables_dos_part3.py   (writes tables_dos_part3.md next to this file)
Every directory next to this file that holds raw/dos_flood.json is one stage.
"""
import glob, json, math, os, statistics as st

import os as _os
import sys as _sys
_sys.path.insert(0, _os.path.dirname(_os.path.abspath(__file__)))
from results_dir import study_dir
ROOT = study_dir("part3")
TARGET_MHZ = 3169.0
FREQ_TOLERANCE = 0.02
PROBE_INTERVAL_S = 0.2
KIND_ORDER = ["none", "handshake", "hello", "auth", "uchunk", "partial", "vpoint", "fullkey", "churn2"]
SYSTEM_ORDER = ["stateless", "stateful"]
SHAPE_ORDER = ["single", "botnet"]
TABLE_KINDS = ("partial", "churn2")
SPOT_CHECK_SENT_RESIDUAL_PCT = 5.0

# Criterion medians of part 1 (us), cross-check of the measured cost per request.
CRITERION_US = {
    ("stateless", "handshake"): {"hqc1": 40.159, "hqc3": 72.786, "hqc5": 85.428},
    ("stateless", "auth"): {"hqc1": 33.299, "hqc3": 65.454, "hqc5": 77.948},
    ("stateless", "uchunk"): {"hqc1": 36.884, "hqc3": 72.350, "hqc5": 137.332},
    ("stateless", "vpoint"): {"hqc1": 40.101, "hqc3": 60.546, "hqc5": 85.453},
    ("stateful", "hello"): {"hqc1": 38.411, "hqc3": 71.261, "hqc5": 83.788},
    ("stateful", "auth"): {"hqc1": 33.109, "hqc3": 65.973, "hqc5": 78.220},
}

out = []
def p(s=""): out.append(s)
def table(head, rows):
    p("| " + " | ".join(head) + " |"); p("|" + "---|" * len(head))
    for r in rows: p("| " + " | ".join(str(c) for c in r) + " |")
    p()
def mean(v): return sum(v) / len(v) if v else None
def sd(v): return st.stdev(v) if len(v) > 1 else 0.0
def ms(v, d=2, scale=1.0):
    v = [x * scale for x in v if x is not None]
    return "-" if not v else f"{mean(v):.{d}f} ± {sd(v):.{d}f}"
def col(reps, key): return [r[key] for r in reps if isinstance(r.get(key), (int, float))]
def pct(v, d=1): return ms(v, d, 100)
def rank(sorted_v, q):
    return sorted_v[max(1, math.ceil(q * len(sorted_v))) - 1] if sorted_v else None
def fs(x, d=3): return "-" if x is None else f"{x:.{d}f}"


def load_stages():
    stages = []
    for path in sorted(glob.glob(f"{ROOT}/*/raw/dos_flood.json")):
        d = os.path.dirname(os.path.dirname(path))
        grid = json.load(open(path))
        state = json.load(open(f"{d}/raw/run_state_dos_flood.json"))
        stages.append({"dir": os.path.basename(d), "grid": grid, "state": state,
                       "prov": open(f"{d}/raw/provenance.txt").read() if os.path.exists(f"{d}/raw/provenance.txt") else ""})
    stages.sort(key=lambda s: s["grid"]["meta"]["timestamp"])
    return stages


def stage_label(s):
    m = s["grid"]["meta"]
    return f"{'+'.join(m['variants'])} rtt {','.join(map(str, m['rtts_ms']))} ms"


def cell_sort(entry):
    c = entry["cell"]
    return (entry["rtt_ms"], c["variant"], SYSTEM_ORDER.index(c["system"]), SHAPE_ORDER.index(c["shape"]),
            KIND_ORDER.index(c["kind"]), c["cap"] or 0)


def name(entry):
    c = entry["cell"]
    return f"{c['system']} {c['variant']} {c['shape']} {c['kind']}" + (f" cap{c['cap']}" if c["cap"] and c["system"] == "stateful" and c["kind"] in TABLE_KINDS else "")


def entries(stage):
    return sorted(stage["grid"]["cells"].values(), key=cell_sort)


def rtt_not_applied(e):
    """The delay is added to the legit address only; an idle probe must take at least one RTT."""
    rtt = e["rtt_ms"] / 1000
    return rtt > 0 and mean(col(e["reps"], "legit_idle_p50_s")) < rtt


def bad_responses(r):
    """The harness reads the response counter with a UDP query to the flooded server; when that query is
    lost the delta silently becomes 0. A flooded rep with 0 responses is therefore a missing value."""
    return r["server_responses_sent"] == 0 and r["attacker_packets_sent"] > 0


def good_resp_reps(e):
    return [r for r in e["reps"] if not bad_responses(r)]


def has_flood(e): return e["cell"]["kind"] != "none"


def setup_s(r):
    return (r.get("flood_client_json") or {}).get("attack_started_secs") or 0.0


def attack_probes(r):
    return [q for q in r["probes"] if q["phase"] == "flood" and q["start_offset_s"] >= setup_s(r)]


STEADY_MARGIN_S = 5.0


def steady_probes(r):
    """Attack-phase probes that start at least STEADY_MARGIN_S before the flood ends, so a probe with a
    5 s deadline cannot be rescued by the end of the flood."""
    return [q for q in attack_probes(r) if q["start_offset_s"] <= r["flood_window_s"] - STEADY_MARGIN_S]


def steady_rate(rs, limit):
    rates = []
    for r in rs:
        pr = steady_probes(r)
        if pr: rates.append(sum(1 for q in pr if q["ok"] and q["latency_s"] <= limit) / len(pr))
    return rates


def cpu_attack_s(r):
    if "cpu_util_pct_attack_phase" not in r: return None
    return r["cpu_util_pct_attack_phase"] / 100 * r["attack_phase_s"]


def mhz(stage):
    s = stage["state"]
    return st.mean(st.median(v["samples_mhz"]) for ph in ("start", "end") for v in s[ph]["frequency_under_load"].values())


# ------------------------------------------------------------------ tables
def provenance(stages):
    p("## Provenance and clock check\n")
    rows = []
    for s in stages:
        st_ = s["state"]
        def fr(ph): return "/".join(f"{st.median(v['samples_mhz']):.1f}" for v in st_[ph]["frequency_under_load"].values())
        extreme = [x for ph in ("start", "end") for v in st_[ph]["frequency_under_load"].values() for x in v["samples_mhz"]]
        dev = max(abs(x - TARGET_MHZ) for x in extreme) / TARGET_MHZ * 100
        viol = len(st_["start"]["violations"]) + len(st_["end"]["violations"])
        ok = "OK" if dev <= FREQ_TOLERANCE * 100 and viol == 0 else "FAIL"
        rows.append([s["dir"], stage_label(s), st_["git"]["commit"][:7], st_["git"]["dirty"], fr("start"), fr("end"),
                     f"{dev:.3f}", viol, ok])
    table(["dir", "stage", "commit", "dirty", "cpu0/2/4 MHz start", "cpu0/2/4 MHz end", "max sample deviation from 3169 (%)", "violations", "2% check"], rows)


def commands(stages):
    path = f"{ROOT}/campaign_part2.stages"
    if os.path.exists(path):
        p("## Stage log (campaign_part2.stages)\n")
        p("```"); p(open(path).read().strip()); p("```\n")
    for s in stages:
        m = s["grid"]["meta"]
        p(f"- `{s['dir']}`: reps {m['reps']}, duration {m['duration_s']} s after set-up, variants {m['variants']}, RTTs {m['rtts_ms']} ms, caps {m['caps']}, seed {m['seed']}, probe interval {m['probe_interval_ms']} ms, probe timeout {m['probe_timeout_s']} s, sockets single {m['knobs']['SINGLE_HOST_SOCKETS']} / botnet {m['knobs']['BOTNET_SOCKETS']} on {m['knobs']['BOTNET_IPS']} addresses.")
    p()


def qc(stages):
    p("## Quality control\n")
    rows = []
    for s in stages:
        es = entries(s)
        n_reps = s["grid"]["meta"]["reps"]
        failed = sum(len(e["failed_reps"]) for e in es)
        short = [name(e) for e in es if len(e["reps"]) != n_reps]
        errors = sum(1 for e in es for r in e["reps"] if "flood_error" in r)
        sl = [r for e in es if e["cell"]["system"] == "stateless" for r in e["reps"]]
        sl_rss = max(r["peak_rss_growth_kb"] for r in sl); sl_set = max(r["rss_after_settle_growth_kb"] for r in sl)
        sl_tbl = sum(1 for r in sl if "peak_table_bytes" in r)
        fl = [(e, r) for e in es if has_flood(e) for r in e["reps"]]
        cpus = [r["cpu_util_pct_attack_phase"] for e, r in fl if "cpu_util_pct_attack_phase" in r]
        noattack = sum(1 for e, r in fl if r.get("attack_phase_s", 1) <= 0)
        not_sched = sum(1 for e in es for r in e["reps"] if r.get("cpu_source") != "schedstat")
        rows.append([f"{s['dir']} ({stage_label(s)})", f"{len(es)} cells, {sum(len(e['reps']) for e in es)} reps", f"{failed} failed reps, {errors} flood errors, {len(short)} short cells",
                     f"{sl_rss:g} / {sl_set:g} kB, {sl_tbl} rows with table stats", f"{min(cpus):.1f}-{max(cpus):.1f}", noattack, not_sched])
    table(["stage", "grid", "completeness", "stateless max peak RSS growth / after settle; table rows", "attack-phase CPU % min-max over all flood reps", "reps with no attack phase", "reps not on schedstat"], rows)

    for s in stages:
        p(f"### Per-cell checks, {s['dir']} ({stage_label(s)})\n")
        p("Probe coverage = attack-phase probes per rep / (attack_phase_s / 0.2 s). Last probe gap = flood window end minus the start of the last flood-phase probe (s). Residual = (packets sent - kernel drops - server responses) / packets sent; it should be near 0 for kinds that get one answer per delivered packet (stateless all; stateful hello/auth) and is large by design for partial, fullkey, churn2.\n")
        rows = []
        for e in entries(s):
            if not has_flood(e): continue
            rs = e["reps"]
            cov = [len(attack_probes(r)) / (r["attack_phase_s"] / PROBE_INTERVAL_S) for r in rs if r.get("attack_phase_s", 0) > 0]
            gaps = [r["flood_window_s"] - max(q["start_offset_s"] for q in r["probes"] if q["phase"] == "flood") for r in rs]
            pps = col(rs, "attacker_packets_per_s_attack_phase")
            cv = sd(pps) / mean(pps) * 100 if pps else 0
            res = [(r["attacker_packets_sent"] - r["kernel_udp_drops"] - r["server_responses_sent"]) / r["attacker_packets_sent"] * 100 for r in good_resp_reps(e)]
            flags = []
            if len(good_resp_reps(e)) < len(rs): flags.append(f"RESPONSE-COUNTER-LOST-IN-{len(rs) - len(good_resp_reps(e))}-REP(S)")
            if min(cov) < 0.9: flags.append("COVERAGE<0.9")
            if max(gaps) > 0.5: flags.append("LAST-PROBE-GAP")
            if cv > 10: flags.append("PPS-CV>10%")
            if min(col(rs, "cpu_util_pct_attack_phase")) < 90: flags.append("CPU<90%")
            if len(rs) < s["grid"]["meta"]["reps"]: flags.append("MISSING-REPS")
            if rtt_not_applied(e): flags.append("RTT-NOT-APPLIED")
            rows.append([name(e), f"rtt {e['rtt_ms']}", f"{min(cov):.2f}-{max(cov):.2f}", f"{min(gaps):.2f}-{max(gaps):.2f}", f"{cv:.1f}", ms(res, 1), " ".join(flags) or "ok"])
        table(["cell", "rtt", "probe coverage min-max", "last probe gap s min-max", "attacker pps CV % (between reps)", "residual % mean±sd", "flags"], rows)


def main_tables(stage):
    es = entries(stage)
    f = mhz(stage) * 1e6
    p(f"## Stage {stage['dir']} ({stage_label(stage)})\n")
    p(f"Values are mean ± sd over {stage['grid']['meta']['reps']} repetitions unless stated. Attack phase = after the flood client finished its set-up (`attack_started_s`). Clock {mhz(stage):.1f} MHz.\n")
    for rtt in sorted({e["rtt_ms"] for e in es}):
        sub = [e for e in es if e["rtt_ms"] == rtt]
        p(f"### Load on the server, rtt {rtt} ms ({stage['dir']})\n")
        rows = []
        for e in sub:
            rs = e["reps"]
            fl = has_flood(e)
            rows.append([name(e), len(rs), ms(col(rs, "attack_started_s"), 2) if fl else "-", ms(col(rs, "attack_phase_s"), 2) if fl else "-",
                         ms(col(rs, "cpu_util_pct_attack_phase"), 1) if fl else f"{ms(col(rs, 'cpu_util_pct'), 1)} (window)",
                         ms(col(rs, "attacker_packets_per_s_attack_phase"), 1, 1e-3) if fl else "-",
                         ms(col(good_resp_reps(e), "server_responses_per_s"), 0) + (f" (n={len(good_resp_reps(e))})" if len(good_resp_reps(e)) < len(rs) else ""), ms(col(rs, "kernel_udp_drops"), 3, 1e-6) if fl else "0"])
        table(["cell", "reps", "set-up s", "attack s", "server CPU % (attack phase)", "attacker kpkt/s (attack phase)", "server responses/s (whole window)", "kernel drops M (whole window)"], rows)

        p(f"### Memory and table growth, rtt {rtt} ms ({stage['dir']})\n")
        p("`peak RSS` is the maximum RSS growth over idle during the flood. Stateless rows have no table. `watched` = counters of the legit client's source address (the server watches 127.2.0.1). `armed` = cookies the flood client obtained (stateful partial/fullkey: sockets that can send fragments).\n")
        rows = []
        for e in sub:
            rs = e["reps"]; stf = e["cell"]["system"] == "stateful"
            g = lambda k, d=0, sc=1.0: ms(col(rs, k), d, sc) if stf else "-"
            armed = ms([(r.get("flood_client_json") or {}).get("cookies_obtained") for r in rs], 0) if has_flood(e) and stf else "-"
            rows.append([name(e), ms(col(rs, "peak_rss_growth_kb"), 0), ms(col(rs, "rss_after_settle_growth_kb"), 0),
                         g("peak_table_entries"), g("peak_table_bytes"), g("table_entries_end"), g("d_entries_created"),
                         g("d_evictions"), g("d_dropped_table_full"), g("d_dropped_source_limit"), g("d_timeouts"),
                         f"{g('d_watched_created')} / {g('d_watched_evictions')} / {g('d_watched_timeouts')}", armed])
        table(["cell", "peak RSS growth kB", "RSS growth after settle kB", "peak table entries", "peak table bytes", "table entries at end", "entries created", "evictions", "dropped_table_full", "dropped_source_limit", "timeouts", "watched created / evicted / timed out", "armed"], rows)

        p(f"### Legitimate probes during the attack phase, rtt {rtt} ms ({stage['dir']})\n")
        p("Success rates: mean ± sd over reps of the per-rep rate (a probe is a full legit session; failed = non-zero exit or 10 s timeout). Latency columns pool the successful attack-phase probes of all reps (nearest rank). `fail` = pooled share of probes that failed. `done in flood` = share of probes that finished before the flood ended. `steady` = same success rates over the probes that started at least 5 s before the flood ended, so the end of the flood cannot rescue them (probes started in the last seconds of a flood finish after it and count as successes in the plain columns). `idle p50` = median of the 3 probes before the flood.\n")
        rows = []
        for e in sub:
            rs = e["reps"]
            pooled = [q for r in rs for q in attack_probes(r)]
            okl = sorted(q["latency_s"] for q in pooled if q["ok"])
            n = len(pooled); fail = sum(1 for q in pooled if not q["ok"])
            rec = f"{sum(r['recovery_ok'] for r in rs)}/{sum(r['recovery_n'] for r in rs)}"
            if has_flood(e):
                s1, s5, dn = (pct(col(rs, k)) for k in ("legit_success_within_1s_attack", "legit_success_within_5s_attack", "legit_frac_completed_during_flood_attack"))
            else:
                s1, s5, dn = (pct(col(rs, k)) for k in ("legit_success_within_1s", "legit_success_within_5s", "legit_frac_completed_during_flood"))
            rows.append([name(e), f"{n / len(rs):.1f}", s1, s5, fs(rank(okl, .5)), fs(rank(okl, .9)), fs(rank(okl, .99)), fs(okl[-1] if okl else None),
                         f"{fail / n * 100:.1f}" if n else "-", dn, pct(steady_rate(rs, 1.0)), pct(steady_rate(rs, 5.0)), rec, fs(mean(col(rs, "legit_idle_p50_s")), 4), "NO" if rtt_not_applied(e) else ("yes" if e["rtt_ms"] else "-")])
        table(["cell", "probes/rep", "success <=1 s %", "success <=5 s %", "p50 s", "p90 s", "p99 s", "max s", "fail %", "done in flood %", "steady <=1 s %", "steady <=5 s %", "recovery ok", "idle p50 s", "RTT applied"], rows)

        p(f"### Server CPU cost per request, rtt {rtt} ms ({stage['dir']})\n")
        p("Cost = CPU seconds of all server threads / count, then x1e6 for us and x clock for cycles. `per answered request` uses the whole flood window (CPU and responses are both whole-window figures; it includes the few legit probes, <1 %). Cells with a long set-up (stateful botnet partial/fullkey) use attack-phase CPU and `responses - cookies obtained` and are marked `*` (approximate). `per delivered packet` = attack-phase CPU / (attacker packets - kernel drops); set-up-phase drops are not separable, so botnet partial/fullkey numbers are lower bounds of the cost. Cycles per byte divide by delivered bytes (packets x packet size; churn2 mixes sizes: -). `/B sent` divides by all bytes the attacker sent. Criterion = part 1 median for the matching request (hello/auth/stateless kinds only).\n")
        rows = []
        for e in sub:
            if not has_flood(e): continue
            c = e["cell"]; rs = e["reps"]
            slow_setup = mean([setup_s(r) for r in rs]) > 1.0
            per_resp, per_pkt, cyc_dB, cyc_sB = [], [], [], []
            for r in rs:
                cpu_w, cpu_a = r["cpu_seconds"], cpu_attack_s(r)
                if bad_responses(r): continue
                resp = r["server_responses_sent"] - ((r.get("flood_client_json") or {}).get("cookies_obtained") or 0) * slow_setup
                cpu_r = cpu_a if slow_setup else cpu_w
                if resp > 0: per_resp.append(cpu_r / resp)
                sent, drops = r["attacker_packets_sent"], r["kernel_udp_drops"]
                if cpu_a is not None and sent - drops > 0:
                    per_pkt.append(cpu_a / (sent - drops))
                    pb = (r.get("flood_client_json") or {}).get("packet_bytes")
                    if pb:
                        cyc_dB.append(cpu_a * f / ((sent - drops) * pb)); cyc_sB.append(cpu_a * f / (sent * pb))
            crit = CRITERION_US.get((c["system"], c["kind"]), {}).get(c["variant"])
            star = "*" if slow_setup else ""
            resp_cell = ms(per_resp, 1, 1e6) + star if per_resp else "-"
            answers_all = c["kind"] in ("handshake", "hello", "auth", "uchunk", "vpoint")
            if not answers_all:
                resp_cell = "- (server answers few of the packets)"
            rows.append([name(e), resp_cell, ms([x * f for x in per_resp], 0) if answers_all else "-",
                         ms(per_pkt, 1, 1e6), ms([x * f for x in per_pkt], 0),
                         ms(cyc_dB, 0), ms(cyc_sB, 0), f"{crit:.1f}" if crit else "-",
                         f"{mean(per_resp) * 1e6 / crit:.2f}" if crit and per_resp and answers_all else "-"])
        table(["cell", "us per answered request", "cycles per answered request", "us per delivered packet", "cycles per delivered packet", "cycles / delivered B", "cycles / B sent", "Criterion us (part 1)", "measured / Criterion"], rows)


def starvation(stages):
    p("## Table-filling kinds: does the legit client get starved? (stateful, botnet shape)\n")
    p("Attack-phase probes, pooled success rates per cap. `peak entries` is the table maximum; `armed` the cookies the flood client had (partial). Watched counters are from the server table for the legit address.\n")
    rows = []
    for s in stages:
        for e in entries(s):
            c = e["cell"]
            if c["system"] != "stateful" or c["kind"] not in TABLE_KINDS or c["shape"] != "botnet": continue
            rs = e["reps"]
            rows.append([s["dir"][:8], c["variant"], e["rtt_ms"], c["kind"], c["cap"],
                         pct(col(rs, "legit_success_within_1s_attack")), pct(col(rs, "legit_success_within_5s_attack")),
                         pct(col(rs, "legit_frac_completed_during_flood_attack")), pct(steady_rate(rs, 1.0)), pct(steady_rate(rs, 5.0)),
                         ms(col(rs, "legit_p50_s_attack"), 2), ms(col(rs, "peak_table_entries"), 0), ms(col(rs, "d_evictions"), 0),
                         ms(col(rs, "d_dropped_table_full"), 0), ms(col(rs, "d_watched_created"), 1), ms(col(rs, "d_watched_evictions"), 1), ms(col(rs, "d_watched_timeouts"), 1)])
    table(["stage", "variant", "rtt", "kind", "cap", "<=1 s %", "<=5 s %", "done in flood %", "steady <=1 s %", "steady <=5 s %", "p50 s (ok probes)", "peak entries", "evictions", "dropped_table_full", "watched created", "watched evicted", "watched timeouts"], rows)


def setup_effect(stages):
    p("## Effect of the flood client set-up (cookie collection) on whole-window versus attack-phase figures\n")
    p("Only cells whose set-up lasts more than 1 s. `whole` = the full flood window (set-up plus attack); `attack` = after set-up. The set-up is a harness property: the stateful client sends one hello from each of its sockets and waits for the cookies. Cookies obtained / sockets shows how much of the botnet was armed.\n")
    rows = []
    for s in stages:
        for e in entries(s):
            rs = e["reps"]
            if not has_flood(e) or mean([setup_s(r) for r in rs]) <= 1.0: continue
            c = e["cell"]
            rows.append([s["dir"][:8], name(e), f"rtt {e['rtt_ms']}", ms(col(rs, "attack_started_s"), 2), ms(col(rs, "flood_window_s"), 1),
                         f"{ms(col(rs, 'cpu_util_pct'), 1)} / {ms(col(rs, 'cpu_util_pct_attack_phase'), 1)}",
                         f"{ms(col(rs, 'attacker_packets_per_s'), 1, 1e-3)} / {ms(col(rs, 'attacker_packets_per_s_attack_phase'), 1, 1e-3)}",
                         f"{pct(col(rs, 'legit_success_within_1s'))} / {pct(col(rs, 'legit_success_within_1s_attack'))}",
                         f"{pct(col(rs, 'legit_success_within_5s'))} / {pct(col(rs, 'legit_success_within_5s_attack'))}",
                         f"{ms([(r.get('flood_client_json') or {}).get('cookies_obtained') for r in rs], 0)} / {c['sockets']}"])
    table(["stage", "cell", "rtt", "set-up s", "window s", "CPU % whole / attack", "attacker kpkt/s whole / attack", "legit <=1 s % whole / attack", "legit <=5 s % whole / attack", "cookies / sockets"], rows)


PAIRS = [("handshake", "hello"), ("auth", "auth"), ("uchunk", "partial"), ("vpoint", "fullkey")]

def pairing(stages):
    p("## Stateless against stateful under the same attack shape (counterpart kinds, stateful cap 1024)\n")
    p("Counterparts: handshake-hello, auth-auth, uchunk-partial, vpoint-fullkey. Cell text: `success<=1 s % / done in flood % / p50 s of ok probes` for the attack-phase probes; CPU = attack-phase server CPU %. The two flood clients are different programs and send at different rates (`kpkt/s`), so equal load is NOT matched; compare with the load table.\n")
    idx = {}
    for s in stages:
        for e in entries(s):
            c = e["cell"]
            if c["kind"] == "none": continue
            cap = c["cap"] if c["system"] == "stateful" and c["kind"] in TABLE_KINDS else None
            if cap not in (None, 1024): continue
            idx[(e["rtt_ms"], c["variant"], c["shape"], c["system"], c["kind"])] = e
    def cell(e):
        if e is None: return "-"
        rs = e["reps"]; okl = sorted(q["latency_s"] for r in rs for q in attack_probes(r) if q["ok"])
        return (f"{mean(col(rs, 'legit_success_within_1s_attack')) * 100:.0f} / {mean(col(rs, 'legit_frac_completed_during_flood_attack')) * 100:.0f} / {fs(rank(okl, .5), 3)}"
                f" (CPU {mean(col(rs, 'cpu_util_pct_attack_phase')):.0f}, {mean(col(rs, 'attacker_packets_per_s_attack_phase')) / 1e3:.0f} kpkt/s)")
    rows = []
    for (rtt, variant, shape) in sorted({(k[0], k[1], k[2]) for k in idx}, key=lambda k: (k[0], k[1], SHAPE_ORDER.index(k[2]))):
        for sl, sf in PAIRS:
            a, b = idx.get((rtt, variant, shape, "stateless", sl)), idx.get((rtt, variant, shape, "stateful", sf))
            if a or b: rows.append([f"rtt{rtt}", variant, shape, f"{sl} / {sf}", cell(a), cell(b)])
    table(["rtt", "variant", "shape", "stateless kind / stateful kind", "stateless", "stateful"], rows)


def variant_compare(stages):
    p("## Variant comparison (legit probes in the attack phase; rtt 0 ms unless stated)\n")
    p("Each cell shows `steady success<=1 s % / p50 s / p99 s` (steady = probes that started at least 5 s before the flood ended), with the p50 and p99 pooled over reps. `none` = no flood. Used to answer whether HQC-1 probes are slower than HQC-3/HQC-5 under flood.\n")
    data = {}
    for s in stages:
        for e in entries(s):
            c = e["cell"]
            key = (e["rtt_ms"], c["system"], c["shape"], c["kind"], c["cap"] if c["kind"] in TABLE_KINDS and c["system"] == "stateful" else None)
            pooled = [q for r in e["reps"] for q in attack_probes(r)]
            okl = sorted(q["latency_s"] for q in pooled if q["ok"])
            sr = steady_rate(e["reps"], 1.0)
            data.setdefault(key, {})[c["variant"]] = f"{mean(sr) * 100:.0f} / {fs(rank(okl, .5), 3)} / {fs(rank(okl, .99), 2)}"
    variants = sorted({v for d in data.values() for v in d})
    if len(variants) < 2: p("(only one variant present so far)\n"); return
    rows = []
    for key in sorted(data, key=lambda k: (k[0], SYSTEM_ORDER.index(k[1]), SHAPE_ORDER.index(k[2]), KIND_ORDER.index(k[3]), k[4] or 0)):
        rows.append([f"rtt{key[0]} {key[1]} {key[2]} {key[3]}" + (f" cap{key[4]}" if key[4] else "")] + [data[key].get(v, "-") for v in variants])
    table(["cell"] + variants, rows)


def probe_dump(stages):
    p("## Slow-probe breakdown (attack phase): share of probes by latency band, pooled over reps\n")
    p("Bands: <0.1 s, 0.1-1 s, 1-5 s, 5-10 s, failed (timeout or error). Only flood cells.\n")
    rows = []
    for s in stages:
        for e in entries(s):
            if not has_flood(e): continue
            pooled = [q for r in e["reps"] for q in attack_probes(r)]
            n = len(pooled)
            if not n: continue
            def band(lo, hi): return sum(1 for q in pooled if q["ok"] and lo <= q["latency_s"] < hi) / n * 100
            fail = sum(1 for q in pooled if not q["ok"]) / n * 100
            rows.append([s["dir"][:8], name(e), f"rtt {e['rtt_ms']}", n, f"{band(0, .1):.0f}", f"{band(.1, 1):.0f}", f"{band(1, 5):.0f}", f"{band(5, 10.01):.0f}", f"{fail:.0f}"])
    table(["stage", "cell", "rtt", "probes", "<0.1 s %", "0.1-1 s %", "1-5 s %", "5-10 s %", "failed %"], rows)


def main():
    stages = load_stages()
    p("# Part 3 DoS tables (generated by make_tables_dos_part3.py)\n")
    provenance(stages); commands(stages); qc(stages)
    for s in stages: main_tables(s)
    starvation(stages); setup_effect(stages); pairing(stages); variant_compare(stages); probe_dump(stages)
    text = "\n".join(out)
    open(f"{ROOT}/tables_dos_part3.md", "w").write(text)
    print(f"wrote tables_dos_part3.md: {len(text)} chars, {len(stages)} stage(s)")


if __name__ == "__main__":
    main()
