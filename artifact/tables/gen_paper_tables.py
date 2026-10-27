#!/usr/bin/env python3
"""Generate the LaTeX tables of the paper from the stored result files.

Usage: RESULTS_DIR=<results-sp27> gen_paper_tables.py [output-dir]. Writes *.tex.
Reads only files under RESULTS_DIR (never modifies them).
"""
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from results_dir import results_dir

RES = results_dir()
FINAL = RES / "final-x86"
PART3 = RES / "part3"
ARM = RES / "arm-final"
OUT = Path(sys.argv[1]) if len(sys.argv) > 1 else Path.cwd() / "paper-tables"
OUT.mkdir(exist_ok=True)

MCTINY_PHASE0_MS = 2.65  # RESULTS.md: one McEliece decapsulation, 3.18 Mcycles at 1.2 GHz
LEVELS = ["HQC-1", "HQC-3", "HQC-5"]


def read(path):
    return Path(path).read_text().splitlines()


def md_table(lines, heading, nth=0):
    """Rows (list of dict) of the nth markdown table after a line starting with `heading`."""
    start = next(i for i, l in enumerate(lines) if l.startswith(heading))
    i = start + 1
    found = -1
    while i < len(lines):
        if lines[i].startswith("|") and i + 1 < len(lines) and re.match(r"^\|[-| ]+\|$", lines[i + 1]):
            found += 1
            if found == nth:
                header = [c.strip() for c in lines[i].strip().strip("|").split("|")]
                rows = []
                j = i + 2
                while j < len(lines) and lines[j].startswith("|"):
                    cells = [c.strip() for c in lines[j].strip().strip("|").split("|")]
                    rows.append(dict(zip(header, cells)))
                    j += 1
                return rows
        i += 1
    raise KeyError(heading)


def new(value):
    """`old -> new` cells keep the new value."""
    return value.split("->")[-1].strip()


def fmt_int(x):
    return f"{int(round(float(x))):,}".replace(",", "{,}")


def lvl(name):
    return "HQC-" + name[-1]


RESULTS = read(FINAL / "RESULTS.md")
NUMBERS = read(FINAL / "numbers_for_paper.md")
PART3_RES = read(PART3 / "RESULTS.md")

# ---------------------------------------------------------------- bandwidth
MCTINY_SENT, MCTINY_RECV, MCTINY_PKTS, MCTINY_PK = 1188422, 135977, 1942, 1047319


def padding_bytes(level):
    """Padding per session, from the layout formulas of src/encoding.rs and src/limits.rs."""
    lam = {"HQC-1": 16, "HQC-3": 24, "HQC-5": 32}[level]
    auth_ct = {"HQC-1": 96, "HQC-3": 156, "HQC-5": 208}[level]
    t = {"HQC-1": 7, "HQC-3": 15, "HQC-5": 25}[level]
    limbs = {"HQC-1": 71, "HQC-3": 73, "HQC-5": 76}[level]
    chunks = {"HQC-1": 2, "HQC-3": 4, "HQC-5": 7}[level]
    cookie = 24 + 32 + lam + 32 + 32 + 16
    hs_reply = 2 + 24 + cookie + 16 + 32 + 16
    hs_unpadded = 2 + 32 + 32 + auth_ct
    hs_pad = max(hs_unpadded, hs_reply) - hs_unpadded
    uchunk_pad = 1232 - (2 + cookie + 16)
    vpoint_pad = 1170 - (2 + cookie + limbs * 8 + 16)
    return hs_pad + chunks * uchunk_pad + t * vpoint_pad


def bandwidth():
    rows = md_table(RESULTS, "#### Bandwidth per session (bytes, UDP payload)", 0)
    by = {(r["system"], r["level"]): r for r in rows}
    def get(system, level, col):
        return new(by[(system, level.lower().replace("-", ""))][col])
    out = []
    out.append(r"\begin{table}[t]")
    out.append(r"\caption{Network use of one key exchange (UDP payload bytes; sizes of both directions). McTiny uses \texttt{mceliece6960119}. Padding is part of the stateless totals.}")
    out.append(r"\label{tab:bandwidth}")
    out.append(r"\centering\footnotesize\setlength{\tabcolsep}{3pt}")
    out.append(r"\begin{tabular}{@{}lrrrr@{}}\toprule")
    out.append(r" & HQC-1 & HQC-3 & HQC-5 & McTiny \\ \midrule")
    def row(label, vals, mct=""):
        out.append(label + " & " + " & ".join(vals) + f" & {mct} \\\\")
    row("Packets, \\tool", [get("stateless", l, "packets") for l in LEVELS], fmt_int(MCTINY_PKTS))
    row("Packets, stateful", [get("stateful", l, "packets") for l in LEVELS])
    row("Upstream, \\tool", [fmt_int(get("stateless", l, "sent (client->server)")) for l in LEVELS], fmt_int(MCTINY_SENT))
    row("Downstream, \\tool", [fmt_int(get("stateless", l, "received")) for l in LEVELS], fmt_int(MCTINY_RECV))
    row("Total, \\tool", [fmt_int(get("stateless", l, "total")) for l in LEVELS], fmt_int(MCTINY_SENT + MCTINY_RECV))
    row("Total, stateful", [fmt_int(get("stateful", l, "total")) for l in LEVELS])
    row("Raw key + ciphertext", [fmt_int(get("stateless", l, "raw pk+ct")) for l in LEVELS], fmt_int(MCTINY_PK))
    row("\\tool total / raw", [get("stateless", l, "total / raw") + "$\\times$" for l in LEVELS])
    row("\\tool padding", [fmt_int(padding_bytes(l)) for l in LEVELS])
    row("Round trips", ["2", "2", "2"], "11--12")
    out.append(r"\bottomrule\end{tabular}\end{table}")
    (OUT / "bandwidth.tex").write_text("\n".join(out) + "\n")
    # numbers used in prose
    s5 = int(get("stateless", "HQC-5", "total")); f5 = int(get("stateful", "HQC-5", "total"))
    print("bytes McTiny/HQC-5 %.2f  packets %.1f  stateless/stateful %.2f" % ((MCTINY_SENT + MCTINY_RECV) / s5, MCTINY_PKTS / int(get('stateless', 'HQC-5', 'packets')), s5 / f5))
    for l in LEVELS:
        s = int(get("stateless", l, "total")); f = int(get("stateful", l, "total"))
        print(l, "stateless/stateful %.2f" % (s / f), "padding share %.1f%%" % (100 * padding_bytes(l) / s))


# ---------------------------------------------------------------- CPU
def cpu():
    sess = md_table(NUMBERS, "## Session CPU", 0)
    per = md_table(NUMBERS, "## Per-request cost", 0)
    P = {(r["system"], r["kind"], r["level"]): r for r in per}
    out = []
    out.append(r"\begin{table}[t]")
    out.append(r"\caption{Server CPU on the Ryzen 7 5800H (3169\,MHz). Top: Criterion median of one request handler, then the measured cost per answered request in a saturating flood (system calls included), in \textmu s. Bottom: server CPU per session (\texttt{schedstat}, mean of three runs), and the ratio McTiny / \tool; McTiny uses \texttt{mceliece6960119} at 19.66\,ms (62.3\,Mcycles).}")
    out.append(r"\label{tab:cpu}")
    out.append(r"\centering\small\setlength{\tabcolsep}{4pt}")
    out.append(r"\begin{tabular}{@{}llrrr@{}}\toprule")
    out.append(r" & & HQC-1 & HQC-3 & HQC-5 \\ \midrule")
    for kind, label in [("handshake", "Handshake"), ("uchunk", "$u$-chunk"), ("vpoint", "$v$-point")]:
        crit = " / ".join(P[("stateless", kind, l)]["Criterion us"] for l in LEVELS)
        out.append(f"{label}, Criterion (\\textmu s) & & " + " & ".join(P[("stateless", kind, l)]["Criterion us"] for l in LEVELS) + r" \\")
        out.append(f"{label}, measured (\\textmu s) & & " + " & ".join(P[("stateless", kind, l)]["measured us per answered request"] for l in LEVELS) + r" \\")
    out.append(r"\midrule")
    S = {r["level"]: r for r in sess}
    out.append("Session, \\tool (ms) & & " + " & ".join(S[l]["stateless ms"] for l in LEVELS) + r" \\")
    out.append("Session, stateful (ms) & & " + " & ".join(S[l]["stateful ms"] for l in LEVELS) + r" \\")
    out.append("McTiny / \\tool & & " + " & ".join(S[l]["McTiny/stateless"].replace("x", "$\\times$") for l in LEVELS) + r" \\")
    out.append(r"\bottomrule\end{tabular}\end{table}")
    (OUT / "cpu.tex").write_text("\n".join(out) + "\n")
    for l in LEVELS:
        print(l, "stateless/stateful session CPU %.2f" % (float(S[l]["stateless ms"]) / float(S[l]["stateful ms"])))


# ---------------------------------------------------------------- cycles per request byte
def cpb():
    per = md_table(NUMBERS, "## Per-request cost", 0)
    P = {(r["system"], r["kind"], r["level"]): r for r in per}
    out = []
    out.append(r"\begin{table}[t]")
    out.append(r"\caption{Server cycles per byte of request, measured in a saturating flood (system calls included). McTiny's overload threshold is 10{,}000 cycles per byte (\S\ref{sec:cpb}).}")
    out.append(r"\label{tab:cpb}")
    out.append(r"\centering\small\setlength{\tabcolsep}{5pt}")
    out.append(r"\begin{tabular}{@{}llrrr@{}}\toprule")
    out.append(r"Server & Request & HQC-1 & HQC-3 & HQC-5 \\ \midrule")
    for system, kind, label in [("stateless", "handshake", "\\tool & handshake"), ("stateless", "uchunk", "\\tool & $u$-chunk"),
                                ("stateless", "vpoint", "\\tool & $v$-point"), ("stateful", "hello", "Stateful & hello")]:
        out.append(label + " & " + " & ".join(fmt_int(P[(system, kind, l)]["cycles per request byte"]) for l in LEVELS) + r" \\")
    out.append(r"\bottomrule\end{tabular}\end{table}")
    (OUT / "cpb.tex").write_text("\n".join(out) + "\n")


# ---------------------------------------------------------------- memory
def memory():
    stack = md_table(RESULTS, "#### Minimum server stack", 0)
    binary = md_table(RESULTS, "#### Binary size", 0)
    rss = md_table(RESULTS, "#### Server RSS", 0)
    S = {r["system"]: r for r in stack}
    B = {r["binary"]: r for r in binary}
    R = {(r["system"], r["level"]): r for r in rss}
    stk = lambda sysname, l: new(S[sysname][l])
    out = []
    out.append(r"\begin{table}[t]")
    out.append(r"\caption{Server memory. Stack: smallest \texttt{ulimit -s} (4\,KiB steps) at which a full session succeeds. RSS: resident set after the timed sessions, median over rounds (first of three runs). Heap: \texttt{brk}/\texttt{mmap} calls after warm-up in 50 sessions per level: 0 for \tool.}")
    out.append(r"\label{tab:memory}")
    out.append(r"\centering\small\setlength{\tabcolsep}{4pt}")
    out.append(r"\begin{tabular}{@{}lrrrr@{}}\toprule")
    out.append(r" & HQC-1 & HQC-3 & HQC-5 & McTiny \\ \midrule")
    out.append("Stack, \\tool (KiB) & " + " & ".join(stk("stateless", l) for l in LEVELS) + f" & {stk('mctiny', 'HQC-1')} \\\\")
    out.append("Stack, stateful (KiB) & " + " & ".join(stk("stateful", l) for l in LEVELS) + r" & \\")
    out.append("RSS, \\tool (MB) & " + " & ".join("%.1f" % (int(R[("stateless", "hqc" + l[-1])]["after sessions"].split("/")[0]) / 1000) for l in LEVELS) + " & %.1f \\\\" % (int(R[("mctiny", "-")]["after sessions"].split("/")[0]) / 1000))
    bin_s = new(B["hqclethe-server"]["total"]); bin_f = new(B["hqclethe-server-stateful"]["total"]); bin_m = new(B["mctiny-server"]["total"])
    out.append("Binary, \\tool (KB) & \\multicolumn{3}{c}{" + f"{int(bin_s)/1000:.0f}" + "} & " + f"{int(bin_m)/1000:.0f}" + r" \\")
    out.append("Binary, stateful (KB) & \\multicolumn{3}{c}{" + f"{int(bin_f)/1000:.0f}" + r"} & \\")
    out.append(r"\bottomrule\end{tabular}\end{table}")
    (OUT / "memory.tex").write_text("\n".join(out) + "\n")


# ---------------------------------------------------------------- WAN
def wan():
    prof = md_table(RESULTS, "#### HQC-5: RTT profiles", 0)
    loss = md_table(RESULTS, "#### HQC-5: loss sweep", 0)
    ge = md_table(RESULTS, "#### HQC-5: Gilbert-Elliott", 0)
    m = md_table(PART3_RES, "### McTiny timing per cell", 0)
    start = next(i for i, l in enumerate(RESULTS) if l.startswith("#### Ratio McTiny network-only time"))
    ratios = {}
    for l in RESULTS[start:]:
        if l.startswith("| ") and "/" in l.split("|")[1] and "|---" not in l:
            c = [x.strip() for x in l.strip().strip("|").split("|")]
            ratios[c[0]] = {"ratio": c[3]}
        if l.startswith("## Tables: DoS"):
            break
    M = {r["cell"]: r for r in m}
    H = {(r["cell"], r["system"]): r for r in prof + loss + ge}

    def mt(cell, col):
        return M[cell][col]

    out = []
    out.append(r"\begin{table}[t]")
    out.append(r"\caption{Session time at HQC-5, 30 sessions per cell, loss in both directions (median in s). \tool and stateful: first request to derived key. McTiny: first packet to last reply (\texttt{network\_s}), so process start-up and key generation are excluded. Ratio = McTiny / \tool. Cells from 2.5\,\% loss are heavy-tailed on the McTiny side: the second value is the median of an earlier independent run of 30 sessions (includes about 0.1\,s of start-up).}")
    out.append(r"\label{tab:wan}")
    out.append(r"\centering\scriptsize\setlength{\tabcolsep}{3pt}")
    out.append(r"\begin{tabular}{@{}lrrrrr@{}}\toprule")
    out.append(r"Cell (RTT, loss/direction) & \tool & p95 & Stateful & McTiny & Ratio \\ \midrule")
    cells = [
        ("local/both", "2\\,ms, 0\\,\\%"),
        ("same_continent/both", "20\\,ms, 0.05\\,\\%"),
        ("transatlantic/both", "75\\,ms, 0.1\\,\\%"),
        ("transpacific/both", "140\\,ms, 0.2\\,\\%"),
        ("satellite/both", "300\\,ms, 0.5\\,\\%"),
        ("loss0/both", "20\\,ms, 0\\,\\%"),
        ("loss1/both", "20\\,ms, 1\\,\\%"),
        ("loss2/both", "20\\,ms, 2\\,\\%"),
        ("loss2.5/both", "20\\,ms, 2.5\\,\\%"),
        ("loss3/both", "20\\,ms, 3\\,\\%"),
        ("loss4/both", "20\\,ms, 4\\,\\%"),
        ("loss5/both", "20\\,ms, 5\\,\\%"),
        ("ge/both", "20\\,ms, Gilbert--Elliott"),
    ]
    for cell, label in cells:
        hs = float(H[(cell, "stateless")]["median s"])
        hf = float(H[(cell, "stateful")]["median s"])
        new_net = float(mt(cell, "new network_s").split("/")[0])
        old = float(mt(cell, "old session_s").split("/")[0])
        loss_pct = None
        mm = re.match(r"loss([\d.]+)/", cell)
        if mm:
            loss_pct = float(mm.group(1))
        if (loss_pct is not None and loss_pct >= 2.5) or cell.startswith("ge/"):
            lo, hi = sorted([new_net, old])
            mct = f"{lo:.1f}--{hi:.1f}" if hi >= 10 else f"{lo:.2f}--{hi:.2f}"
            ratio = f"{lo / hs:.0f}--{hi / hs:.0f}"
            if mct.split("--")[0] == mct.split("--")[1]:
                mct = mct.split("--")[0]
            if ratio.split("--")[0] == ratio.split("--")[1]:
                ratio = ratio.split("--")[0]
        else:
            mct = f"{new_net:.3f}" if new_net < 1 else f"{new_net:.2f}"
            ratio = ratios[cell]["ratio"]
        p95 = float(H[(cell, "stateless")]["p95 s"])
        out.append(f"{label} & {hs:.3f} & {p95:.3f} & {hf:.3f} & {mct} & {ratio} \\\\")
    out.append(r"\bottomrule\end{tabular}\end{table}")
    (OUT / "wan.tex").write_text("\n".join(out) + "\n")


# ---------------------------------------------------------------- floods
def flood():
    rows = md_table(NUMBERS, "## Flood: steady success", 0)
    def block(shape):
        return [r for r in rows if r["shape"] == shape]
    out = []
    out.append(r"\begin{table}[t]")
    out.append(r"\caption{Legitimate client during a saturating flood (one core). SL = \tool (stateless), SF = stateful baseline. Cell: steady success within 1\,s / share of probes that finished before the flood ended, in \%, mean of 10 repetitions, single-source shape. Steady = probes that started at least 5\,s before the flood ended. The two flood programs send at different rates, so compare per-request cost (Table~\ref{tab:cpu}), not the two columns.}")
    out.append(r"\label{tab:flood}")
    out.append(r"\centering\scriptsize\setlength{\tabcolsep}{2pt}")
    out.append(r"\begin{tabular}{@{}lrrrrrr@{}}\toprule")
    out.append(r" & \multicolumn{2}{c}{HQC-1} & \multicolumn{2}{c}{HQC-3} & \multicolumn{2}{c}{HQC-5} \\")
    out.append(r"Flood (SL/SF) & SL & SF & SL & SF & SL & SF \\ \midrule")
    for r in block("single"):
        name = r["stateless kind / stateful kind"].replace("uchunk", "$u$-chunk").replace("vpoint", "$v$-point").replace("fullkey", "full").replace(" / ", "/")
        cells = []
        for l in LEVELS:
            for sys_ in ("stateless", "stateful"):
                cells.append(r[f"{l} {sys_}"].replace(" / ", "/"))
        out.append(name + " & " + " & ".join(cells) + r" \\")
    out.append(r"\bottomrule\end{tabular}\end{table}")
    (OUT / "flood.tex").write_text("\n".join(out) + "\n")

    # appendix: botnet shape
    out = []
    out.append(r"\begin{table}[t]")
    out.append(r"\caption{As Table~\ref{tab:flood} (SL = \tool, SF = stateful), botnet shape (4096 sockets on 1024 loopback addresses of one host).}")
    out.append(r"\label{tab:flood-botnet}")
    out.append(r"\centering\scriptsize\setlength{\tabcolsep}{2pt}")
    out.append(r"\begin{tabular}{@{}lrrrrrr@{}}\toprule")
    out.append(r" & \multicolumn{2}{c}{HQC-1} & \multicolumn{2}{c}{HQC-3} & \multicolumn{2}{c}{HQC-5} \\")
    out.append(r"Flood (SL/SF) & SL & SF & SL & SF & SL & SF \\ \midrule")
    for r in block("botnet"):
        name = r["stateless kind / stateful kind"].replace("uchunk", "$u$-chunk").replace("vpoint", "$v$-point").replace("fullkey", "full").replace(" / ", "/")
        cells = []
        for l in LEVELS:
            for sys_ in ("stateless", "stateful"):
                cells.append(r[f"{l} {sys_}"].replace(" / ", "/"))
        out.append(name + " & " + " & ".join(cells) + r" \\")
    out.append(r"\bottomrule\end{tabular}\end{table}")
    (OUT / "flood_botnet.tex").write_text("\n".join(out) + "\n")


def tablefill():
    rows = md_table(RESULTS, "### Table-filling kinds", 0)
    sel = [r for r in rows if r["rtt"] == "0"]
    def steady(r):
        return r["steady <=1 s %"].split("±")[0].strip()
    def cell(variant, kind, cap):
        r = next(r for r in sel if r["variant"] == variant and r["kind"] == kind and r["cap"] == cap)
        return steady(r)
    entry = {"hqc1": 2401, "hqc3": 4674, "hqc5": 7397}
    out = []
    out.append(r"\begin{table}[t]")
    out.append(r"\caption{Table-filling attack on the cookie-gated stateful server (botnet shape; steady success within 1\,s, \%, mean of 10 repetitions). Table memory is the cap times the entry size (2.4, 4.7 and 7.4\,KB at HQC-1, 3 and 5). \tool has no table and needs no cap; its steady success under its own worst floods is in Table~\ref{tab:flood}.}")
    out.append(r"\label{tab:tablefill}")
    out.append(r"\centering\scriptsize\setlength{\tabcolsep}{2.5pt}")
    out.append(r"\begin{tabular}{@{}rrrrrrrr@{}}\toprule")
    out.append(r" & \multicolumn{3}{c}{\texttt{partial}} & \multicolumn{3}{c}{\texttt{churn2}} & Table at \\")
    out.append(r"Cap & HQC-1 & HQC-3 & HQC-5 & HQC-1 & HQC-3 & HQC-5 & HQC-5 (MB) \\ \midrule")
    for cap in ["16", "64", "256", "1024"]:
        mb = int(cap) * entry["hqc5"] / 1e6
        out.append(f"{cap} & " + " & ".join(cell(v, "partial", cap) for v in ["hqc1", "hqc3", "hqc5"]) + " & " +
                   " & ".join(cell(v, "churn2", cap) for v in ["hqc1", "hqc3", "hqc5"]) + f" & {mb:.2f} \\\\")
    out.append(r"\bottomrule\end{tabular}\end{table}")
    (OUT / "tablefill.tex").write_text("\n".join(out) + "\n")


def rtt():
    rows = md_table(NUMBERS, "RTT cells (HQC-5)", 0)
    out = []
    out.append(r"\begin{table}[t]")
    out.append(r"\caption{HQC-5 floods at three round-trip times of the legitimate client: steady success within 1\,s / within 5\,s (\%). Stateful table cap 1024. Idle probe latency: 0.016, 0.165, 0.619\,s (\tool) at 0, 75, 300\,ms.}")
    out.append(r"\label{tab:flood-rtt}")
    out.append(r"\centering\footnotesize\setlength{\tabcolsep}{3pt}")
    out.append(r"\begin{tabular}{@{}llrrr@{}}\toprule")
    out.append(r"Server, flood & Shape & 0\,ms & 75\,ms & 300\,ms \\ \midrule")
    for r in rows:
        if r["kind"] == "none":
            continue
        kind = r["kind"].replace("uchunk", "$u$-chunk").replace("vpoint", "$v$-point").replace("fullkey", "full").replace(" / ", "/")
        cells = []
        for k in ("rtt 0", "rtt 75", "rtt 300"):
            a, b, _ = [x.strip() for x in r[k].split("/")]
            cells.append(f"{a}/{b}")
        out.append(f"{r['system']}, {kind} & {r['shape']} & " + " & ".join(cells) + r" \\")
    out.append(r"\bottomrule\end{tabular}\end{table}")
    (OUT / "flood_rtt.tex").write_text("\n".join(out) + "\n")


# ---------------------------------------------------------------- ARM (Raspberry Pi 3B+)
def last(value):
    """`old / new` cells keep the new value."""
    return value.split(" / ")[-1].strip()


def col(row, prefix):
    return next(v for k, v in row.items() if k.startswith(prefix))


def arm_data():
    lines = read(ARM / "RESULTS.md")
    rate = md_table(lines, "### Rate limits derived from cost", 0)
    cost = {(r["system"], r["level"], r["unit"]): float(r["CPU cost ms"]) for r in rate}
    bound = {(r["system"], r["level"], r["unit"]): float(col(r, "max per second")) for r in rate}
    sess = {(r["system"], r["level"]): float(last(col(r, "Pi server CPU"))) for r in
            md_table(lines, "### Item 1: server CPU per session", 0)}
    client = {(r["system"], r["level"]): float(last(col(r, "client CPU"))) for r in
              md_table(lines, "### Item 2: client cost", 1)}
    stack = {(r["system"], r["level"]): last(col(r, "min stack")) for r in
             md_table(lines, "### Item 3: memory", 0)}
    flood = {r["profile/level:system:kind:shape"]: r for r in
             md_table(lines, "### Item 4: real-network flood", 0)}
    lat = {(r["system"], r["level"]): float(last(col(r, "median ms (old"))) for r in
           md_table(lines, "### Item 5: LAN session latency", 0)}
    link = {r["test"]: r for r in md_table(lines, "New:", 0)}
    return dict(cost=cost, bound=bound, sess=sess, client=client, stack=stack, flood=flood, lat=lat, link=link)


def arm():
    d = arm_data()
    cost, bound, sess = d["cost"], d["bound"], d["sess"]
    lv = ["hqc1", "hqc3", "hqc5"]
    mct = sess[("mctiny", "-")]
    mct_bound = bound[("mctiny", "-", "session (971 queries)")]

    def fl(profile_of, level, kind, system="stateless"):
        key = f"{profile_of[level]}/{level}:{system}:{kind}:single"
        return d["flood"][key]

    prof = {"hqc1": "paced1", "hqc3": None, "hqc5": "paced5"}

    def flood_cells(kind, field, fmt):
        cells = []
        for l in lv:
            if prof[l] is None:
                cells.append("---")
            else:
                cells.append(fmt(last(col(fl(prof, l, kind), field))))
        return cells

    def pct(x):
        return f"{100 * float(x):.0f}"

    def live_over_bound(kind, unit):
        cells = []
        for l in lv:
            if prof[l] is None:
                cells.append("---")
            else:
                live = float(last(col(fl(prof, l, kind), "answers/s")))
                cells.append(f"{100 * live / bound[('stateless', l, unit)]:.0f}")
        return cells

    def legit(kind):
        cells = []
        for l in lv:
            if prof[l] is None:
                cells.append("---")
            else:
                r = fl(prof, l, kind)
                cells.append(pct(last(col(r, "legit <=1 s"))) + "/" + pct(last(col(r, "legit <=5 s"))))
        return cells

    def row(label, vals, mc=""):
        return label + " & " + " & ".join(vals) + f" & {mc} \\\\"

    ms = lambda x, n=2: f"{x:.{n}f}"
    out = []
    out.append(r"\begin{table}[t]")
    out.append(r"\caption{Raspberry Pi 3B+ (Cortex-A53, 1.2\,GHz, one pinned core). "
               r"Capacity is 1 / (server CPU) for both systems; McTiny was not flooded (McTiny handshake row: phase~0, one McEliece decapsulation). "
               r"Flood rows: live LAN flood from the x86 host, five repetitions (none at HQC-3); "
               r"legitimate success within 1\,s / 5\,s (\%) is for the $v$-point flood.}")
    out.append(r"\label{tab:arm}")
    out.append(r"\centering\scriptsize\setlength{\tabcolsep}{3pt}")
    out.append(r"\begin{tabular}{@{}lrrrr@{}}\toprule")
    out.append(r" & HQC-1 & HQC-3 & HQC-5 & McTiny \\ \midrule")
    out.append(row("Session CPU, \\tool (ms)", [ms(sess[("stateless", l)]) for l in lv], ms(mct, 1)))
    out.append(row("Session CPU, stateful (ms)", [ms(sess[("stateful", l)]) for l in lv]))
    out.append(row("McTiny / \\tool", [f"{mct / sess[('stateless', l)]:.1f}$\\times$" for l in lv]))
    out.append(row("Handshake request (ms)", [f"{cost[('stateless', l, 'request: handshake')]:.3f}" for l in lv],
                   f"{MCTINY_PHASE0_MS:.2f}"))
    out.append(row("$u$-chunk request (ms)", [f"{cost[('stateless', l, 'request: uchunk')]:.3f}" for l in lv]))
    out.append(row("$v$-point request (ms)", [f"{cost[('stateless', l, 'request: vpoint')]:.3f}" for l in lv]))
    out.append(row("Capacity (derived), sessions/s", [f"{bound[('stateless', l, 'session')]:.1f}" for l in lv], f"{mct_bound:.2f}"))
    query_bound = {k[1]: v for k, v in bound.items() if k[0] == "stateless" and k[2].startswith("query")}
    out.append(row("Capacity (derived), queries/s", [fmt_int(query_bound[l]) for l in lv],
                   fmt_int(bound[("mctiny", "-", "query (session cost / queries)")])))
    out.append(row("Flood: handshakes answered/s", flood_cells("handshake", "answers/s", fmt_int), "---"))
    out.append(row("Flood: $v$-points answered/s", flood_cells("vpoint", "answers/s", fmt_int), "---"))
    out.append(row("Flood / derived, $v$-point (\\%)", live_over_bound("vpoint", "request: vpoint"), "---"))
    out.append(row("Legit. success, $v$-point flood (\\%)", legit("vpoint"), "---"))
    out.append(row("Client CPU per session (ms)", [fmt_int(d["client"][("stateless", l)]) for l in lv], fmt_int(d["client"][("mctiny", "-")])))
    out.append(row("LAN session time (ms)", [fmt_int(d["lat"][("stateless", l)]) for l in lv], fmt_int(d["lat"][("mctiny", "-")])))
    out.append(row("Minimum stack (KiB)", [d["stack"][("stateless", l)] for l in lv], d["stack"][("mctiny", "-")]))
    out.append(r"\bottomrule\end{tabular}\end{table}")
    (OUT / "arm.tex").write_text("\n".join(out) + "\n")
    print("ARM: McTiny/HqcLethe", [round(mct / sess[("stateless", l)], 2) for l in lv],
          "link", d["link"]["udp_1200_to_pi"]["Mbit/s received"], "TCP", d["link"]["tcp_to_pi"]["Mbit/s received"])


if __name__ == "__main__":
    bandwidth(); cpu(); cpb(); memory(); wan(); flood(); tablefill(); rtt(); arm()
    print("tables written to", OUT)
