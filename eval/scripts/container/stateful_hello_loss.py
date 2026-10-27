#!/usr/bin/env python3
"""Which packet of a legitimate stateful session is lost under a stateful flood.

Runs in the eval server container on the measurement host (take ~/measure.lock):
  stateful_hello_loss.py VARIANT [fullkey|partial|hello|none]
T and KEYS select another build and key directory (for example an older
commit built with CARGO_TARGET_DIR=/work/target-old). Prints how often the
hello and the fragment phase needed a retransmission.
"""
import re, subprocess, sys, time, statistics as st
v = sys.argv[1]; kind = sys.argv[2] if len(sys.argv) > 2 else "fullkey"
import os
T = os.environ.get("T", "/work/target-linux"); K = f"{os.environ.get('KEYS', T + '/eval-keys')}/server-{v}"
srv = subprocess.Popen(["taskset", "-c", "0", f"{T}/tiny-release/hqclethe-server-stateful", "--port", "24399",
                        "--variant", v, "--key", K + ".sk", "--max-entries", "1024"],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
time.sleep(1)
flood = None
if kind != "none":
    flood = subprocess.Popen(["taskset", "-c", "2", f"{T}/release/hqclethe-client-stateful", "flood-client", "--addr", "127.0.0.1:24399",
                              "--variant", v, "--server-key", K + ".pk", "--duration", "14", "--sockets", "128", "--source-ips", "1",
                              "--kind", kind], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    time.sleep(3.5)
rows = []
end = time.time() + 9
while time.time() < end:
    t0 = time.time()
    p = subprocess.run(["taskset", "-c", "4", f"{T}/release/hqclethe-client-stateful", "client", "--addr", "127.0.0.1:24399",
                        "--variant", v, "--server-key", K + ".pk", "--bind-ip", "127.2.0.1"],
                       capture_output=True, text=True, timeout=30)
    ph = dict((m.group(1), float(m.group(2))) for m in re.finditer(r"\[phase\] (\S+) t=([0-9.]+)", p.stderr))
    rt = re.findall(r"\[retry\] (\S+)", p.stderr)
    rows.append((p.returncode, ph, rt, time.time() - t0))
    time.sleep(max(0, 0.2 - (time.time() - t0)))
srv.terminate()
if flood: flood.kill()
hello = [r[1].get("hello_response_received", 99) - r[1].get("hello_sent", 0) for r in rows if r[0] == 0]
frag = [r[1].get("shared_secret_derived", 99) - r[1].get("key_fragments_sent", 0) for r in rows if r[0] == 0]
retries = {}
for r in rows:
    for x in r[2]: retries[x] = retries.get(x, 0) + 1
print(f"{v} {kind}: sessions {len(rows)} ok {sum(r[0]==0 for r in rows)}; hello phase median {st.median(hello):.4f} s, "
      f">0.4 s in {sum(h>0.4 for h in hello)}; fragment phase median {st.median(frag):.4f} s, >0.09 s in {sum(f>0.09 for f in frag)}; "
      f"retry lines {retries}; total median {st.median(r[3] for r in rows):.3f}")
