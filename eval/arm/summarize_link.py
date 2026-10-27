#!/usr/bin/env python3
"""Prints the link table from raw/link (iperf3 JSON, Pi UDP counters before and after, mpstat)."""

import glob
import json
import os
import sys

DIR = sys.argv[1] if len(sys.argv) > 1 else "raw/link"


def udp_counters(path: str) -> dict:
    lines = open(path).read().splitlines()
    return dict(zip(lines[0].split()[1:], map(int, lines[1].split()[1:])))


def mpstat_average(path: str) -> dict:
    rows = {}
    for line in open(path):
        fields = line.split()
        if fields and fields[0] == "Average:" and fields[1] in ("0", "1", "2", "3"):
            rows[fields[1]] = {"usr": fields[2], "sys": fields[4], "irq": fields[6], "soft": fields[7], "idle": fields[-1]}
    return rows


print("| test | Mbit/s received | Mbit/s sent | datagrams/s received | Pi InDatagrams | Pi RcvbufErrors | Pi core 0 soft % | Pi core 2 usr+sys+soft % | Pi core 3 soft % |")
print("|---|---|---|---|---|---|---|---|---|")
for path in sorted(glob.glob(f"{DIR}/*.json")):
    name = os.path.basename(path)[:-5]
    end = json.load(open(path))["end"]
    if "sum_received" in end:
        recv, sent, pps = end["sum_received"]["bits_per_second"], end["sum_sent"]["bits_per_second"], None
    else:
        s = end["sum"]
        sent, pps = s["bits_per_second"], s["packets"] / s["seconds"]
        recv = sent * (1 - s["lost_percent"] / 100)
        pps = None
    before, after = udp_counters(f"{DIR}/{name}.pi_before.txt"), udp_counters(f"{DIR}/{name}.pi_after.txt")
    cores = mpstat_average(f"{DIR}/{name}.mpstat.txt")
    busy2 = sum(float(cores["2"][k]) for k in ("usr", "sys", "soft")) if "2" in cores else float("nan")
    print(f"| {name} | {recv / 1e6:.0f} | {sent / 1e6:.0f} | {round((after["InDatagrams"] - before["InDatagrams"]) / 10) if "udp" in name else "-"} | {after['InDatagrams'] - before['InDatagrams']} | "
          f"{after['RcvbufErrors'] - before['RcvbufErrors']} | {cores['0']['soft']} | {busy2:.1f} | {cores['3']['soft']} |")
