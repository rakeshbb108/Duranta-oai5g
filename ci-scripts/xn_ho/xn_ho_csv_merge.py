#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-CSSL-1.0
"""
Xn HO latency CSV merge: joins the per-process CSVs written by the RRC-layer
instrumentation (common/utils/xn_ho_latency.h, one row per handover attempt
per side) into one row per handover, and computes the paper's Table VII
aggregate statistics and Table VIII success/failure counts.

Source gNB, target gNB, and (in a split CU-CP/CU-UP deployment) the target's
CU-UP are normally separate hosts, so each process appends its own local CSV
(xn_ho_latency_source.csv / xn_ho_latency_target.csv / xn_ho_latency_cuup.csv,
default directory "."; override with the XN_HO_LATENCY_CSV_DIR env var each
process was run with). Copy all files to one place (e.g. scp) before running
this script. In a monolithic gNB, the target and cuup files are the same
process's output but still two separate files -- pass both.

Join keys:
  - source <-> target: s_xnap_id (the source NG-RAN node UE XnAP ID),
    allocated by the source and carried in every XNAP message of the
    procedure. This id is a per-gNB, per-role counter, so in a ping-pong
    test (gNB A is source in round 1, target in round 2) gNB A's OWN
    source.csv and target.csv rows can end up sharing an s_xnap_id purely
    by coincidence -- those are never the same handover (a real Xn HO
    always crosses two different gNBs), so a candidate is only accepted if
    its target_gnb_id differs from the source row's source_gnb_id. Pass
    every gNB's source.csv and target.csv (--source/--target take one or
    more paths) and the script does this matching across all of them.
  - target <-> cuup: rrc_ue_id. CU-UP's own ue_id is always identical to the
    target CU-CP's rrc_ue_id (CU-CP sets gNB_cu_cp_ue_id = UE->rrc_ue_id in
    the E1AP Bearer Context Setup Request, and CU-UP mirrors it verbatim as
    its own gNB_cu_up_ue_id), so this holds in both monolithic and split
    deployments without any new correlation id.

Radio Exec (T4-T3), Interruption, and any T0/T7-spanning total cross source
and target (and, for interruption, CU-UP) hosts, so they use CLOCK_REALTIME
(wall_ns) and require NTP/PTP-synced clocks across all hosts involved --
same constraint as this project's existing wall_clock log-based tooling.
Xn Prep (T2-T1) and Path-Switch (T6-T5) are single-process intervals,
computed from CLOCK_MONOTONIC (mono_ns) and exact regardless of clock sync.

Usage (two-gNB ping-pong, one source/target/cuup file collected from each):
  ./xn_ho_csv_merge.py \
      --source gnb1_xn_ho_latency_source.csv gnb2_xn_ho_latency_source.csv \
      --target gnb1_xn_ho_latency_target.csv gnb2_xn_ho_latency_target.csv \
      --cuup   gnb1_xn_ho_latency_cuup.csv   gnb2_xn_ho_latency_cuup.csv \
      --out paper/results/xn_ho_latency.csv
"""
import argparse
import csv
import statistics
import sys


def read_rows(path):
    try:
        with open(path, newline="") as f:
            return list(csv.DictReader(f))
    except FileNotFoundError:
        print(f"warning: {path} not found, treating as empty", file=sys.stderr)
        return []


def to_int(row, key, default=0):
    v = row.get(key, "")
    return int(v) if v not in (None, "") else default


def parse_drb_list_u32(s):
    """Parse "id:value;id:value" into {id: value}."""
    out = {}
    if not s:
        return out
    for item in s.split(";"):
        if not item:
            continue
        drb_id, value = item.split(":")
        out[int(drb_id)] = int(value)
    return out


def ms(delta_ns):
    return round(delta_ns / 1e6, 3)


def merge_row(src, tgt, cuup_rows):
    """Build one paper-table row from a matched (source, target) pair, plus
    the CU-UP first-tx rows for this UE (cuup_rows, one per DRB, possibly
    empty). tgt may be None if only the source side reported (e.g. handover
    failed before the target ever heard back, or the target's file wasn't
    found)."""
    out = {
        "s_xnap_id": src["s_xnap_id"],
        "source_gnb": src.get("source_gnb_id", ""),
        "target_gnb": tgt.get("target_gnb_id", "") if tgt else "",
        "rrc_ue_id": src.get("rrc_ue_id", ""),
        "status": src.get("outcome", ""),
        "ho_start_wall_ns": to_int(src, "t0_wall_ns"),
        "ho_complete_wall_ns": "",
        "total_latency_ms": "",
        "xn_prep_ms": "",
        "radio_exec_ms": "",
        "path_switch_ms": "",
        "context_release_ms": "",
        "interruption_ms": "",
        "est_lost_pdcp_pdus": "",
    }

    t1_mono, t2_mono = to_int(src, "t1_mono_ns"), to_int(src, "t2_mono_ns")
    if t1_mono and t2_mono:
        out["xn_prep_ms"] = ms(t2_mono - t1_mono)

    t0_wall, t3_wall = to_int(src, "t0_wall_ns"), to_int(src, "t3_wall_ns")

    if tgt is not None and tgt.get("outcome") == "SUCCESS":
        t5_mono, t6_mono = to_int(tgt, "t5_mono_ns"), to_int(tgt, "t6_mono_ns")
        t6_mono2, t7_mono = to_int(tgt, "t6_mono_ns"), to_int(tgt, "t7_mono_ns")
        t4_wall, t7_wall = to_int(tgt, "t4_wall_ns"), to_int(tgt, "t7_wall_ns")

        if t5_mono and t6_mono:
            out["path_switch_ms"] = ms(t6_mono - t5_mono)
        if t6_mono2 and t7_mono:
            out["context_release_ms"] = ms(t7_mono - t6_mono2)
        if t3_wall and t4_wall:
            out["radio_exec_ms"] = ms(t4_wall - t3_wall)
        if t0_wall and t7_wall:
            out["ho_complete_wall_ns"] = t7_wall
            out["total_latency_ms"] = ms(t7_wall - t0_wall)

        # Interruption + loss estimate: earliest first-delivered DRB at the
        # target's CU-UP vs. the source's T3 (source stops scheduling this
        # UE) and its SN Status Transfer boundary for the same DRB.
        #
        # cuup_rows holds every DRB (re)activation ever seen for this
        # rrc_ue_id -- including unrelated earlier sessions, since a gNB
        # process reuses rrc_ue_id slots over its lifetime -- so narrow to
        # the ones that actually landed inside this handover's window
        # (T3..T7) rather than trusting rrc_ue_id alone.
        window_rows = [r for r in cuup_rows if t3_wall and int(r["wall_ns"]) >= t3_wall and (not t7_wall or int(r["wall_ns"]) <= t7_wall)]
        first_tx_by_drb = {int(r["drb_id"]): (int(r["sn"]), int(r["wall_ns"])) for r in window_rows}
        dl_count_sn = parse_drb_list_u32(src.get("dl_count_sn", ""))

        if first_tx_by_drb and t3_wall:
            earliest_drb = min(first_tx_by_drb, key=lambda d: first_tx_by_drb[d][1])
            out["interruption_ms"] = ms(first_tx_by_drb[earliest_drb][1] - t3_wall)

        total_lost = 0
        any_estimate = False
        for drb_id, (first_sn, _) in first_tx_by_drb.items():
            if drb_id in dl_count_sn:
                any_estimate = True
                total_lost += max(0, first_sn - dl_count_sn[drb_id])
        if any_estimate:
            out["est_lost_pdcp_pdus"] = total_lost

    return out


def stats(values):
    if not values:
        return {"min": "", "max": "", "mean": "", "median": "", "std": "", "p95": ""}
    values = sorted(values)
    n = len(values)
    p95_idx = min(n - 1, int(round(0.95 * (n - 1))))
    return {
        "min": round(values[0], 3),
        "max": round(values[-1], 3),
        "mean": round(statistics.mean(values), 3),
        "median": round(statistics.median(values), 3),
        "std": round(statistics.pstdev(values), 3) if n > 1 else 0.0,
        "p95": round(values[p95_idx], 3),
    }


def read_many(paths):
    rows = []
    for p in paths or []:
        rows.extend(read_rows(p))
    return rows


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--source", required=True, nargs="+",
                     help="one or more xn_ho_latency_source.csv files, one per gNB that ever acted as source")
    ap.add_argument("--target", required=True, nargs="+",
                     help="one or more xn_ho_latency_target.csv files, one per gNB that ever acted as target")
    ap.add_argument("--cuup", nargs="+",
                     help="one or more target-CU-UP xn_ho_latency_cuup.csv files (optional; enables interruption/loss)")
    ap.add_argument("--out", required=True, help="merged per-HO CSV output path (e.g. paper/results/xn_ho_latency.csv)")
    args = ap.parse_args()

    source_rows = read_many(args.source)
    target_rows = read_many(args.target)
    cuup_rows = read_many(args.cuup)

    target_by_sid = {}
    for t in target_rows:
        target_by_sid.setdefault(t["s_xnap_id"], []).append(t)

    cuup_by_ue = {}
    for c in cuup_rows:
        cuup_by_ue.setdefault(c["rrc_ue_id"], []).append(c)

    merged = []
    for src in source_rows:
        # A given gNB's own s_xnap_id counter resets/restarts independently per
        # role, so in a ping-pong test (gNB A source in round 1, target in
        # round 2) the SAME gNB can produce a source row and a target row that
        # share an s_xnap_id purely by coincidence -- those two are never the
        # same handover (a real Xn HO always crosses two different gNBs), so
        # any same-gNB candidate is rejected before picking a match.
        candidates = target_by_sid.get(src["s_xnap_id"], [])
        match_idx = next((i for i, t in enumerate(candidates) if t.get("target_gnb_id") != src.get("source_gnb_id")), None)
        tgt = candidates.pop(match_idx) if match_idx is not None else None
        this_cuup_rows = cuup_by_ue.get(tgt["rrc_ue_id"], []) if tgt else []
        merged.append(merge_row(src, tgt, this_cuup_rows))

    fieldnames = ["s_xnap_id", "source_gnb", "target_gnb", "rrc_ue_id", "status",
                  "ho_start_wall_ns", "ho_complete_wall_ns", "total_latency_ms",
                  "xn_prep_ms", "radio_exec_ms", "path_switch_ms", "context_release_ms",
                  "interruption_ms", "est_lost_pdcp_pdus"]
    with open(args.out, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for row in merged:
            writer.writerow(row)
    print(f"wrote {len(merged)} row(s) to {args.out}")

    # Table VII: aggregate stats over successful handovers only
    successes = [r for r in merged if r["status"] == "SUCCESS"]
    print(f"\n=== Table VII input (n={len(successes)} successful handovers) ===")
    for label, key in [("Xn prep (ms)", "xn_prep_ms"),
                        ("Radio exec (ms)", "radio_exec_ms"),
                        ("Path-switch (ms)", "path_switch_ms"),
                        ("Interruption (ms)", "interruption_ms")]:
        values = [r[key] for r in successes if r[key] != ""]
        s = stats(values)
        print(f"  {label}: min={s['min']} max={s['max']} mean={s['mean']} "
              f"median={s['median']} std={s['std']} p95={s['p95']} (n={len(values)})")

    # Table VIII: success/failure counts
    total = len(merged)
    n_success = len(successes)
    n_failed = total - n_success
    print(f"\n=== Table VIII ===")
    print(f"  Successful: {n_success} ({round(100 * n_success / total, 1) if total else 0}%)")
    print(f"  Failed:     {n_failed} ({round(100 * n_failed / total, 1) if total else 0}%)")
    print(f"  Total:      {total} (100%)")
    if n_failed:
        from collections import Counter
        reasons = Counter(r["status"] for r in merged if r["status"] != "SUCCESS")
        for reason, count in reasons.most_common():
            print(f"    {reason}: {count}")


if __name__ == "__main__":
    main()
