import argparse
import csv
import io
import json
import platform
import random
import tracemalloc
from datetime import datetime, timedelta
from itertools import combinations
from pathlib import Path
from statistics import mean, stdev
from time import perf_counter

from reportlab.graphics import renderSVG
from reportlab.graphics.charts.barcharts import VerticalBarChart
from reportlab.graphics.shapes import Drawing, String
from reportlab.lib.colors import HexColor
from sqlalchemy import delete, update

from . import analysis, db, demo, parsers, vault
from .settings import ROOT

DESCRIPTIONS = {
    "detection": "Compare case-and-rule predictions with the synthetic scenario labels.",
    "correlation": "Compare source isolation, a time-only baseline and the platform's evidence-aware event links.",
    "missing_evidence": "Remove an exact proportion of fixture records and evaluate the remaining graph against original truth.",
    "timestamp_inconsistency": "Inject a known source clock offset, count changed event orderings and test correction.",
    "integrity": "Alter preserved bytes, edit a custody record and remove its final entry in a disposable database.",
    "scalability": "Measure normalization and graph construction on generated records in one process.",
    "confidence": "Compare the platform score under single-source, corroborated and integrity-failed evidence.",
}
LIMITATIONS = [
    "Synthetic labels and fixture distributions do not establish production effectiveness.",
    "Detection is evaluated per case and rule, so repeated alerts for one rule count once.",
    (
        "Correlation evaluates all unordered event pairs in the labeled fixture, with the original positive labels retained "
        "after removal. A large negative class can make the false-positive rate look small."
    ),
    "Scalability timings include Python allocation tracing. Peak MiB measures traced Python allocations, not process RSS.",
    "Clock tests inject known offsets. Real offsets require independent validation.",
]


def metric(truth, predicted, candidates):
    if not truth <= candidates or not predicted <= candidates:
        raise ValueError("Truth and predictions must use the same candidate universe")
    tp = len(truth & predicted)
    fp = len(predicted - truth)
    fn = len(truth - predicted)
    tn = len(candidates - (truth | predicted))
    precision = tp / (tp + fp) if tp + fp else 0
    recall = tp / (tp + fn) if tp + fn else 0
    return {
        "precision": precision,
        "recall": recall,
        "f1": 2 * precision * recall / (precision + recall)
        if precision + recall
        else 0,
        "false_positive_rate": fp / (fp + tn) if fp + tn else 0,
        "tp": tp,
        "fp": fp,
        "tn": tn,
        "fn": fn,
    }


def normalized(record, identifier, source):
    return dict(
        parsers.normalize(record, "json", identifier, 0, 0),
        id=identifier,
        evidence_id=source,
    )


def evaluate_detection(seed, independent=False):
    expected, actual = set(), set()
    candidates = {
        (index, key) for index in range(len(demo.SCENARIOS)) for key in analysis.RULES
    }
    configs = [
        {"id": key, "enabled": True, "threshold": threshold, "window": window}
        for key, (_, _, threshold, window, _) in analysis.RULES.items()
    ]
    indicator = {
        "id": "benchmark-indicator",
        "kind": "ipv4",
        "value": "203.0.113.44",
        "expires_at": None,
    }
    for index in range(len(demo.SCENARIOS)):
        primary, secondary, labels = demo.scenario(index, seed)
        expected.update((index, label) for label in labels)
        records = [
            normalized(row, f"{source}:{i}", source)
            for source, rows in (("identity", primary), ("observations", secondary))
            for i, row in enumerate(rows)
        ]
        partitions = (
            [
                [row for row in records if row["evidence_id"] == source]
                for source in ("identity", "observations")
            ]
            if independent
            else [records]
        )
        for partition in partitions:
            matched = analysis.indicator_matches(
                partition, [indicator] if index == 2 else []
            )
            actual.update(
                (index, finding[0])
                for finding in analysis.predictions(partition, [], matched, configs)
            )
    return metric(expected, actual, candidates)


def pair(left, right):
    return tuple(sorted((left, right)))


def labeled_events(seed):
    rng = random.Random(seed)
    events, truth = [], set()
    for index in range(30):
        moment = demo.BASE + timedelta(seconds=index * 120)
        correlation_host = f"orchid-case-{index}"
        identities = [
            ("identity", rng.randrange(0, 7)),
            ("network", rng.randrange(8, 16)),
            ("audit", rng.randrange(18, 27)),
        ]
        labeled = []
        for position, (kind, moment_offset) in enumerate(identities):
            identifier = analysis.key_for(str(seed), str(index), str(position))
            labeled.append(identifier)
            events.append(
                normalized(
                    {
                        "timestamp": db.utc(moment + timedelta(seconds=moment_offset)),
                        "action": "observed",
                        "hostname": correlation_host,
                        "username": f"orchid-{index}",
                        "source_ip": f"192.0.2.{index + 10}",
                    },
                    identifier,
                    kind,
                )
            )
        truth.update(pair(left, right) for left, right in combinations(labeled, 2))
        for benign in range(3):
            identifier = analysis.key_for(
                str(seed), str(index), str(benign + len(identities))
            )
            events.append(
                normalized(
                    {
                        "timestamp": db.utc(
                            moment + timedelta(seconds=rng.randrange(0, 30))
                        ),
                        "action": "observed",
                        "hostname": correlation_host
                        if benign == 0 and index % 3 == 0
                        else f"unrelated-{index}-{benign}",
                        "username": f"orchid-{index}"
                        if benign == 1 and index % 5 == 0
                        else f"operator-{index}-{benign}",
                    },
                    identifier,
                    identities[benign][0],
                )
            )
    return events, truth


def predictions(events, method):
    if method == "evidence-aware":
        return {
            pair(left, right)
            for left, right, attrs in analysis.correlate(events, 30).edges(data=True)
            if attrs["kind"] == "inferred"
        }
    relevant = set()
    ordered = sorted(events, key=analysis.event_order)
    for index, left in enumerate(ordered):
        for right in ordered[index + 1 :]:
            left_time = datetime.fromisoformat(left["timestamp"])
            right_time = datetime.fromisoformat(right["timestamp"])
            if (right_time - left_time).total_seconds() > 30:
                break
            if method == "time-only" or left["evidence_id"] == right["evidence_id"]:
                relevant.add(pair(left["id"], right["id"]))
    return relevant


def time_conditions(events, truth, candidates):
    original_times = {row["id"]: row["timestamp"] for row in events}
    for magnitude, correction in ((0, 0), (30, 0), (90, 0), (90, -90)):
        affected = [
            dict(
                row,
                timestamp=db.utc(
                    datetime.fromisoformat(row["timestamp"])
                    + timedelta(seconds=magnitude + correction)
                ),
            )
            if row["evidence_id"] == "network"
            else row
            for row in events
        ]
        errors = sum(
            left["timestamp"] < right["timestamp"]
            and original_times[left["id"]] > original_times[right["id"]]
            for left, right in combinations(
                sorted(affected, key=analysis.event_order), 2
            )
        )
        yield {
            "condition": f"{magnitude:+} s skew, {correction:+} s correction",
            "order_errors": errors,
            **metric(truth, predictions(affected, "evidence-aware"), candidates),
        }


def integrity():
    db.initialize()
    with db.transaction() as conn:
        user = db.add(
            conn,
            db.users,
            username=db.uid(),
            password_hash="disabled-in-research",
            role="administrator",
            created_at=db.utc(),
        )
        case = db.add(
            conn,
            db.cases,
            owner_id=user["id"],
            title="Integrity evaluation",
            description="Synthetic",
            created_at=db.utc(),
            updated_at=db.utc(),
            severity="info",
            status="open",
            investigator="research",
            classification="synthetic",
            synthetic=True,
        )
    item = vault.import_file(
        case["id"],
        "research",
        io.BytesIO(b'{"action":"observed"}'),
        "sample.json",
        "json",
        "research",
        None,
        0,
        0,
    )
    eid = item["id"]
    path = vault.path_for(eid)

    def check(conn):
        return vault.custody_verify(
            conn, db.one(conn, db.evidence, db.evidence.c.id == eid)
        )["valid"]

    with db.transaction() as conn:
        clean_bytes = vault.verify(conn, item, "research")["status"] == "verified"
        clean_chain = check(conn)
    path.write_bytes(b'{"action":"tampered"}')
    with db.transaction() as conn:
        corrupt_bytes = vault.verify(conn, item, "research")["status"] == "failed"
        selector = (db.custody.c.evidence_id == eid, db.custody.c.sequence == 1)
        original = db.one(conn, db.custody, *selector)
        conn.execute(
            update(db.custody)
            .where(*selector)
            .values(reason="Modified research record")
        )
        corrupt_chain = not check(conn)
        conn.execute(
            update(db.custody).where(*selector).values(reason=original["reason"])
        )
        tail = db.one(conn, db.evidence, db.evidence.c.id == eid)["custody_count"]
        conn.execute(
            delete(db.custody).where(
                db.custody.c.evidence_id == eid, db.custody.c.sequence == tail
            )
        )
        truncated = not check(conn)
        conn.execute(delete(db.users).where(db.users.c.id == user["id"]))
    path.unlink()
    return [
        ("Original evidence bytes", clean_bytes),
        ("Original custody chain", clean_chain),
        ("Changed evidence bytes", corrupt_bytes),
        ("Modified custody entry", corrupt_chain),
        ("Deleted final custody entry", truncated),
    ]


def scaling(count):
    tracemalloc.start()
    start = perf_counter()
    generated = [
        normalized(
            {
                "timestamp": db.utc(demo.BASE + timedelta(seconds=i)),
                "action": "observed",
                "hostname": f"orchid-{i % 19}",
                "username": f"operator-{i % 300}",
            },
            str(i),
            f"source-{i % 41}",
        )
        for i in range(count)
    ]
    correlation_start = perf_counter()
    links = analysis.correlate(generated, 30).number_of_edges()
    elapsed = perf_counter() - start
    peak = tracemalloc.get_traced_memory()[1]
    tracemalloc.stop()
    return {
        "events": count,
        "seconds": elapsed,
        "correlation_seconds": elapsed - (correlation_start - start),
        "throughput": count / elapsed,
        "peak_mib": peak / 1024**2,
        "relationships": links,
    }


def figure(path, title, labels, values, maximum):
    drawing = Drawing(680, 310)
    drawing.add(
        String(
            35,
            277,
            title,
            fontName="Helvetica-Bold",
            fontSize=17,
            fillColor=HexColor("#172d45"),
        )
    )
    chart = VerticalBarChart()
    chart.x, chart.y, chart.width, chart.height = 58, 55, 590, 190
    chart.data = [values]
    chart.valueAxis.valueMin = 0
    chart.valueAxis.valueMax = maximum
    chart.valueAxis.valueStep = maximum / 5
    chart.categoryAxis.categoryNames = labels
    chart.bars[0].fillColor = HexColor("#197f91")
    drawing.add(chart)
    renderSVG.drawToFile(drawing, str(path))


def baseline_results(seed, events, truth, candidates):
    for independent, method in (
        (False, "platform rules"),
        (True, "independent sources"),
    ):
        yield dict(
            experiment="detection",
            method=method,
            condition="five original scenarios",
            **evaluate_detection(seed, independent=independent),
        )
    for method in ("source-isolated", "time-only", "evidence-aware"):
        yield dict(
            experiment="correlation",
            method=method,
            condition="all records",
            **metric(truth, predictions(events, method), candidates),
        )


def candidates_for(events):
    return {pair(left["id"], right["id"]) for left, right in combinations(events, 2)}


def repeat_baselines(seeds, output):
    rows = []
    for seed in seeds:
        events, truth = labeled_events(seed)
        rows.extend(
            dict(row, seed=seed)
            for row in baseline_results(seed, events, truth, candidates_for(events))
        )
    groups = sorted({(row["experiment"], row["method"]) for row in rows})
    metrics = ("precision", "recall", "f1", "false_positive_rate")
    summary = []
    for experiment, method in groups:
        subset = [
            row
            for row in rows
            if (row["experiment"], row["method"]) == (experiment, method)
        ]
        summaries = {}
        for metric_name in metrics:
            values = [row[metric_name] for row in subset]
            summaries[metric_name] = {"mean": mean(values), "sample_sd": stdev(values)}
        summary.append({"experiment": experiment, "method": method, **summaries})
    data = {"seeds": seeds, "rows": rows, "summary": summary}
    output.mkdir(parents=True, exist_ok=True)
    (output / "multi-seed.json").write_text(
        json.dumps(data, indent=2) + "\n", encoding="utf-8"
    )
    print(f"Replayed {len(rows)} baseline conditions across {len(seeds)} seeds")


def run(seed, sizes, output, figures):
    events, truth = labeled_events(seed)
    candidates = candidates_for(events)
    rows = list(baseline_results(seed, events, truth, candidates))

    def add(experiment, method, condition, **values):
        rows.append(
            dict(experiment=experiment, method=method, condition=condition, **values)
        )

    ordered = events.copy()
    random.Random(seed).shuffle(ordered)
    for level in (0, 10, 25, 50):
        filtered = ordered[len(ordered) * level // 100 :]
        add(
            "missing_evidence",
            "evidence-aware",
            f"{level}% removed",
            **metric(truth, predictions(filtered, "evidence-aware"), candidates),
        )
    for stats in time_conditions(events, truth, candidates):
        add("timestamp_inconsistency", "evidence-aware", **stats)
    for condition, success in integrity():
        add(
            "integrity",
            "vault and custody",
            condition,
            result="pass" if success else "fail",
        )
    for count in sizes:
        add(
            "scalability",
            "normalization and graph",
            f"{count:,} records",
            **scaling(count),
        )
    verified = {"integrity": "verified", "state": "processed"}
    fail = {"integrity": "failed", "state": "processed"}
    for label, support, checks, consistency in (
        ("single source", events[:1], [verified], None),
        ("corroborated", events[:2], [verified] * 2, 1.0),
        ("conflicting integrity", events[:2], [verified, fail], 1.0),
        ("no evidence", [], [], None),
    ):
        quality = analysis.score(support, checks, consistency=consistency)
        add(
            "confidence",
            "weighted index",
            label,
            score=quality["score"],
            category=quality["category"],
        )
    data = {
        "seed": seed,
        "generated_at": db.utc(),
        "descriptions": DESCRIPTIONS,
        "limitations": LIMITATIONS,
        "configuration": {
            "scenarios": 5,
            "pair_fixture_events": len(events),
            "labeled_pairs": len(truth),
            "window_seconds": 30,
            "platform": platform.platform(),
            "python": platform.python_version(),
        },
        "rows": rows,
    }
    output.mkdir(parents=True, exist_ok=True)
    figures.mkdir(parents=True, exist_ok=True)
    (output / "results.json").write_text(json.dumps(data, indent=2), encoding="utf-8")
    keys = list(dict.fromkeys(key for row in rows for key in row))
    with (output / "results.csv").open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=keys)
        writer.writeheader()
        writer.writerows(rows)
    with db.transaction() as conn:
        db.add(
            conn,
            db.experiments,
            timestamp=data["generated_at"],
            seed=seed,
            results=data,
        )
    selected = [row for row in rows if row["experiment"] == "correlation"]
    figure(
        figures / "correlation-f1.svg",
        "Correlation F1 by method",
        [row["method"] for row in selected],
        [row["f1"] for row in selected],
        1.0,
    )
    selected = [row for row in rows if row["experiment"] == "missing_evidence"]
    figure(
        figures / "missing-evidence-f1.svg",
        "Correlation F1 with missing evidence",
        [row["condition"] for row in selected],
        [row["f1"] for row in selected],
        1.0,
    )
    print(f"Saved {len(rows)} measurements to {output}")


def main():
    parser = argparse.ArgumentParser(
        description="Run deterministic synthetic forensic evaluation"
    )
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument(
        "--repeat-seeds",
        type=int,
        nargs="+",
        help="Repeat only detection and correlation baselines",
    )
    parser.add_argument("--sizes", type=int, nargs="+", default=[1000, 10000, 50000])
    parser.add_argument("--output", type=Path, default=ROOT / "research" / "results")
    parser.add_argument("--figures", type=Path, default=ROOT / "research" / "figures")
    args = parser.parse_args()
    if args.repeat_seeds:
        if (
            len(set(args.repeat_seeds)) != len(args.repeat_seeds)
            or len(args.repeat_seeds) < 2
        ):
            parser.error("Use at least two distinct repeat seeds")
        repeat_baselines(args.repeat_seeds, args.output)
        return
    if any(not 1 <= size <= 100_000 for size in args.sizes):
        parser.error("Sizes must be from 1 to 100,000")
    import os

    if not os.environ.get("TTX_DATA_DIR") or os.environ.get("TTX_DATABASE_URL"):
        parser.error(
            "Set TTX_DATA_DIR to a disposable local research directory, or use scripts/run-research.ps1"
        )
    run(args.seed, args.sizes, args.output, args.figures)


if __name__ == "__main__":
    main()
