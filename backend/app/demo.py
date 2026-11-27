import argparse
import getpass
import io
import json
import os
import random
from datetime import UTC, datetime, timedelta
from pathlib import Path
from tempfile import TemporaryDirectory

from scapy.layers.dns import DNS, DNSQR
from scapy.layers.inet import IP, UDP
from scapy.layers.l2 import Ether
from scapy.utils import wrpcap
from sqlalchemy import select

from . import analysis, db, schemas, security, settings, vault

BASE = datetime(2025, 4, 8, 14, 0, tzinfo=UTC)
SCENARIOS = (
    ("Suspicious account access", "Identity anomaly", "high"),
    ("Unexpected privilege changes", "Account privilege", "high"),
    ("Unusual outbound communication", "Network anomaly", "medium"),
    ("Potential unauthorized file access", "Data access", "high"),
    ("Benign administrative activity", "Authorized maintenance", "low"),
)


def scenario(index, seed=42):
    rng = random.Random(seed + index)
    base = BASE + timedelta(days=index)
    host = f"orchid-{('gateway', 'directory', 'relay', 'files', 'maintenance')[index]}"
    user = f"analyst-{index + 1}"
    primary = []

    def row(second, category, action, **fields):
        return {
            "timestamp": db.utc(base + timedelta(seconds=second)),
            "hostname": host,
            "username": user,
            "category": category,
            "action": action,
            "source_ip": f"192.0.2.{20 + index}",
            **fields,
        }

    for sequence in range(15):
        primary.append(
            row(
                sequence * 12,
                "authentication",
                "login",
                outcome="success",
                source_port=rng.randint(40000, 56000),
            )
        )
    if index == 0:
        primary.extend(
            row(240 + i * 9, "authentication", "login", outcome="failure")
            for i in range(6)
        )
        secondary = [
            row(301, "authentication", "login", outcome="success"),
            row(330, "account", "admin_activity", flagged=True, severity="high"),
        ]
        truth = ["auth_failures", "auth_followup", "admin_activity"]
    elif index == 1:
        secondary = [
            row(138, "account", "privilege_change", severity="high"),
            row(150, "service", "service_change", expected=True),
        ]
        truth = ["privilege_change"]
    elif index == 2:
        secondary = [
            row(
                140,
                "network",
                "connection",
                destination_ip="203.0.113.44",
                bytes=2_400_000,
                protocol="TCP",
                destination_port=443,
                flagged=True,
                severity="high",
            ),
            row(
                167,
                "network",
                "connection",
                destination_ip="198.51.100.22",
                bytes=320,
                protocol="UDP",
                destination_port=53,
                domain="lookup.orchid.example",
            ),
        ]
        truth = ["transfer", "network_unusual", "indicator"]
    elif index == 3:
        secondary = [
            row(
                139,
                "file",
                "file_access",
                file_path="/orchid/finance/ledger.txt",
                flagged=True,
                severity="high",
            ),
            row(
                150,
                "process",
                "process_start",
                process_name="archive-viewer",
                flagged=True,
            ),
        ]
        truth = ["file_access", "process_start"]
    else:
        primary.extend(
            row(240 + i * 9, "authentication", "login", outcome="failure")
            for i in range(5)
        )
        secondary = [
            row(300, "account", "privilege_change", expected=True),
            row(315, "authentication", "login", outcome="success", expected=True),
        ]
        truth = []
    secondary += [
        dict(secondary[0]),
        {"timestamp": "unavailable", "action": "collection_gap"},
    ]
    return primary, secondary, truth


def pcap(path):
    packets = []
    for i in range(6):
        destination = "203.0.113.44" if i < 4 else "198.51.100.22"
        packet = (
            Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02")
            / IP(src="192.0.2.22", dst=destination)
            / UDP(sport=50000 + i, dport=53)
            / DNS(id=i, rd=1, qd=DNSQR(qname=f"service-{i}.orchid.example"))
        )
        packet.time = BASE.timestamp() + 2 * 86400 + 125 + i * 8
        packets.append(packet)
    wrpcap(str(path), packets)


def encoded(rows):
    return json.dumps(rows, ensure_ascii=False, indent=2).encode()


def generate(root, seed):
    root.mkdir(parents=True, exist_ok=True)
    truth = {}
    for index, (title, _, _) in enumerate(SCENARIOS):
        primary, secondary, labels = scenario(index, seed)
        (root / f"case-{index + 1}-identity.json").write_bytes(encoded(primary))
        (root / f"case-{index + 1}-observations.json").write_bytes(encoded(secondary))
        truth[str(index + 1)] = {"case": title, "rules": labels}
    (root / "ground-truth.json").write_bytes(encoded({"seed": seed, "cases": truth}))
    pcap(root / "orchid-offline.pcap")


def seed_demo(username, password, seed):
    from .api import save_indicator

    settings.validate_demo_configuration()
    with db.transaction() as connection:
        user = db.one(connection, db.users, db.users.c.username == username)
        if user is not None and not security.verify_password(
            password, user["password_hash"]
        ):
            raise SystemExit("Existing account password did not match.")
        if not settings.DEMO_PROFILE.is_file():
            existing = connection.scalars(select(db.users.c.id)).all()
            cases = connection.execute(
                select(db.cases.c.owner_id, db.cases.c.synthetic)
            ).all()
            legacy_demo = (
                user is not None
                and existing == [user["id"]]
                and cases
                and all(
                    owner_id == user["id"] and synthetic
                    for owner_id, synthetic in cases
                )
            )
            if (existing or cases) and not legacy_demo:
                raise SystemExit(
                    "Choose a separate empty data directory for the synthetic demo."
                )
            settings.DEMO_PROFILE.touch(exist_ok=True)
        if user is None:
            user = security.create_user(connection, username, password, "administrator")
    for index, (title, classification, severity) in enumerate(SCENARIOS):
        case_id = analysis.key_for("demo", username, str(seed), str(index))[:36]
        with db.transaction() as connection:
            if db.one(connection, db.cases, db.cases.c.id == case_id):
                continue
            db.add(
                connection,
                db.cases,
                id=case_id,
                owner_id=user["id"],
                title=title,
                description="Fictional Orchid Research demonstration. The case examines source records from the "
                "identity and telemetry systems and preserves the original collected bytes.",
                investigator="Orchid response team",
                created_at=db.utc(),
                updated_at=db.utc(),
                classification=classification,
                severity=severity,
                status="under_investigation",
                synthetic=True,
            )
            db.record(
                connection, username, "demo_case_created", case_id, f"Seed {seed}"
            )
            if index == 2:
                save_indicator(
                    connection,
                    case_id,
                    schemas.Indicator(
                        kind="ipv4",
                        value="203.0.113.44",
                        source="Orchid synthetic reference",
                        confidence=70,
                        description="Reserved address used for deterministic matching.",
                        tags=["synthetic", "network"],
                    ),
                )
        primary, secondary, _ = scenario(index, seed)
        for records, name, source in (
            (primary, "identity-export.json", "Orchid identity collector"),
            (secondary, "security-observations.json", "Orchid analyst telemetry"),
        ):
            item = vault.import_file(
                case_id,
                username,
                io.BytesIO(encoded(records)),
                name,
                "json",
                source,
                db.utc(BASE + timedelta(days=index)),
                0,
                0,
            )
            with db.transaction() as connection:
                vault.verify(connection, item, username)
        if index == 2:
            with TemporaryDirectory(dir=db.DATA) as temporary:
                path = Path(temporary) / "orchid-offline.pcap"
                pcap(path)
                with path.open("rb") as stream:
                    item = vault.import_file(
                        case_id,
                        username,
                        stream,
                        path.name,
                        "pcap",
                        "Orchid offline capture",
                        db.utc(BASE + timedelta(days=index)),
                        0,
                        0,
                    )
            with db.transaction() as connection:
                vault.verify(connection, item, username)
        with db.transaction() as connection:
            analysis.analyze(connection, case_id, username, 300)
            db.add(
                connection,
                db.notes,
                case_id=case_id,
                event_id=None,
                actor=username,
                timestamp=db.utc(),
                body="Synthetic records only. Confirm rule findings against source and expected change records.",
            )


def main():
    cli = argparse.ArgumentParser(
        description="Create local accounts and fictional investigation data"
    )
    cli.add_argument("action", choices=["admin", "seed", "generate"])
    cli.add_argument("--username", default="demo-investigator")
    cli.add_argument("--seed", type=int, default=42)
    cli.add_argument("--output", type=Path, default=Path("../datasets/generated"))
    args = cli.parse_args()
    if args.action == "generate":
        generate(args.output, args.seed)
        return
    if args.action == "seed":
        if not os.environ.get("TTX_DATA_DIR"):
            raise SystemExit(
                "Set TTX_DATA_DIR to a dedicated demo directory or run scripts/start-demo.ps1."
            )
        try:
            settings.validate_demo_configuration()
        except ValueError as error:
            raise SystemExit(str(error)) from error
    password = os.environ.get("TTX_SETUP_PASSWORD") or getpass.getpass(
        "Local account password (12+ characters): "
    )
    payload = schemas.UserCreate(
        username=args.username, password=password, role="administrator"
    )
    db.initialize()
    username = payload.username.lower()
    if args.action == "seed":
        seed_demo(username, password, args.seed)
        print(f"Synthetic cases ready for {username}")
    else:
        with db.transaction() as connection:
            if db.one(connection, db.users, db.users.c.username == username):
                raise SystemExit("Account already exists.")
            security.create_user(connection, username, password, "administrator")
        print(f"Local administrator created: {username}")


if __name__ == "__main__":
    main()
