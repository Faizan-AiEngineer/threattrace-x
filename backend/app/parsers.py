import csv
import ipaddress
import json
import math
import re
import struct
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta, timezone

from scapy.config import conf
from scapy.error import Scapy_Exception
from scapy.layers.dns import DNSQR
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import Ether  # noqa: F401 - registers Ethernet capture decoding
from scapy.utils import PcapReader

conf.use_pcap = False
VERSION = "1.0"
MAX_RECORDS = 100_000
MAX_LINE = 262_144
FORMATS = (
    "json",
    "jsonl",
    "csv",
    "syslog",
    "auth",
    "access",
    "zeek",
    "pcap",
    "windows",
)
ACCESS = re.compile(r'^(\S+) \S+ (\S+) \[([^\]]+)\] "(\S+) (.*?) \S+" (\d{3}) (\d+|-)')
AUTH = re.compile(
    r"(Failed password for (?:invalid user )?|Accepted \S+ for )(\S+) from (\S+) port (\d+)"
)
SYSLOG = re.compile(
    r"^(?:<\d+>(?:1 )?)?(\d{4}-\S+|[A-Z][a-z]{2}\s+\d+\s+\d\d:\d\d:\d\d) (\S+) (.*)$"
)


@dataclass
class ParseResult:
    events: list
    stats: dict


def timestamp(value, offset=0, correction=0):
    if value is None or value == "" or value == "-":
        return None, None, "missing"
    raw = str(value)
    try:
        if isinstance(value, (float, int)) or re.fullmatch(r"\d{9,12}(?:\.\d+)?", raw):
            seconds = float(value)
            parsed = datetime.fromtimestamp(seconds, UTC)
        else:
            parsed = datetime.fromisoformat(raw)
        quality = "explicit"
        if parsed.tzinfo is None:
            quality = "assumed"
            parsed = parsed.replace(tzinfo=timezone(timedelta(minutes=offset)))
        return (
            raw,
            (parsed.astimezone(UTC) + timedelta(seconds=correction)).isoformat(
                timespec="microseconds"
            ),
            quality,
        )
    except (ValueError, OverflowError, OSError):
        return raw, None, "uncertain"


def json_record(line):
    def reject(value):
        raise ValueError(f"Nonstandard JSON number {value}")

    def bounded_float(value):
        result = float(value)
        if not math.isfinite(result):
            raise ValueError("JSON number exceeds the supported range")
        return result

    result = json.loads(line, parse_constant=reject, parse_float=bounded_float)
    # Confirm that decoded string values can be stored and reported as UTF-8.
    json.dumps(result, ensure_ascii=False).encode("utf-8")
    return result


def rows(path, kind):
    if kind == "pcap":
        with path.open("rb") as stream:
            if stream.read(4) not in (
                b"\xd4\xc3\xb2\xa1",
                b"\xa1\xb2\xc3\xd4",
                b"\x4d\x3c\xb2\xa1",
                b"\xa1\xb2\x3c\x4d",
                b"\x0a\x0d\x0d\x0a",
            ):
                raise ValueError("Expected PCAP or PCAPNG capture magic")
        with PcapReader(str(path)) as packets:
            for number, packet in enumerate(packets, 1):
                ip = packet.getlayer(IP) or packet.getlayer(IPv6)
                transport = packet.getlayer(TCP) or packet.getlayer(UDP)
                question = packet.getlayer(DNSQR)
                yield (
                    f"packet:{number}",
                    {
                        "timestamp": str(packet.time),
                        "category": "network",
                        "action": "packet",
                        "source_ip": ip.src if ip else None,
                        "destination_ip": ip.dst if ip else None,
                        "source_port": transport.sport if transport else None,
                        "destination_port": transport.dport if transport else None,
                        "protocol": transport.name if transport else packet.name,
                        "domain": question.qname.decode("ascii", "replace").rstrip(".")
                        if question
                        else None,
                        "bytes": getattr(packet, "wirelen", None) or len(packet),
                    },
                )
        return
    with path.open(encoding="utf-8-sig", errors="strict", newline="") as stream:
        if kind in {"json", "windows"}:
            data = json_record(stream.read())
            if isinstance(data, dict):
                data = data.get("events", [data])
            if not isinstance(data, list):
                raise ValueError("Expected a JSON array, event object, or events array")
            yield from ((f"record:{i}", row) for i, row in enumerate(data, 1))
            return
        if kind == "csv":
            reader = csv.DictReader(stream, strict=True)
            if not reader.fieldnames or len(set(reader.fieldnames)) != len(
                reader.fieldnames
            ):
                raise ValueError("CSV header is missing or ambiguous")
            for row in reader:
                yield f"line:{reader.line_num}", row if None not in row else None
            return
        headers = []
        separator = "\t"
        for number, line in enumerate(stream, 1):
            line = line.rstrip("\r\n")
            if not line:
                continue
            anchor = f"line:{number}"
            if len(line) > MAX_LINE:
                yield anchor, None
                continue
            if kind == "jsonl":
                try:
                    yield anchor, json_record(line)
                except (ValueError, RecursionError):
                    yield anchor, None
            elif kind == "zeek":
                if line.startswith("#separator "):
                    separator = (
                        line.split(" ", 1)[1].encode("ascii").decode("unicode_escape")
                    )
                    if not separator or len(separator) > 8:
                        raise ValueError("Invalid Zeek separator")
                elif line.startswith("#fields"):
                    headers = line.split(separator)[1:]
                elif not line.startswith("#"):
                    fields = line.split(separator)
                    yield (
                        anchor,
                        dict(zip(headers, fields))
                        if headers and len(fields) == len(headers)
                        else None,
                    )
            elif kind == "access":
                match = ACCESS.match(line)
                if match:
                    ip, user, stamp, method, target, code, size = match.groups()
                    try:
                        stamp = datetime.strptime(
                            stamp, "%d/%b/%Y:%H:%M:%S %z"
                        ).isoformat()
                    except ValueError:
                        pass  # Preserve the raw timestamp and let normalization mark it uncertain.
                    yield (
                        anchor,
                        {
                            "timestamp": stamp,
                            "source_ip": ip,
                            "username": user,
                            "category": "web",
                            "action": method,
                            "url": target,
                            "outcome": code,
                            "bytes": size,
                            "raw": line,
                        },
                    )
                else:
                    yield anchor, None
            else:
                match = SYSLOG.match(line)
                auth = AUTH.search(line)
                if not match and not auth:
                    yield anchor, None
                    continue
                stamp, host, _ = match.groups() if match else (None, None, line)
                row = {
                    "timestamp": stamp,
                    "hostname": host,
                    "category": "system",
                    "action": "syslog",
                    "raw": line,
                }
                if auth:
                    action, user, ip, port = auth.groups()
                    row.update(
                        username=user,
                        source_ip=ip,
                        source_port=port,
                        category="authentication",
                        action="login",
                        outcome="failure" if action.startswith("Failed") else "success",
                    )
                yield anchor, row if kind != "auth" or auth else None


ALIASES = {
    "source_ip": ("src_ip", "id.orig_h", "IpAddress"),
    "destination_ip": ("dst_ip", "id.resp_h"),
    "source_port": ("src_port", "id.orig_p"),
    "destination_port": ("dst_port", "id.resp_p"),
    "hostname": ("host", "Computer"),
    "username": ("user", "TargetUserName"),
    "process_name": ("process", "NewProcessName"),
    "process_id": ("pid", "NewProcessId"),
    "file_path": ("path", "ObjectName"),
    "file_hash": ("sha256", "hash"),
    "protocol": ("proto",),
    "domain": ("query",),
    "url": (),
    "bytes": ("orig_bytes", "size"),
    "outcome": ("result",),
}
WINDOWS = {
    "4624": ("authentication", "login", "success"),
    "4625": ("authentication", "login", "failure"),
    "4728": ("account", "privilege_change", None),
    "4732": ("account", "privilege_change", None),
    "4688": ("process", "process_start", None),
    "4663": ("file", "file_access", None),
    "7045": ("service", "service_change", None),
    "4672": ("account", "admin_activity", None),
}


def value(row, *keys):
    for key in keys:
        val = row.get(key)
        if isinstance(val, (str, int, float)) and val != "" and val != "-":
            return val
    return None


def number(item, maximum):
    try:
        result = int(str(item))
        return result if 0 <= result <= maximum else None
    except (ValueError, OverflowError):
        return None


def normalize(row, kind, anchor, zone, correction):
    if not isinstance(row, dict) or not row:
        raise ValueError("Expected a nonempty record object")
    recognized = (
        "timestamp",
        "time",
        "ts",
        "TimeCreated",
        "datetime",
        "category",
        "action",
        "EventID",
    )
    if not any(key in row for key in recognized):
        raise ValueError("No supported event fields")
    original, corrected, quality = timestamp(
        value(row, "timestamp", "time", "ts", "TimeCreated", "datetime"),
        zone,
        correction,
    )
    category, action, outcome = WINDOWS.get(
        str(row.get("EventID")),
        ("network" if kind in {"zeek", "pcap"} else "other", "observed", None),
    )
    normalized = {key: value(row, key, *aliases) for key, aliases in ALIASES.items()}
    for key, maximum in (
        ("source_port", 65535),
        ("destination_port", 65535),
        ("bytes", 2**63 - 1),
    ):
        normalized[key] = number(normalized[key], maximum)
    for key in ("source_ip", "destination_ip"):
        if normalized[key] is not None:
            try:
                normalized[key] = str(ipaddress.ip_address(str(normalized[key])))
            except ValueError:
                normalized[key] = None
    for key, item in normalized.items():
        if item is not None and key not in {"source_port", "destination_port", "bytes"}:
            normalized[key] = str(item)[:4096]
    for key in ("hostname", "username", "file_hash", "domain", "outcome"):
        if normalized[key]:
            normalized[key] = normalized[key].casefold()
    normalized["outcome"] = normalized["outcome"] or outcome
    severity = str(row.get("severity", "info")).lower()
    return dict(
        normalized,
        original_timestamp=original,
        timestamp=corrected,
        time_quality=quality,
        source_type=kind,
        category=str(value(row, "category") or category).lower()[:64],
        action=str(value(row, "action") or action).lower()[:128],
        severity=severity
        if severity in {"info", "low", "medium", "high", "critical"}
        else "info",
        source_ref=anchor,
        metadata=row,
        clock_offset=correction,
    )


def parse(path, kind, timezone_offset=0, clock_offset=0):
    events, errors = [], []
    count = uncertain = 0
    truncated = False
    try:
        for index, (anchor, row) in enumerate(rows(path, kind), 1):
            if index > MAX_RECORDS:
                truncated = True
                break
            count += 1
            try:
                event = normalize(row, kind, anchor, timezone_offset, clock_offset)
                events.append(event)
                uncertain += event["time_quality"] in {"missing", "uncertain"}
            except (ValueError, TypeError, RecursionError) as error:
                if len(errors) < 50:
                    errors.append({"source_ref": anchor, "reason": str(error)})
    except (
        UnicodeError,
        OSError,
        EOFError,
        ValueError,
        csv.Error,
        RecursionError,
        struct.error,
        Scapy_Exception,
    ) as error:
        return ParseResult(
            [],
            {
                "records": count,
                "parsed": 0,
                "malformed": count,
                "errors": [{"source_ref": "file", "reason": str(error)[:200]}],
                "failed": True,
            },
        )
    return ParseResult(
        events,
        {
            "records": count,
            "parsed": len(events),
            "malformed": count - len(events),
            "uncertain": uncertain,
            "errors": errors,
            "truncated": truncated,
            "failed": not events,
        },
    )
