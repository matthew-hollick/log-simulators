"""Cisco FTD (Firepower Threat Defense) security event syslog simulator.

Generates FTD 6.3+ key/value security event syslog in the style of:
  %FTD-6-430002: EventPriority: Low, DeviceUUID: ..., ...
  %FTD-6-430003: ... ConnectionDuration: 0, ...
  %FTD-1-430001: ... Classification: ..., Message: ..., SigID: ...
  %FTD-5-430004: ... FileAction: ..., FileType: ...
  %FTD-4-430005: ... Disposition: Malware, ...

These are the security event message IDs introduced in FTD 6.3:
  430001  intrusion event
  430002  connection event at beginning of connection
  430003  connection event at end of connection
  430004  file event
  430005  file malware event

Flags:
  --syslog-header  prefix '<PRI>Mmm dd HH:MM:SS host : ' (facility local4)

Scenarios:
  ips-flood  recurring windows of intrusion events (430001) from one
             external host to one inside host
"""

from __future__ import annotations

import argparse
import random
from dataclasses import dataclass
from datetime import datetime, timezone

from log_simulators.core import (
    BurstSchedule,
    EventFn,
    RunConfig,
    base_parser,
    config_from_args,
    internal_ips,
    lognormal_int,
    make_faker,
    pick,
    pri,
    public_ips,
    rfc3164_ts,
    run,
    usernames,
    zipf_weights,
)

HOSTNAME = "ftd-edge-01"
SYSLOG_FACILITY = 20  # local4

MAX_OPEN_CONNS = 400

EVENT_IDS = {
    "conn_start": "430002",
    "conn_end": "430003",
    "intrusion": "430001",
    "file": "430004",
    "malware": "430005",
}

PRIORITIES = ["Low", "Medium", "High"]
PRIORITY_WEIGHTS = [70.0, 20.0, 10.0]

ACTIONS = ["Allow", "Block", "Block with reset"]
ACTION_WEIGHTS = [70.0, 20.0, 10.0]

PROTOCOLS = ["tcp", "udp", "icmp"]
PROTOCOL_WEIGHTS = [65.0, 25.0, 10.0]

TCP_DST_PORTS = [443, 80, 22, 25, 993, 5432, 3389, 5900]
TCP_DST_WEIGHTS = [55.0, 20.0, 8.0, 4.0, 4.0, 3.0, 4.0, 2.0]
UDP_DST_PORTS = [53, 123, 500, 4500, 161]
UDP_DST_WEIGHTS = [70.0, 12.0, 8.0, 5.0, 5.0]

INGRESS_IFACES = ["inside", "Inside-Lab", "Inside-Work"]
EGRESS_IFACES = ["outside", "Outside-ISP", "DMZ"]
INGRESS_ZONES = ["inside", "Inside", "Inside_Users"]
EGRESS_ZONES = ["outside", "outside", "Outside"]
VRFS = ["Global"]

AC_POLICIES = [
    "Default Allow All Traffic",
    "Lab_ACP",
    "IZ1235WH02_Access_Control",
    "Corp_ACP",
]
AC_RULES = [
    "Allow_Outbound",
    "Allow-DNS",
    "Allow MDM - Out to DMZ",
    "Deny High Risk Apps",
    "Block-Countries",
    "Lab-Outside",
]
PREFILTERS = [
    "Default Prefilter Policy",
    "Default Prefilter",
    "IZ1235WH02_Prefilter",
]
NAP_POLICIES = [
    "Balanced Security and Connectivity",
    "No Rules Active",
    "Default-Policy",
]

APP_PAIRS = [
    ("SSL client", "HTTPS"),
    ("DNS", "DNS"),
    ("HTTP client", "HTTP"),
    ("ICMP client", "ICMP"),
    ("CLDAP client", "CLDAP"),
    ("Unknown", "TCP"),
]
APP_PAIR_WEIGHTS = [35.0, 20.0, 15.0, 12.0, 8.0, 10.0]

FILE_TYPES = ["PDF", "EXE", "ZIP", "DOCX", "JAR", "APK"]
FILE_NAMES = ["report.pdf", "invoice.docx", "setup.exe", "archive.zip", "app.jar"]
FILE_ACTIONS = ["Block", "Allow", "Malware Cloud Lookup", "Store"]
FILE_DIRECTIONS = ["Download", "Upload"]

MALWARE_NAMES = ["Trojan.Agent", "Generic.Malware", "Cryptolocker"]
DISPOSITIONS = ["Malware", "Whitelisted"]

CLASSIFICATIONS = [
    "Potential Corporate Policy Violation",
    "Attempted Administrator Privilege Gain",
    "Web Application Attack",
    "Network Scan",
]
INTRUSION_MESSAGES = [
    "GNU Bash Environment Variable Command Injection",
    "Possible SQL Injection",
    "SMBv1 Remote Code Execution",
    "DNS Tunneling Detected",
]

ICMP_TYPES = {8: "Echo Request", 0: "Echo Reply", 3: "Destination Unreachable"}
ICMP_CODES = {0: "No Code", 1: "Host Unreachable", 3: "Port Unreachable"}


@dataclass
class Conn:
    proto: str
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    ingress: str
    egress: str
    in_zone: str
    out_zone: str
    in_vrf: str
    out_vrf: str
    acp: str
    rule: str
    action: str
    user: str
    client: str
    app: str
    start: datetime
    conn_id: int
    init_pkts: int
    resp_pkts: int
    init_bytes: int
    resp_bytes: int


def _iso_z(ts: datetime) -> str:
    return ts.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _render_pairs(fields: list[tuple[str, object | None]]) -> str:
    return ", ".join(f"{k}: {v}" for k, v in fields if v is not None)


def _dst_port(rng: random.Random, proto: str) -> int:
    if proto == "icmp":
        return 0
    if proto == "udp":
        return pick(rng, UDP_DST_PORTS, UDP_DST_WEIGHTS)
    return pick(rng, TCP_DST_PORTS, TCP_DST_WEIGHTS)


def _src_port(rng: random.Random, proto: str) -> int:
    if proto == "icmp":
        return 8  # echo request
    return rng.randint(1024, 65535)


def _icmp_type_str(src_port: int) -> str | None:
    return ICMP_TYPES.get(src_port)


def _icmp_code_str(dst_port: int) -> str | None:
    return ICMP_CODES.get(dst_port)


def _app_pair(rng: random.Random, dst_port: int) -> tuple[str, str]:
    port_app = {
        53: ("DNS", "DNS"),
        80: ("HTTP client", "HTTP"),
        443: ("SSL client", "HTTPS"),
    }
    if dst_port in port_app:
        return port_app[dst_port]
    return pick(rng, APP_PAIRS, APP_PAIR_WEIGHTS)


def build_event_fn(cfg: RunConfig, args: argparse.Namespace) -> EventFn:
    rng = cfg.content_rng()
    fk = make_faker(cfg.seed)
    inside = internal_ips(rng, 24, prefix="10.0") + [
        f"192.168.1.{octet}" for octet in rng.sample(range(2, 250), 12)
    ]
    inside_weights = zipf_weights(len(inside), s=0.9)
    outside = public_ips(fk, 120)
    outside_weights = zipf_weights(len(outside), s=0.8)
    users = ["No Authentication Required", "Unknown", *usernames(fk, 15)]
    user_weights = zipf_weights(len(users))

    device_uuid = str(fk.uuid4())
    instance_id = 1
    acp = rng.choice(AC_POLICIES)
    prefilter = rng.choice(PREFILTERS)
    nap = rng.choice(NAP_POLICIES)

    next_conn_id = rng.randint(1, 500_000)
    open_conns: dict[int, Conn] = {}

    ips_flood = BurstSchedule(period=600, length=45) if args.scenario == "ips-flood" else None
    attacker_ip = pick(rng, outside, outside_weights)
    attack_target = rng.choice(inside)

    def _conn_fields(conn: Conn) -> list[tuple[str, object | None]]:
        return [
            ("EventPriority", pick(rng, PRIORITIES, PRIORITY_WEIGHTS)),
            ("DeviceUUID", device_uuid),
            ("InstanceID", instance_id),
            ("FirstPacketSecond", _iso_z(conn.start)),
            ("ConnectionID", conn.conn_id),
            ("AccessControlRuleAction", conn.action),
            ("AccessControlRuleReason", "IP Block" if conn.action != "Allow" else None),
            ("SrcIP", conn.src_ip),
            ("DstIP", conn.dst_ip),
            ("SrcPort", conn.src_port),
            ("DstPort", conn.dst_port),
            ("Protocol", conn.proto),
            ("IngressInterface", conn.ingress),
            ("EgressInterface", conn.egress),
            ("IngressZone", conn.in_zone),
            ("EgressZone", conn.out_zone),
            ("IngressVRF", conn.in_vrf),
            ("EgressVRF", conn.out_vrf),
            ("ACPolicy", conn.acp),
            ("AccessControlRuleName", conn.rule),
            ("Prefilter Policy", prefilter),
            ("User", conn.user),
            ("Client", conn.client),
            ("ApplicationProtocol", conn.app),
            ("ICMPType", _icmp_type_str(conn.src_port) if conn.proto == "icmp" else None),
            ("ICMPCode", _icmp_code_str(conn.dst_port) if conn.proto == "icmp" else None),
            ("InitiatorPackets", conn.init_pkts),
            ("ResponderPackets", conn.resp_pkts),
            ("InitiatorBytes", conn.init_bytes),
            ("ResponderBytes", conn.resp_bytes),
            ("NAPPolicy", nap),
        ]

    def new_conn(ts: datetime) -> Conn:
        nonlocal next_conn_id
        proto = pick(rng, PROTOCOLS, PROTOCOL_WEIGHTS)
        dst_port = _dst_port(rng, proto)
        src_port = _src_port(rng, proto)
        if rng.random() < 0.70:
            src_ip = pick(rng, inside, inside_weights)
            dst_ip = pick(rng, outside, outside_weights)
            ingress = rng.choice(INGRESS_IFACES)
            egress = rng.choice(EGRESS_IFACES)
            in_zone = rng.choice(INGRESS_ZONES)
            out_zone = rng.choice(EGRESS_ZONES)
        else:
            src_ip = pick(rng, outside, outside_weights)
            dst_ip = pick(rng, inside, inside_weights)
            ingress = rng.choice(EGRESS_IFACES)
            egress = rng.choice(INGRESS_IFACES)
            in_zone = rng.choice(EGRESS_ZONES)
            out_zone = rng.choice(INGRESS_ZONES)
        client, app = _app_pair(rng, dst_port)
        action = pick(rng, ACTIONS, ACTION_WEIGHTS)
        user = pick(rng, users, user_weights)
        rule = rng.choice(AC_RULES)
        conn = Conn(
            proto=proto,
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=src_port,
            dst_port=dst_port,
            ingress=ingress,
            egress=egress,
            in_zone=in_zone,
            out_zone=out_zone,
            in_vrf=rng.choice(VRFS),
            out_vrf=rng.choice(VRFS),
            acp=acp,
            rule=rule,
            action=action,
            user=user,
            client=client,
            app=app,
            start=ts,
            conn_id=next_conn_id,
            init_pkts=0,
            resp_pkts=0,
            init_bytes=0,
            resp_bytes=0,
        )
        open_conns[conn.conn_id] = conn
        next_conn_id += 1
        return conn

    def conn_start(ts: datetime) -> str:
        conn = new_conn(ts)
        return f"%FTD-6-{EVENT_IDS['conn_start']}: {_render_pairs(_conn_fields(conn))}"

    def conn_end(ts: datetime, forced: bool = False) -> str:
        if not open_conns:
            return conn_start(ts)
        cid = next(iter(open_conns)) if forced else rng.choice(list(open_conns))
        conn = open_conns.pop(cid)
        duration = int((ts - conn.start).total_seconds())
        if conn.proto == "icmp":
            conn.init_pkts = 1
            conn.resp_pkts = rng.choice([0, 1])
            conn.init_bytes = 74
            conn.resp_bytes = 74 if conn.resp_pkts else 0
        else:
            conn.init_pkts = max(0, int(rng.lognormvariate(2.0, 1.2)))
            conn.resp_pkts = max(0, int(rng.lognormvariate(2.0, 1.2)))
            conn.init_bytes = lognormal_int(rng, 4000, 1.2, lo=64, hi=1_000_000_000)
            conn.resp_bytes = lognormal_int(rng, 200_000, 1.2, lo=0, hi=10_000_000_000)

        ordered: list[tuple[str, object | None]] = []
        for k, v in _conn_fields(conn):
            if k == "NAPPolicy":
                ordered.append(("ConnectionDuration", duration))
            ordered.append((k, v))
        return f"%FTD-6-{EVENT_IDS['conn_end']}: {_render_pairs(ordered)}"

    def intrusion(ts: datetime, src_ip: str | None = None, dst_ip: str | None = None) -> str:
        proto = pick(rng, PROTOCOLS, PROTOCOL_WEIGHTS)
        if src_ip is None:
            src_ip = pick(rng, outside, outside_weights)
        if dst_ip is None:
            dst_ip = pick(rng, inside, inside_weights)
        dst_port = _dst_port(rng, proto)
        src_port = _src_port(rng, proto)
        client, app = _app_pair(rng, dst_port)
        action = pick(rng, ACTIONS, ACTION_WEIGHTS)
        conn_id = rng.randint(1, 100_000)
        sig_id = rng.randint(1, 30_000)
        fields: list[tuple[str, object | None]] = [
            ("EventPriority", pick(rng, PRIORITIES, PRIORITY_WEIGHTS)),
            ("DeviceUUID", device_uuid),
            ("InstanceID", instance_id),
            ("FirstPacketSecond", _iso_z(ts)),
            ("ConnectionID", conn_id),
            ("AccessControlRuleAction", action),
            ("AccessControlRuleReason", "IP Block" if action != "Allow" else None),
            ("SrcIP", src_ip),
            ("DstIP", dst_ip),
            ("SrcPort", src_port),
            ("DstPort", dst_port),
            ("Protocol", proto),
            ("IngressInterface", rng.choice(INGRESS_IFACES)),
            ("EgressInterface", rng.choice(EGRESS_IFACES)),
            ("IngressZone", rng.choice(INGRESS_ZONES)),
            ("EgressZone", rng.choice(EGRESS_ZONES)),
            ("ACPolicy", acp),
            ("AccessControlRuleName", rng.choice(AC_RULES)),
            ("Client", client),
            ("ApplicationProtocol", app),
            ("Classification", rng.choice(CLASSIFICATIONS)),
            ("Priority", "High"),
            ("Message", rng.choice(INTRUSION_MESSAGES)),
            ("SigID", sig_id),
            ("Revision", rng.randint(1, 10)),
            ("Generator ID", rng.randint(1, 100)),
            ("NAPPolicy", nap),
            ("InlineResult", "Would have dropped" if action == "Block" else None),
        ]
        if proto == "icmp":
            fields.extend(
                [
                    ("ICMPType", _icmp_type_str(src_port)),
                    ("ICMPCode", _icmp_code_str(dst_port)),
                ]
            )
        return f"%FTD-1-{EVENT_IDS['intrusion']}: {_render_pairs(fields)}"

    def file_event(ts: datetime, malware: bool = False) -> str:
        proto = "tcp" if rng.random() < 0.8 else "udp"
        src_ip = pick(rng, inside, inside_weights)
        dst_ip = pick(rng, outside, outside_weights)
        dst_port = 80 if proto == "tcp" and rng.random() < 0.5 else 443
        src_port = rng.randint(1024, 65535)
        conn_id = rng.randint(1, 100_000)
        file_type = rng.choice(FILE_TYPES)
        file_name = rng.choice(FILE_NAMES)
        file_size = lognormal_int(rng, 5_000_000, 1.4, lo=1024, hi=500_000_000)
        sha = "".join(rng.choices("0123456789abcdef", k=64))
        fields: list[tuple[str, object | None]] = [
            ("EventPriority", pick(rng, PRIORITIES, PRIORITY_WEIGHTS)),
            ("DeviceUUID", device_uuid),
            ("InstanceID", instance_id),
            ("FirstPacketSecond", _iso_z(ts)),
            ("ConnectionID", conn_id),
            ("AccessControlRuleAction", "Block" if malware else "Allow"),
            ("SrcIP", src_ip),
            ("DstIP", dst_ip),
            ("SrcPort", src_port),
            ("DstPort", dst_port),
            ("Protocol", proto),
            ("ApplicationProtocol", "HTTPS" if dst_port == 443 else "HTTP"),
            ("FileAction", "Block" if malware else rng.choice(FILE_ACTIONS)),
            ("FileType", file_type),
            ("FileName", file_name),
            ("FileSize", file_size),
            ("FileDirection", rng.choice(FILE_DIRECTIONS)),
            ("Sha256", sha),
        ]
        if malware:
            fields.extend(
                [
                    ("Disposition", rng.choice(DISPOSITIONS)),
                    ("MalwareName", rng.choice(MALWARE_NAMES)),
                ]
            )
        fields.append(("NAPPolicy", nap))
        msg_id = EVENT_IDS["malware"] if malware else EVENT_IDS["file"]
        sev = 4 if malware else 5
        return f"%FTD-{sev}-{msg_id}: {_render_pairs(fields)}"

    def envelope(ts: datetime, line: str) -> str:
        if not args.syslog_header:
            return line
        severity = int(line[5])
        return f"<{pri(SYSLOG_FACILITY, severity)}>{rfc3164_ts(ts)} {HOSTNAME} : {line}"

    def make_event(ts: datetime, seq: int) -> str:
        if (
            ips_flood is not None
            and ips_flood.active(ts)
            and rng.random() < 0.4 + 0.5 * ips_flood.intensity(ts)
        ):
            return envelope(ts, intrusion(ts, src_ip=attacker_ip, dst_ip=attack_target))
        if len(open_conns) >= MAX_OPEN_CONNS:
            return envelope(ts, conn_end(ts, forced=True))
        roll = rng.random()
        if roll < 0.45 or not open_conns:
            return envelope(ts, conn_start(ts))
        if roll < 0.80:
            return envelope(ts, conn_end(ts))
        if roll < 0.90:
            return envelope(ts, intrusion(ts))
        if roll < 0.95:
            return envelope(ts, file_event(ts, malware=False))
        return envelope(ts, file_event(ts, malware=True))

    return make_event


def main(argv: list[str] | None = None) -> int:
    parser = base_parser(
        "logsim-ftd",
        "Generate realistic Cisco FTD (Firepower Threat Defense) security event syslog.",
        default_rate=10.0,
    )
    parser.add_argument(
        "--syslog-header",
        action="store_true",
        help="prefix each line with a syslog header '<PRI>Mmm dd HH:MM:SS host : '",
    )
    parser.add_argument(
        "--scenario",
        choices=["none", "ips-flood"],
        default="none",
        help="inject recurring anomaly windows (default: none)",
    )
    args = parser.parse_args(argv)
    cfg = config_from_args(args)
    run(cfg, build_event_fn(cfg, args))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
