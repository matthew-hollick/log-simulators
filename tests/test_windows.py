"""Tests for logsim-windows (Windows Security Event Log)."""

from __future__ import annotations

import json
import re

# stdlib ElementTree is safe here: we only parse XML this simulator just
# generated in-process (trusted input, no DTDs/external entities), and the
# project is stdlib+faker only by design.
import xml.etree.ElementTree as ET
from collections import Counter, defaultdict
from itertools import pairwise
from typing import ClassVar

from log_simulators.windows.cli import main

from .conftest import generate

XMLNS = "http://schemas.microsoft.com/win/2004/08/events/event"
NS = {"e": XMLNS}
PROVIDER_GUID = "{54849625-5478-4994-A5BA-3E3B0328C30D}"
ALLOWED_IDS = {4624, 4625, 4672, 4688, 4720, 4740}
SINGLE_LINE_RE = re.compile(
    r'^<Event xmlns="http://schemas\.microsoft\.com/win/2004/08/events/event">'
    r"<System>.+</System><EventData>.+</EventData></Event>$"
)
# Real events render FILETIME at 100-ns resolution: 7 fractional digits.
SYSTIME_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{7}Z$")
DOMAIN_SID_RE = re.compile(r"^S-1-5-21-\d+-\d+-\d+-\d+$")
GUID_RE = re.compile(r"^\{[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}\}$")
NULL_GUID = "{00000000-0000-0000-0000-000000000000}"
HEX_PID_RE = re.compile(r"^0x[0-9a-f]+$")

# Version-2 manifest fields that v0/v1 events lack (4624 and 4688).
V2_4624_FIELDS = {
    "LogonGuid",
    "TransmittedServices",
    "LmPackageName",
    "KeyLength",
    "ProcessId",
    "ImpersonationLevel",
    "RestrictedAdminMode",
    "TargetOutboundUserName",
    "TargetOutboundDomainName",
    "VirtualAccount",
    "TargetLinkedLogonId",
    "ElevatedToken",
}
V2_4688_FIELDS = {
    "TargetUserSid",
    "TargetUserName",
    "TargetDomainName",
    "TargetLogonId",
    "MandatoryLabel",
}


def _parse(line: str) -> ET.Element:
    root = ET.fromstring(line)
    assert root.tag == f"{{{XMLNS}}}Event"
    return root


def _event_id(root: ET.Element) -> int:
    return int(root.findtext("e:System/e:EventID", namespaces=NS) or 0)


def _event_data(root: ET.Element) -> dict[str, str]:
    return {d.get("Name") or "": d.text or "" for d in root.findall("e:EventData/e:Data", NS)}


def _events_from_pretty(lines: list[str]) -> list[str]:
    events: list[str] = []
    buf: list[str] = []
    for line in lines:
        buf.append(line)
        if line == "</Event>":
            events.append("\n".join(buf))
            buf = []
    assert not buf, "trailing partial event"
    return events


def _records(count: int = 400, extra: list[str] | None = None, **kw: object) -> list[dict]:
    lines = generate(main, count=count, extra=["--format", "ndjson", *(extra or [])], **kw)  # type: ignore[arg-type]
    return [json.loads(line) for line in lines]


def _elastic_records(count: int = 400, extra: list[str] | None = None, **kw: object) -> list[dict]:
    lines = generate(main, count=count, extra=["--format", "elastic", *(extra or [])], **kw)  # type: ignore[arg-type]
    return [json.loads(line) for line in lines]


class TestXmlFormat:
    def test_every_line_is_a_valid_single_line_event(self) -> None:
        for line in generate(main, count=300):
            assert SINGLE_LINE_RE.match(line), line
            root = _parse(line)
            event_id = int(root.findtext("e:System/e:EventID", namespaces=NS) or 0)
            assert event_id in ALLOWED_IDS
            systime = root.find("e:System/e:TimeCreated", NS)
            assert systime is not None and SYSTIME_RE.match(systime.get("SystemTime", ""))
            provider = root.find("e:System/e:Provider", NS)
            assert provider is not None
            assert provider.get("Name") == "Microsoft-Windows-Security-Auditing"
            assert root.findtext("e:System/e:Channel", namespaces=NS) == "Security"
            computer = root.findtext("e:System/e:Computer", namespaces=NS) or ""
            assert computer.endswith(".CORP.EXAMPLE.COM")
            assert root.findall("e:EventData/e:Data", NS), "EventData must not be empty"

    def test_record_ids_increase_per_computer_not_globally(self) -> None:
        # Each machine keeps its own Security log: EventRecordID must be
        # strictly increasing (and gapless) per Computer, while the merged
        # stream must NOT look like one shared global counter.
        by_computer: defaultdict[str, list[int]] = defaultdict(list)
        merged: list[int] = []
        for line in generate(main, count=400):
            root = _parse(line)
            computer = root.findtext("e:System/e:Computer", namespaces=NS) or ""
            rid = int(root.findtext("e:System/e:EventRecordID", namespaces=NS) or 0)
            by_computer[computer].append(rid)
            merged.append(rid)
        assert len(by_computer) >= 3, "expected events from several computers"
        for computer, ids in by_computer.items():
            assert all(b == a + 1 for a, b in pairwise(ids)), computer
        bases = {ids[0] for ids in by_computer.values()}
        assert len(bases) == len(by_computer), "per-computer counter bases must be distinct"
        assert not all(b > a for a, b in pairwise(merged)), "global gapless counter is unrealistic"

    def test_failed_logons_use_failure_keywords(self) -> None:
        seen = set()
        for line in generate(main, count=600):
            root = _parse(line)
            event_id = int(root.findtext("e:System/e:EventID", namespaces=NS) or 0)
            keywords = root.findtext("e:System/e:Keywords", namespaces=NS)
            expected = "0x8010000000000000" if event_id == 4625 else "0x8020000000000000"
            assert keywords == expected
            seen.add(event_id)
        assert 4625 in seen

    def test_pretty_emits_parseable_multiline_events(self) -> None:
        lines = generate(main, count=60, extra=["--pretty"])
        events = _events_from_pretty(lines)
        assert len(events) == 60
        for event in events:
            assert "\n" in event
            _parse(event)

    def test_event_mix_is_logon_heavy(self) -> None:
        counts: Counter[int] = Counter()
        for line in generate(main, count=800):
            root = _parse(line)
            counts[int(root.findtext("e:System/e:EventID", namespaces=NS) or 0)] += 1
        assert counts[4624] > 0.4 * 800
        assert counts[4688] > 0.15 * 800
        assert counts[4672] > 0  # paired follow-ups to admin logons


class TestManifestV2:
    def test_4624_emits_full_version2_field_set(self) -> None:
        seen = 0
        for line in generate(main, count=600):
            root = _parse(line)
            if _event_id(root) != 4624:
                continue
            seen += 1
            assert root.findtext("e:System/e:Version", namespaces=NS) == "2"
            data = _event_data(root)
            assert data.keys() >= V2_4624_FIELDS, V2_4624_FIELDS - data.keys()
            assert GUID_RE.match(data["LogonGuid"])
            assert data["TransmittedServices"] == "-"
            assert data["ImpersonationLevel"] == "%%1833"
            assert data["RestrictedAdminMode"] == "-"
            assert data["TargetOutboundUserName"] == "-"
            assert data["TargetOutboundDomainName"] == "-"
            assert data["VirtualAccount"] == "%%1843"
            assert data["TargetLinkedLogonId"] == "0x0"
            assert data["ElevatedToken"] in {"%%1842", "%%1843"}
            # correlations: LM/key length follow the auth package, LogonGuid
            # is real for Kerberos and the null GUID otherwise, ProcessId is
            # 0x0 exactly when ProcessName is '-' (network logons)
            if data["AuthenticationPackageName"] == "NTLM":
                assert data["LmPackageName"] == "NTLM V2"
                assert data["KeyLength"] == "128"
            else:
                assert data["LmPackageName"] == "-"
                assert data["KeyLength"] == "0"
            if data["AuthenticationPackageName"] == "Kerberos":
                assert data["LogonGuid"] != NULL_GUID
            else:
                assert data["LogonGuid"] == NULL_GUID
            assert HEX_PID_RE.match(data["ProcessId"])
            assert (data["ProcessId"] == "0x0") == (data["ProcessName"] == "-")
        assert seen > 100

    def test_4688_emits_version2_target_and_label_fields(self) -> None:
        seen = 0
        for line in generate(main, count=600):
            root = _parse(line)
            if _event_id(root) != 4688:
                continue
            seen += 1
            assert root.findtext("e:System/e:Version", namespaces=NS) == "2"
            data = _event_data(root)
            assert data.keys() >= V2_4688_FIELDS, V2_4688_FIELDS - data.keys()
            assert data["TargetUserSid"] == "S-1-0-0"
            assert data["TargetUserName"] == "-"
            assert data["TargetDomainName"] == "-"
            assert data["TargetLogonId"] == "0x0"
            assert data["MandatoryLabel"] in {"S-1-16-8192", "S-1-16-12288"}
        assert seen > 50

    def test_elevated_token_and_mandatory_label_correlate_with_admins(self) -> None:
        records = _records(count=800)
        # admins are exactly the users who earn paired 4672 events
        admins = {r["subject_user"] for r in records if r["event_id"] == 4672}
        assert admins
        logons = [r for r in records if r["event_id"] == 4624]
        # the final record may be an admin 4624 whose paired 4672 was cut off
        for rec in logons[:-1]:
            expected = "%%1842" if rec["target_user"] in admins else "%%1843"
            assert rec["elevated_token"] == expected, rec["target_user"]
        assert any(r["elevated_token"] == "%%1842" for r in logons)
        procs = [r for r in records if r["event_id"] == 4688]
        assert procs
        for rec in procs:
            if rec["subject_user"] in admins:
                assert rec["mandatory_label"] == "S-1-16-12288"
            else:
                assert rec["mandatory_label"] == "S-1-16-8192"
        assert any(r["mandatory_label"] == "S-1-16-12288" for r in procs)


class TestNdjsonFormat:
    def test_every_line_parses_with_required_keys(self) -> None:
        for rec in _records(count=300):
            assert {"@timestamp", "event_id", "computer", "record_id"} <= rec.keys()
            assert rec["event_id"] in ALLOWED_IDS
            assert rec["computer"].endswith(".CORP.EXAMPLE.COM")

    def test_4624_fields(self) -> None:
        logons = [r for r in _records(count=500) if r["event_id"] == 4624]
        assert logons
        for rec in logons:
            assert rec["logon_type"] in {2, 3, 5, 10}
            assert rec["target_user"]
            assert rec["auth_package"] in {"Kerberos", "NTLM", "Negotiate"}
            # 4624's ProcessId is the logon process, never a parent pid
            assert HEX_PID_RE.match(rec["process_id"])
            assert "parent_process_id" not in rec
            assert rec["elevated_token"] in {"%%1842", "%%1843"}
            assert GUID_RE.match(rec["logon_guid"])
            if rec["logon_type"] in {3, 10}:
                assert rec["source_ip"].startswith("10.0.")
                assert 1024 <= rec["source_port"] <= 65535


class TestElasticFormat:
    REQUIRED_ROOT: ClassVar[set[str]] = {"@timestamp", "event", "winlog"}
    REQUIRED_EVENT: ClassVar[set[str]] = {"code", "kind", "module", "outcome"}
    REQUIRED_WINLOG: ClassVar[set[str]] = {
        "api",
        "channel",
        "computer_name",
        "event_id",
        "provider_name",
        "provider_guid",
        "record_id",
        "time_created",
        "version",
        "event_data",
    }

    def _records(
        self, count: int = 400, extra: list[str] | None = None, **kw: object
    ) -> list[dict]:
        return _elastic_records(count=count, extra=extra, **kw)

    def test_valid_json_one_line_per_event(self) -> None:
        lines = generate(main, count=300, extra=["--format", "elastic"])
        assert len(lines) == 300
        for line in lines:
            assert "\n" not in line
            rec = json.loads(line)
            assert isinstance(rec, dict)

    def test_required_fields_and_types(self) -> None:
        for rec in self._records(count=300):
            assert rec.keys() >= self.REQUIRED_ROOT
            assert rec["event"].keys() >= self.REQUIRED_EVENT
            assert rec["winlog"].keys() >= self.REQUIRED_WINLOG
            assert isinstance(rec["@timestamp"], str)
            assert isinstance(rec["event"]["code"], str)
            assert isinstance(rec["winlog"]["event_id"], str)
            assert isinstance(rec["winlog"]["record_id"], str)
            assert isinstance(rec["winlog"]["version"], int)
            assert isinstance(rec["winlog"]["event_data"], dict)

    def test_constant_values(self) -> None:
        for rec in self._records(count=200):
            assert rec["event"]["kind"] == "event"
            assert rec["event"]["module"] == "system"
            assert rec["winlog"]["api"] == "wineventlog"
            assert rec["winlog"]["channel"] == "Security"
            assert rec["winlog"]["provider_name"] == "Microsoft-Windows-Security-Auditing"
            assert rec["winlog"]["provider_guid"] == PROVIDER_GUID

    def test_event_code_consistency_and_supported_ids(self) -> None:
        seen: set[str] = set()
        for rec in self._records(count=600):
            assert rec["event"]["code"] == rec["winlog"]["event_id"]
            assert rec["event"]["code"] in {"4624", "4625", "4672", "4688", "4720", "4740"}
            seen.add(rec["event"]["code"])
        assert seen == {"4624", "4625", "4672", "4688", "4720", "4740"}

    def test_outcomes(self) -> None:
        for rec in self._records(count=300):
            expected = "failure" if rec["event"]["code"] == "4625" else "success"
            assert rec["event"]["outcome"] == expected

    def test_keywords_are_human_readable_labels(self) -> None:
        for rec in self._records(count=300):
            keywords = rec["winlog"]["keywords"]
            assert keywords in [["Audit Success"], ["Audit Failure"]]
            if rec["event"]["code"] == "4625":
                assert keywords == ["Audit Failure"]
            else:
                assert keywords == ["Audit Success"]

    def test_process_metadata_shape(self) -> None:
        for rec in self._records(count=200):
            proc = rec["winlog"]["process"]
            assert isinstance(proc["pid"], int)
            assert isinstance(proc["thread"]["id"], int)
            assert 560 <= proc["pid"] <= 980
            assert 1000 <= proc["thread"]["id"] <= 9900

    def test_event_data_preserves_original_manifest_names(self) -> None:
        for rec in self._records(count=400):
            event_data = rec["winlog"]["event_data"]
            code = rec["event"]["code"]
            if code == "4624":
                assert "TargetUserName" in event_data
                assert "AuthenticationPackageName" in event_data
                assert "IpAddress" in event_data
                assert "ElevatedToken" in event_data
            elif code == "4625":
                assert "TargetUserName" in event_data
                assert "Status" in event_data
                assert "SubStatus" in event_data
                assert "IpAddress" in event_data
            elif code == "4672":
                assert "SubjectUserName" in event_data
                assert "PrivilegeList" in event_data
            elif code == "4688":
                assert "NewProcessName" in event_data
                assert "CommandLine" in event_data
                assert "ParentProcessName" in event_data
                assert "MandatoryLabel" in event_data
            elif code == "4720":
                assert "TargetUserName" in event_data
                assert "SamAccountName" in event_data
                assert "UserPrincipalName" in event_data
            elif code == "4740":
                assert "TargetUserName" in event_data
                assert "CallerComputerName" in event_data

    def test_flattened_ndjson_keys_not_at_root(self) -> None:
        for rec in self._records(count=200):
            assert "target_user" not in rec
            assert "source_ip" not in rec
            assert "computer" not in rec
            assert "event_id" not in rec

    def test_per_computer_record_ids(self) -> None:
        by_computer: defaultdict[str, list[int]] = defaultdict(list)
        merged: list[int] = []
        for rec in self._records(count=400):
            computer = rec["winlog"]["computer_name"]
            rid = int(rec["winlog"]["record_id"])
            by_computer[computer].append(rid)
            merged.append(rid)
        assert len(by_computer) >= 3
        for computer, ids in by_computer.items():
            assert all(b == a + 1 for a, b in pairwise(ids)), computer
        bases = {ids[0] for ids in by_computer.values()}
        assert len(bases) == len(by_computer)
        assert not all(b > a for a, b in pairwise(merged)), "global gapless counter is unrealistic"

    def test_timestamps_match(self) -> None:
        for rec in self._records(count=200):
            assert rec["@timestamp"] == rec["winlog"]["time_created"]
            # ISO-8601 UTC with millisecond precision
            assert re.match(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$", rec["@timestamp"])

    def test_brute_force_scenario(self) -> None:
        records = self._records(count=800, backfill="2h", extra=["--scenario", "brute-force"])
        failures = [r for r in records if r["event"]["code"] == "4625"]
        attacker_ip = Counter(
            r["winlog"]["event_data"].get("IpAddress", "-") for r in failures
        ).most_common(1)[0][0]
        flood = [r for r in failures if r["winlog"]["event_data"].get("IpAddress") == attacker_ip]
        assert len(flood) > 50
        assert len({r["winlog"]["event_data"]["TargetUserName"] for r in flood}) > 8
        assert all(r["winlog"]["event_data"]["LogonType"] == "3" for r in flood)
        assert all(r["winlog"]["event_data"]["Status"] == "0xC000006D" for r in flood)
        assert all(r["winlog"]["event_data"]["SubStatus"] == "0xC000006A" for r in flood)
        breaches = [
            r
            for r in records
            if r["event"]["code"] == "4624"
            and r["winlog"]["event_data"].get("IpAddress") == attacker_ip
        ]
        assert len(breaches) == 1
        assert any(r["event"]["code"] == "4740" for r in records)

    def test_seed_determinism(self) -> None:
        first = generate(main, count=100, seed=42, extra=["--format", "elastic"])
        second = generate(main, count=100, seed=42, extra=["--format", "elastic"])
        assert first == second


class TestCrossFormatEquivalence:
    def test_event_ids_computers_record_ids_match(self) -> None:
        xml_lines = generate(main, count=200, seed=7, extra=["--format", "xml"])
        elastic_lines = generate(main, count=200, seed=7, extra=["--format", "elastic"])
        assert len(xml_lines) == len(elastic_lines)
        for xml_line, elastic_line in zip(xml_lines, elastic_lines, strict=True):
            xml_root = _parse(xml_line)
            elastic = json.loads(elastic_line)
            xml_event_id = int(xml_root.findtext("e:System/e:EventID", namespaces=NS) or 0)
            assert str(xml_event_id) == elastic["event"]["code"]
            assert (
                xml_root.findtext("e:System/e:Computer", namespaces=NS)
                == elastic["winlog"]["computer_name"]
            )
            assert (
                xml_root.findtext("e:System/e:EventRecordID", namespaces=NS)
                == elastic["winlog"]["record_id"]
            )
            xml_time = xml_root.find("e:System/e:TimeCreated", NS)
            assert xml_time is not None
            # Elastic uses millisecond precision; XML uses 7-digit FILETIME.
            assert elastic["winlog"]["time_created"].startswith(xml_time.get("SystemTime", "")[:23])
            xml_data = _event_data(xml_root)
            assert xml_data == elastic["winlog"]["event_data"]


class TestDeterminism:
    def test_same_seed_same_output(self) -> None:
        assert generate(main, count=50) == generate(main, count=50)

    def test_different_seed_differs(self) -> None:
        assert generate(main, count=50, seed=1) != generate(main, count=50, seed=2)


class TestRealism:
    def test_sid_is_stable_per_user(self) -> None:
        sid_by_user: defaultdict[str, set[str]] = defaultdict(set)
        for rec in _records(count=800):
            if rec["event_id"] == 4624:
                sid_by_user[rec["target_user"]].add(rec["target_sid"])
        assert sid_by_user
        for user, sids in sid_by_user.items():
            assert len(sids) == 1, f"{user} has multiple SIDs: {sids}"
            assert DOMAIN_SID_RE.match(next(iter(sids)))

    def test_users_recur(self) -> None:
        users = Counter(r["target_user"] for r in _records(count=500) if r["event_id"] == 4624)
        assert users.most_common(1)[0][1] > 5
        assert len(users) <= 20

    def test_4672_immediately_follows_matching_admin_4624(self) -> None:
        records = _records(count=600)
        special = [i for i, r in enumerate(records) if r["event_id"] == 4672]
        assert special, "expected paired 4672 events in a 600-event sample"
        for i in special:
            prev = records[i - 1]
            assert prev["event_id"] == 4624
            assert prev["target_user"] == records[i]["subject_user"]
            assert prev["logon_id"] == records[i]["subject_logon_id"]
            assert records[i]["privileges"].startswith("Se")

    def test_4688_command_line_matches_image(self) -> None:
        procs = [r for r in _records(count=600) if r["event_id"] == 4688]
        assert procs
        for rec in procs:
            assert rec["process"].lower().endswith(".exe")
            basename = rec["process"].rsplit("\\", 1)[-1].lower()
            assert basename in rec["command_line"].lower()
            assert rec["parent_process"].lower().endswith(".exe")


class TestScenario:
    def test_brute_force_raises_4625_fraction(self) -> None:
        def frac_4625(extra: list[str]) -> float:
            records = _records(count=800, backfill="2h", extra=extra)
            return sum(r["event_id"] == 4625 for r in records) / len(records)

        baseline = frac_4625([])
        attack = frac_4625(["--scenario", "brute-force"])
        assert baseline < 0.10
        assert attack > baseline * 2

    def test_brute_force_flood_shape_and_breach(self) -> None:
        records = _records(count=800, backfill="2h", extra=["--scenario", "brute-force"])
        failures = [r for r in records if r["event_id"] == 4625]
        attacker_ip = Counter(r.get("source_ip", "-") for r in failures).most_common(1)[0][0]
        flood = [r for r in failures if r.get("source_ip") == attacker_ip]
        # one IP, many usernames, NTLM type-3 with the canonical NT status codes
        assert len(flood) > 50
        assert len({r["target_user"] for r in flood}) > 8
        assert all(r["logon_type"] == 3 for r in flood)
        assert all(r["status"] == "0xC000006D" for r in flood)
        assert all(r["sub_status"] == "0xC000006A" for r in flood)
        # nonexistent accounts are being sprayed too
        legit = {r["target_user"] for r in records if r["event_id"] == 4624}
        assert {r["target_user"] for r in flood} - legit
        # the breach: a single 4624 success from the attacker IP at window end
        breaches = [
            r for r in records if r["event_id"] == 4624 and r.get("source_ip") == attacker_ip
        ]
        assert len(breaches) == 1
        # lockouts get sprinkled into the flood
        assert any(r["event_id"] == 4740 for r in records)
