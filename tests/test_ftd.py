"""Tests for logsim-ftd (Cisco FTD security event syslog)."""

from __future__ import annotations

import re
from collections import Counter
from itertools import pairwise

from log_simulators.ftd.cli import main

from .conftest import generate

IP = r"(?:\d{1,3}\.){3}\d{1,3}"

ANY_FTD_RE = re.compile(
    r"^%FTD-(\d)-(430001|430002|430003|430004|430005): "
    r"EventPriority: \w+, DeviceUUID: .+"
)
CONN_START_RE = re.compile(r".*ConnectionID: (\d+).*")
INTRUSION_RE = re.compile(r"^%FTD-1-430001: .*SigID: (\d+)")
FILE_RE = re.compile(r"^%FTD-5-430004: .*FileType: \w+")
MALWARE_RE = re.compile(r"^%FTD-4-430005: .*Disposition: \w+")
SYSLOG_RE = re.compile(
    r"^<(\d{2,3})>[A-Z][a-z]{2} [ \d]\d \d{2}:\d{2}:\d{2} \S+ : (%FTD-(\d)-\d{6}: .+)$"
)


def _proto(line: str) -> str:
    return line.split("Protocol:")[1].split(",")[0].strip()


class TestFormats:
    def test_every_line_is_ftd(self) -> None:
        for line in generate(main, count=500):
            assert ANY_FTD_RE.match(line), line

    def test_syslog_header_format(self) -> None:
        for line in generate(main, count=200, extra=["--syslog-header"]):
            m = SYSLOG_RE.match(line)
            assert m, line
            assert ANY_FTD_RE.match(m.group(2)), line

    def test_pri_is_local4_plus_severity(self) -> None:
        for line in generate(main, count=100, extra=["--syslog-header"]):
            m = SYSLOG_RE.match(line)
            assert m, line
            assert int(m.group(1)) == 160 + int(m.group(3)), line

    def test_intrusion_has_key_fields(self) -> None:
        lines = [line for line in generate(main, count=3000) if line.startswith("%FTD-1-430001")]
        assert lines, "expected at least one intrusion event"
        for line in lines:
            assert "Classification:" in line
            assert "SigID:" in line
            assert "Message:" in line

    def test_file_events_have_sha_and_size(self) -> None:
        lines = [line for line in generate(main, count=2000) if line.startswith("%FTD-5-430004")]
        assert lines, "expected at least one file event"
        for line in lines:
            assert "Sha256:" in line
            assert "FileSize:" in line

    def test_malware_events_have_disposition(self) -> None:
        lines = [line for line in generate(main, count=2000) if line.startswith("%FTD-4-430005")]
        assert lines, "expected at least one malware event"
        for line in lines:
            assert "Disposition:" in line
            assert "MalwareName:" in line


class TestDeterminism:
    def test_same_seed_same_output(self) -> None:
        assert generate(main, count=120) == generate(main, count=120)

    def test_different_seed_differs(self) -> None:
        assert generate(main, count=120, seed=1) != generate(main, count=120, seed=2)


class TestConnectionPairing:
    def test_every_end_was_started_first_and_only_ended_once(self) -> None:
        open_ids: set[int] = set()
        ends = 0
        for line in generate(main, count=1500):
            if line.startswith("%FTD-6-430002"):
                m = CONN_START_RE.match(line)
                assert m, line
                open_ids.add(int(m.group(1)))
            elif line.startswith("%FTD-6-430003"):
                m = CONN_START_RE.match(line)
                assert m, line
                cid = int(m.group(1))
                assert cid in open_ids, f"end of never-started/already-ended conn: {line}"
                open_ids.remove(cid)
                ends += 1
        assert ends > 50

    def test_conn_ids_strictly_increasing(self) -> None:
        ids = [
            int(m.group(1))
            for line in generate(main, count=1000)
            if line.startswith("%FTD-6-430002") and (m := CONN_START_RE.match(line))
        ]
        assert len(ids) > 50
        assert all(b > a for a, b in pairwise(ids))


class TestRealism:
    def test_ips_recur(self) -> None:
        ips: Counter[str] = Counter()
        for line in generate(main, count=800):
            m = re.search(r"SrcIP: " + IP, line)
            if m:
                ips[m.group(0).split(": ")[1]] += 1
        assert ips and ips.most_common(1)[0][1] > 5

    def test_tcp_heavy_protocol_mix(self) -> None:
        protos = Counter(_proto(line) for line in generate(main, count=1000))
        total = sum(protos.values())
        assert total
        assert protos["tcp"] / total > 0.5


class TestScenario:
    @staticmethod
    def _intrusion_fraction(extra: list[str]) -> float:
        lines = generate(main, count=800, backfill="2h", extra=extra)
        return sum(1 for line in lines if line.startswith("%FTD-1-430001")) / len(lines)

    def test_ips_flood_raises_intrusion_rate(self) -> None:
        baseline = self._intrusion_fraction([])
        flood = self._intrusion_fraction(["--scenario", "ips-flood"])
        assert baseline < 0.15
        assert flood > baseline * 2
