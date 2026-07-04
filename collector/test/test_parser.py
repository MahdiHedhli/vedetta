#!/usr/bin/env python3
"""Regression guard for the shipped syslog-rfc3164 parser in ../config/parsers.conf.

Fluent Bit's Lua golden suite (run_tests.lua) exercises unifi_transform *after* the
syslog parser has already split the line — via harness.lua's permissive ":%s*" split.
That masked a real defect: the shipped parsers.conf regex was stricter than the
harness and dropped (1) every CEF line and (2) any single-digit-day line, before the
transform ever ran. This test reads the ACTUAL regex out of parsers.conf and asserts
it accepts the line shapes real UniFi gateways emit, so the two can't drift again.

Run: python3 collector/test/test_parser.py   (no deps; exits nonzero on failure)
"""
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
PARSERS = os.path.join(HERE, "..", "config", "parsers.conf")


def load_syslog_regex():
    """Extract the syslog-rfc3164 Regex line and translate Fluent Bit (?<n>) → Python (?P<n>)."""
    name, regex = None, None
    for line in open(PARSERS, encoding="utf-8"):
        s = line.strip()
        if s.startswith("Name") and s.split()[1] == "syslog-rfc3164":
            name = "syslog-rfc3164"
        elif name and s.startswith("Regex"):
            regex = s[len("Regex"):].strip()
            break
    if not regex:
        sys.exit("FAIL: could not find syslog-rfc3164 Regex in parsers.conf")
    return re.compile(regex.replace("(?<", "(?P<"))


# (label, line, expected_ident, message_startswith) — all synthetic (RFC 5737 / placeholder)
CASES = [
    ("CEF, two-digit day",
     "<134>Jul 13 10:16:05 gateway-placeholder CEF:0|Ubiquiti|UniFi Network|9.0|fwrule|Firewall|3|src=192.0.2.45",
     "CEF", "0|Ubiquiti"),
    ("CEF, single-digit day (double space) — the preferred path on days 1-9",
     "<134>Jul  3 09:05:01 gateway-placeholder CEF:0|Ubiquiti|UniFi Network|9.0|fwrule|Firewall|3|src=192.0.2.45",
     "CEF", "0|Ubiquiti"),
    ("legacy iptables kernel line",
     "<4>Jul 13 10:15:22 gateway-placeholder kernel: [WAN_LOCAL-default-D]IN=eth8 OUT= SRC=203.0.113.9 DST=198.51.100.2",
     "kernel", "[WAN_LOCAL"),
    ("iptables, single-digit day",
     "<4>Jul  3 10:15:22 gateway-placeholder kernel: [LAN_IN-3001]IN=eth0 OUT= SRC=192.0.2.50 DST=198.51.100.2",
     "kernel", "[LAN_IN"),
]

REGEX = load_syslog_regex()
failures = 0
for label, line, want_ident, msg_prefix in CASES:
    m = REGEX.match(line)
    if not m:
        print(f"  FAIL  {label}: NOMATCH (line would be dropped at the syslog parser)")
        failures += 1
        continue
    ident, msg = m.group("ident"), m.group("message")
    if ident != want_ident:
        print(f"  FAIL  {label}: ident={ident!r} want {want_ident!r}")
        failures += 1
    elif not msg.startswith(msg_prefix):
        print(f"  FAIL  {label}: message={msg[:24]!r}... want prefix {msg_prefix!r}")
        failures += 1
    else:
        print(f"  PASS  {label}")

print(f"\nRESULT: {len(CASES) - failures} passed, {failures} failed")
sys.exit(1 if failures else 0)
