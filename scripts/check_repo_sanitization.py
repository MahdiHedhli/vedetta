#!/usr/bin/env python3
"""Reject tracked lab artifacts and non-documentation identifiers in Git data.

The SQL checks prevent accidental disclosure in a deliberately restricted,
reviewable migration subset.  They are not an arbitrary SQLite program
verifier.  Legacy identity-copy migrations are accepted only at an exact,
path-bound content digest; any edit is evaluated by the forward-only subset.
"""

from __future__ import annotations

import argparse
from bisect import bisect_right
import csv
import hashlib
import ipaddress
import json
import re
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any, Iterable


FORBIDDEN_PARTS = {
    ".local",
    "lab", "labs",
    "capture", "captures", "packet-capture", "packet-captures", "pcap", "pcaps",
    "export", "exports", "backup", "backups", "dump", "dumps", "scan", "scans",
    "inventory", "inventories",
}
LOCAL_ONLY_COMPONENT_FAMILIES = {
    ".aws",
    ".claude",
    ".codex",
    ".cursor",
    ".docker",
    ".gcp",
    ".terraform",
    "agent-scratch",
    "analysis-notes",
    "logs",
    "scratch",
}
ROOT_LOCAL_ONLY_FAMILIES = {"internal", "private"}
FORBIDDEN_ARTIFACT_SUFFIXES = (
    ".db",
    ".db3",
    ".s3db",
    ".sl3",
    ".sqlite",
    ".sqlite3",
    ".db-wal",
    ".db-shm",
    ".db-journal",
    ".db3-wal",
    ".db3-shm",
    ".db3-journal",
    ".s3db-wal",
    ".s3db-shm",
    ".s3db-journal",
    ".sl3-wal",
    ".sl3-shm",
    ".sl3-journal",
    ".sqlite-wal",
    ".sqlite-shm",
    ".sqlite-journal",
    ".sqlite3-wal",
    ".sqlite3-shm",
    ".sqlite3-journal",
    ".pcap",
    ".pcapng",
    ".cap",
    ".har",
    ".ndjson",
    ".jsonl",
    ".nmap",
    ".gnmap",
    ".etl",
    ".evtx",
    ".dmp",
    ".dump",
    ".bak",
    ".backup",
)
FORBIDDEN_ARCHIVE_SUFFIXES = (
    ".zip",
    ".tar",
    ".tar.gz",
    ".tgz",
    ".gz",
    ".bz2",
    ".xz",
    ".7z",
    ".rar",
    ".zst",
    ".lz4",
)
INSPECT_SUFFIXES = {
    ".json",
    ".csv",
    ".tsv",
    ".xml",
    ".txt",
    ".yaml",
    ".yml",
    ".toml",
    ".ini",
    ".sql",
}
DATA_PARTS = {
    "corpus",
    "corpora",
    "corpuses",
    "data",
    "dataset",
    "datasets",
    "testdata",
    "test-data",
    "test_data",
    "fixture",
    "fixtures",
    "sample",
    "samples",
    "sample-data",
    "demo-data",
    "demo_data",
    "inventory",
    "inventories",
}
# These exact tests intentionally contain unsafe marker strings to prove the
# separate publication privacy gate. Production Go files in the corpus package
# are still scanned so a future embedded seed cannot bypass this repository gate.
SOURCE_FILE_EXEMPTIONS = {
    "threat-network/internal/corpus/canonical_test.go",
    "threat-network/internal/corpus/privacy_test.go",
}
CONTENT_SCAN_EXEMPT_FILES = {"scripts/tests/repo-sanitization-test.sh"}
OPERATIONAL_SUFFIXES = {
    ".bash",
    ".conf",
    ".fish",
    ".ksh",
    ".plist",
    ".ps1",
    ".service",
    ".sh",
    ".zsh",
}
BINARY_MEDIA_PREFIXES = (
    "docs/assets/",
    "docs/images/",
    "frontend/public/",
    "frontend/src/assets/",
    "site/assets/",
)
IMAGE_MEDIA_SUFFIXES = {".avif", ".gif", ".ico", ".jpeg", ".jpg", ".png", ".webp"}
FONT_MEDIA_SUFFIXES = {".otf", ".ttf", ".woff", ".woff2"}
VIDEO_MEDIA_SUFFIXES = {".mp4", ".webm"}
BINARY_MEDIA_SUFFIXES = IMAGE_MEDIA_SUFFIXES | FONT_MEDIA_SUFFIXES | VIDEO_MEDIA_SUFFIXES
# Opaque media cannot be proven non-executable by format parsing: Bash can
# continue after binary-prefix errors and ignore embedded NUL bytes. Only these
# exact manually reviewed blobs are admitted. This checker is protected by the
# base-owned PR gate, so adding or changing media requires an explicit policy
# maintenance review rather than a candidate-edited manifest.
BINARY_MEDIA_SHA256 = {
    "site/assets/dashboard-devices.png": (
        "e7c12bc3a54b65759c9fef305ad15bc9b738a5862b2a95d31ac19d8c5ff92e08"
    ),
    "site/assets/dashboard-findings-tour.gif": (
        "799a9eb6284de0854e59e695cc2548c223046a6cfb8d9c6adb116b7307a941f3"
    ),
    "site/assets/dashboard-findings.png": (
        "dc6bf1b3378f97d16da4596734b40f9e1ca2747a9a52ed712f185e4e79c61c5a"
    ),
    "site/assets/dashboard-overview.png": (
        "4b22fe0ecfba6a8738124f3fc552f623d81bb75dddc94b205c94d06d7b06e081"
    ),
    "site/assets/dashboard-threats.png": (
        "71fa675e8ee88c91e7643e31e3d22c057773926de0da4e0c73b51a8ad0f2691d"
    ),
    "site/assets/dashboard-tour.gif": (
        "7fefadfbcaaf66c201d17ab75253bf92b1f8368041c720965a08ef72c6d9e6f3"
    ),
    "site/assets/og-image.png": (
        "dba84ba268ad1860213790a8fc47e10a740f91b15ff6ea63124c82b0cdd82967"
    ),
    "specs/007-asset-centered-findings/assets/asset-identity.png": (
        "e27005701a2fcf39027c620c0b51a9e7aaf00adc76632d514a544991ff18dda9"
    ),
    "specs/007-asset-centered-findings/assets/finding-evidence.png": (
        "bb36ce53e18323bde9ff9110a8c8628772de028e91bf38d4dcb3ae035f52863a"
    ),
    "specs/007-asset-centered-findings/assets/findings-dashboard.png": (
        "6e41871e5c82b729f7aaffaf2a9501325d1df44375fb8fa7392b9ef8aff9e5f4"
    ),
}
PATH_V4_ALLOWLIST = {
    # Product default copied by fresh installs, not observed operator data.
    ".env.example": {ipaddress.ip_address("192.168.1.0")},
}
RISK_DATA_NAME_RE = re.compile(
    r"(?i)(?:^|[-_.])(?:inventor(?:y|ies)|fingerprints?|device[-_.]?data|exports?|dumps?|"
    r"backups?|nmap|masscan|scans?|pcaps?|packet[-_]?captures?)(?:[-_.]|$)"
)
# Risk-shaped source and documentation names describe product behavior; opaque
# names such as device_inventory.dat are treated as generated data instead.
RISK_SOURCE_SUFFIXES = {
    ".c",
    ".cc",
    ".conf",
    ".cpp",
    ".css",
    ".go",
    ".h",
    ".html",
    ".java",
    ".js",
    ".jsx",
    ".kt",
    ".md",
    ".mjs",
    ".plist",
    ".ps1",
    ".py",
    ".rb",
    ".rs",
    ".scss",
    ".service",
    ".sh",
    ".swift",
    ".ts",
    ".tsx",
}
ALLOWED_LOG_PREFIXES = ("specs/001-unifi-log-ingestion/corpus/inputs/",)
JSON_LINES_PREFIXES = ("specs/001-unifi-log-ingestion/corpus/expected/",)
PUBLIC_DOMAIN_LIST_PATH = "threat-network/internal/store/data/allowlist.txt"
# The embedded IEEE OUI table is public reference data (24-bit vendor prefixes + vendor
# names), not homelab inventory. Many IEEE vendor names legitimately contain ".com",
# ".corp", "&", etc., which would trip the identity scans, so it gets a dedicated
# structural validator instead — see oui_table_failures / inspect_data.
OUI_TABLE_PATH = "backend/internal/fingerprint/data/oui.csv"
ALLOWED_SQL_PREFIXES = ("siem/migrations/", "threat-network/internal/store/migrations/")
ALLOWED_SQL_FILES = {"scripts/db-health.sql", "scripts/seed-snr-validation.sql"}
LEGACY_SQL_SHA256 = {
    "siem/migrations/009_event_type_encrypted_dns.sql": "47ceeaae74602ee1bcca6e07fe64de992e6d0bae796da4796ca1cb267b8454ab",
    "siem/migrations/018_device_correlation.sql": "f49578f820a3aa3909cd3899084235b1aaee737d06013e1e4d53bad1e6faafde",
    "siem/migrations/019_relax_segment_check.sql": "cc61139587f31edf58f2124baa0d0fc1299b8679cc6120c49fc6fbab13884594",
    "siem/migrations/020_repair_correlation_fks.sql": "bc3d9adc09ad442443490be963b1a061145cd936c10c4254dd9db1baff6d3c43",
    "siem/migrations/025_asset_centered_findings.sql": "afe8df6c897485e0e7195ecc6027ba3d5308d7781ad10439817a95b1352de564",
}
SQL_READ_ONLY_FILES = {"scripts/db-health.sql"}
SQL_READ_ONLY_SHA256 = {
    "scripts/db-health.sql": "fad7f5c3698adef1be94aa3a8dc133b3168338a82522e47f188a8c542902f844",
}
SQL_STATIC_FIXTURE_FILES = {"scripts/seed-snr-validation.sql"}
SQL_HARMLESS_DOT_COMMANDS = {".echo", ".headers", ".mode", ".timer"}
MAX_DATA_BYTES = 8 * 1024 * 1024
MAX_JSON_BYTES = 1 * 1024 * 1024
MAX_DELIMITED_BYTES = 2 * 1024 * 1024
MAX_XML_BYTES = 2 * 1024 * 1024
MAX_STRUCTURED_VALUES = 100_000
LFS_POINTER_RE = re.compile(
    rb"\Aversion https://(?:git-lfs|hawser)\.github\.com/spec/v1\r?\n"
    rb"(?:ext-[0-9]{1,3}-[A-Za-z0-9][A-Za-z0-9.-]{0,63} [^\x00-\x1f\x7f]{1,256}\r?\n)*"
    rb"oid sha256:[0-9a-f]{64}\r?\nsize (?:0|[1-9][0-9]{0,19})(?:\r?\n)?\Z"
)

DOCUMENTATION_V4 = tuple(
    ipaddress.ip_network(network)
    for network in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24")
)
DOCUMENTATION_V6 = ipaddress.ip_network("2001:db8::/32")
STANDARD_MULTICAST_V4 = {
    ipaddress.ip_address("224.0.0.251"),  # mDNS
    ipaddress.ip_address("239.255.255.250"),  # SSDP
}
STANDARD_MULTICAST_V6 = {ipaddress.ip_address("ff02::fb")}  # mDNS

# Zero-width lookahead preserves overlapping four-component windows in longer
# dotted runs, so both `10.1.2.3.4` and `1.192.168.77.9` expose the embedded
# private quad. Group 1 is the candidate value.
IPV4_RE = re.compile(r"(?=(?<!\d)((?:\d{1,3}\.){3}\d{1,3})(?!\d))")
IPV6_TOKEN_RE = re.compile(r"(?<![A-Za-z0-9:])[A-Za-z0-9:%]{2,}(?![A-Za-z0-9:])")
MAC_DELIMITED_RE = re.compile(r"(?i)(?<![0-9a-f])(?:[0-9a-f]{2}[:-]){5}[0-9a-f]{2}(?![0-9a-f])")
MAC_CISCO_RE = re.compile(r"(?i)(?<![0-9a-f])[0-9a-f]{4}(?:\.[0-9a-f]{4}){2}(?![0-9a-f])")
MAC_COMPACT_RE = re.compile(r"(?i)(?<![0-9a-z])[0-9a-f]{12}(?![0-9a-z])")
MAC_COMPACT_EMBEDDED_RE = re.compile(r"(?i)[0-9a-f]{12}")
MAC_CONTEXTUAL_COMPACT_RE = re.compile(
    r"(?i)(?<![a-z0-9])(?:"
    r"(?:source|src|destination|dest|dst|device|client|server)[_ -]?mac(?:[_ -]?(?:address|addr))?|"
    r"mac(?:[_ -]?(?:address|addr))?|bssid|hw(?:addr|[_ -]?address)|hardware[_ -]?address"
    r")(?![a-z0-9])(?:[\"']?[ \t]*[:=][ \t]*[\"']?|[_ -]+)(?:0x)?"
    r"([0-9a-f]{12})(?![0-9a-f])"
)
MAC_CONTEXTUAL_TIGHT_RE = re.compile(
    r"(?i)(?<![a-z0-9])(?:mac|bssid)(?:0x)?([0-9a-f]{12})(?![0-9a-f])"
)
MAC_HEX_COMPACT_RE = re.compile(r"(?i)(?<![0-9a-z])0x([0-9a-f]{12})(?![0-9a-f])")
UUID_RE = re.compile(
    # Only versions whose final 48 bits are random/hash material may be masked.
    # UUIDv1/v2/v6 (and unknown/custom versions) can carry an originating MAC
    # in the node field and must continue through compact-MAC inspection.
    r"(?i)(?<![0-9a-f])(?:00000000-0000-0000-0000-000000000000|"
    r"[0-9a-f]{8}-[0-9a-f]{4}-[3457][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12})(?![0-9a-f])"
)
# Tokenize in one bounded pass while retaining Unicode/emoji labels. Structural
# delimiters stop a candidate; dots, hyphens, underscores and non-ASCII
# characters remain part of it so a private suffix cannot be detached from its
# identifying label.
LOCAL_TOKEN_RE = re.compile(r'''[^\s"'`<>{}\[\](),;:=/\\|?&!#]+''')
IDNA_DOT_TRANSLATION = str.maketrans({"\u3002": ".", "\uff0e": ".", "\uff61": "."})
PURE_MDNS_SERVICE_RE = re.compile(r"(?i)^_[a-z0-9-]+\._(?:tcp|udp)\.local\.?$")
PLACEHOLDER_LOCAL_RE = re.compile(
    r"(?i)^(?:[a-z0-9]+-)?placeholder(?:-[0-9]+)?\."
    r"(?:local|lan|home(?:\.arpa)?|internal|localdomain|corp)\.?$"
)
LOCAL_WILDCARD_RE = re.compile(
    r"(?i)^(?:\*|%)\.(?:local|lan|home(?:\.arpa)?|internal|localdomain|corp)\.?$"
)
SYNTHETIC_LOG_HOST_RE = re.compile(
    r"(?i)^(?:(?:[a-z0-9]+-)?placeholder|placeholder(?:-[a-z0-9]+)?)$"
)
ALLOWED_UNIFI_NOISE_LINES = {"this is not a syslog line at all and must be dropped"}
GENERIC_KEY_VALUE_RE = re.compile(
    r"(?i)(?<![a-z0-9_])[\"']?([a-z][a-z0-9_-]*)[\"']?[ \t]*[:=](?![=~])[ \t]*[\"']?"
    r"(\$\{[^}\r\n]+\}|\{\{[^}\r\n]+\}\}|%[a-z_][a-z0-9_.:-]*%|<[a-z_][a-z0-9_.:-]*>|[^\"',}\]\s]+)"
)
XML_TEXT_VALUE_RE = re.compile(
    r"<\s*([a-z_][a-z0-9_.:-]*)\b[^>]*>\s*([^<]+?)\s*</\s*\1\s*>", re.IGNORECASE | re.DOTALL
)
XML_UNSAFE_DECL_RE = re.compile(r"(?is)<!\s*(?:DOCTYPE|ENTITY)\b|<!\[CDATA\[")
XML_DECLARATION_RE = re.compile(
    r'''(?is)^xml\s+version\s*=\s*(?:"1\.[01]"|'1\.[01]')'''
    r'''(?:\s+encoding\s*=\s*(?:"[a-z][a-z0-9._-]*"|'[a-z][a-z0-9._-]*'))?'''
    r'''(?:\s+standalone\s*=\s*(?:"(?:yes|no)"|'(?:yes|no)'))?\s*$'''
)
MAX_XML_DEPTH = 128
MAX_XML_ELEMENTS = 100_000
MAX_XML_VALUE_CHARS = 256 * 1024
MAX_XML_OUTPUT_VALUES = 200_000
SQL_DML_VALUES_RE = re.compile(
    r"(?is)^(?:insert(?:\s+or\s+[a-z]+)?|replace)\s+into\s+[^\s(]+\s*"
    r"(?:\((?P<columns>[^)]*)\))?\s+values\b(?P<rows>.*)$"
)
SQL_DML_SELECT_RE = re.compile(
    r"(?is)^(?:insert(?:\s+or\s+[a-z]+)?|replace)\s+into\s+[^\s(]+\s*"
    r"(?:\((?P<columns>[^)]*)\))?\s+select\b(?P<projection>.*)$"
)
SQL_LITERAL_TOKEN = r'''(?:x'[0-9a-f]*'|'(?:''|[^'])*'|"(?:""|[^"])*")'''
SQL_IDENTIFIER_TOKEN = r'''(?:[a-z_][a-z0-9_]*|`(?:``|[^`])+`|\[(?:[^]])+\]|"(?:""|[^"])+")'''
SQL_POSITIONAL_IDENTIFIER_TOKEN = rf'''(?:{SQL_IDENTIFIER_TOKEN}|'(?:''|[^'])+')'''
SQL_LITERAL_CONCAT_RE = re.compile(
    rf"(?is)^\s*{SQL_LITERAL_TOKEN}(?:\s*\|\|\s*{SQL_LITERAL_TOKEN})*\s*$"
)
SQL_NUMERIC_BODY = (
    r"(?:0x[0-9a-f](?:_?[0-9a-f])*|"
    r"(?:\d(?:_?\d)*)?(?:\.\d(?:_?\d)*)(?:e[+-]?\d(?:_?\d)*)?|"
    r"\d(?:_?\d)*(?:\.(?:\d(?:_?\d)*)?)?(?:e[+-]?\d(?:_?\d)*)?)"
)
SQL_NUMERIC_TOKEN_RE = re.compile(rf"(?i)(?<![a-z0-9_]){SQL_NUMERIC_BODY}(?![a-z0-9_])")
SQL_NUMERIC_LITERAL_RE = re.compile(rf"(?i)^\s*[+-]?{SQL_NUMERIC_BODY}\s*$")
SQL_ATTRIBUTE_IDENTIFIER_RE = re.compile(
    r'''(?is)(?<![a-z0-9_])(?:attribute|`attribute`|\[attribute\]|"attribute")(?![a-z0-9_])'''
)
SQL_PARAMETER_RE = re.compile(
    r"(?i)(?<![a-z0-9_])(?:[@:$](?:[a-z_][a-z0-9_]*|\d+)|\?(?:\d+)?)"
)
SQL_WRITE_CAPABILITY_RE = re.compile(
    r"(?i)\b(?:insert|replace|update|delete|create|alter|drop|pragma|attach|detach|"
    r"vacuum|reindex|analyze)\b"
)
MAX_SQL_LITERAL_MARKS = 8192
MAX_SQL_PARENTHESIS_MARKS = 16_384
MAX_SQL_FIELD_MARKS = 100_000
MAX_SQL_STATIC_BYTES = 64 * 1024
MAX_SQL_BYTES = 256 * 1024
MAX_SQL_STATEMENTS = 20_000
MAX_SQL_BOOLEAN_OPERATORS = 50_000
MAX_SQL_QUERY_KEYWORDS = 96
VERSION_VALUE_RE = re.compile(
    r"(?i)^(?:[a-z0-9]+-)?v?\d+(?:\.\d+){1,7}(?:[_+-][0-9a-z]+(?:[._-][0-9a-z]+)*)?$"
)
TEMPLATE_HOST_RE = re.compile(
    r"^(?:\$\{[^{}\r\n]+\}|\{\{[A-Za-z_][A-Za-z0-9_.:-]*\}\}|"
    r"%[A-Za-z_][A-Za-z0-9_.:-]*%|<[A-Za-z_][A-Za-z0-9_.:-]*>)$"
)
DNS_NAME_RE = re.compile(
    r"(?i)(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*"
    r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
)
STRUCTURED_NAME_KEY = "__structured_name__"

SHOW_SENSITIVE_PATHS = False
OPAQUE_PATH_TOKENS: dict[str, str] = {}

HOST_KEYS = {
    "host",
    "host_name",
    "hostname",
    "fqdn",
    "domain",
    "etld_plus_one",
    "client_hostname",
    "device_hostname",
    "local_hostname",
    "mdns_hostname",
    "mdns_name",
    "server_hostname",
    "gateway_hostname",
    "client_name",
    "device_name",
    "display_name",
    "friendly_name",
    "custom_name",
}
PUBLIC_DOMAIN_KEYS = {"domain", "etld_plus_one"}
DEVICE_HOST_KEYS = HOST_KEYS - PUBLIC_DOMAIN_KEYS
MAC_KEYS = {"mac", "mac_address", "src_mac", "dst_mac", "bssid", "hwaddr", "hardware_address"}
IP_KEYS = {
    "ip",
    "ip_address",
    "source_ip",
    "src_ip",
    "destination_ip",
    "dest_ip",
    "dst_ip",
    "resolved_ip",
    "gateway_ip",
    "address",
}
VERSION_KEYS = {
    "version",
    "firmware",
    "firmwareversion",
    "firmware_version",
    "hardware_version",
    "hardware_revision",
    "software_version",
    "softwareversion",
    "os_version",
    "osversion",
    "build_version",
    "buildversion",
    "product_version",
    "model_number",
    "revision",
}
TYPED_ATTRIBUTE_KEYS = HOST_KEYS | MAC_KEYS | IP_KEYS | VERSION_KEYS
RELATIONAL_VALUE_KEYS = {"value", "value_end"}
RELATIONAL_TYPE_VALUE_KEYS = {
    "attribute": {"value", "value_end"},
    "id_type": {"id_value"},
    "address_type": {"address_value"},
    "field": {"value", "value_end"},
    "observable_type": {"observable_value"},
    "primary_observable_type": {"primary_observable"},
    "indicator_type": {"indicator"},
}
RELATIONAL_ALL_VALUE_KEYS = set().union(*RELATIONAL_TYPE_VALUE_KEYS.values())
INVENTORY_SCHEMA_KEYS = (
    TYPED_ATTRIBUTE_KEYS
    | set(RELATIONAL_TYPE_VALUE_KEYS)
    | RELATIONAL_ALL_VALUE_KEYS
    | {
        "id",
        "device_id",
        "asset_id",
        "device",
        "devices",
        "asset",
        "assets",
        "item",
        "items",
        "record",
        "records",
        "inventory",
        "fingerprint",
        "fingerprints",
        "fingerprint_id",
        "data",
        "metadata",
        "schema",
        "schema_version",
        "facts",
        "signals",
        "observations",
        "name",
        "type",
        "device_type",
        "category",
        "vendor",
        "manufacturer",
        "model",
        "product",
        "product_name",
        "os",
        "platform",
        "segment",
        "sensor",
        "sensor_id",
        "source",
        "sources",
        "first_seen",
        "last_seen",
        "created_at",
        "updated_at",
        "observed_at",
        "valid_from",
        "valid_until",
        "confidence",
        "identity_confidence",
        "reason",
        "evidence",
        "service",
        "services",
        "port",
        "ports",
        "protocol",
        "status",
        "notes",
        "note",
        "comment",
        "comments",
    }
)
INVENTORY_COLLECTION_KEYS = {"devices", "assets", "items", "records", "facts", "signals", "observations", "fingerprints"}
STRUCTURED_KEY_ALIASES = {
    "host_name": "hostname",
    "devicehostname": "device_hostname",
    "clienthostname": "client_hostname",
    "serverhostname": "server_hostname",
    "gatewayhostname": "gateway_hostname",
    "ipaddress": "ip_address",
    "macaddress": "mac_address",
    "mac_addr": "mac_address",
    "macaddr": "mac_address",
    "hw_addr": "hwaddr",
    "hw_address": "hwaddr",
    "hwaddress": "hwaddr",
    "hardwareaddress": "hardware_address",
    "m_dns_name": "mdns_name",
    "i_pv4_address": "ip_address",
    "ip_v4_address": "ip_address",
    "ipv4address": "ip_address",
    "i_pv6_address": "ip_address",
    "ip_v6_address": "ip_address",
    "ipv6address": "ip_address",
    "device_host_name": "device_hostname",
    "client_host_name": "client_hostname",
    "server_host_name": "server_hostname",
    "gateway_host_name": "gateway_hostname",
    "idtype": "id_type",
    "idvalue": "id_value",
    "addresstype": "address_type",
    "addressvalue": "address_value",
    "etldplusone": "etld_plus_one",
    "e_tld_plus_one": "etld_plus_one",
    "firmwareversion": "firmware_version",
    "softwareversion": "software_version",
    "osversion": "os_version",
    "buildversion": "build_version",
}
JSON_STRING_TOKEN_RE = r'''"(?:\\["\\/bfnrt]|\\u[0-9a-fA-F]{4}|[^"\\\x00-\x1f])*"'''
JSON_STRING_RE = re.compile(JSON_STRING_TOKEN_RE)


@dataclass(frozen=True)
class GitEntry:
    path: str
    mode: str
    oid: str


@dataclass(frozen=True)
class GenericField:
    key: str
    value: str
    value_start: int
    value_end: int
    line: int
    scope: tuple[str, ...]


@dataclass
class XMLResidualPiece:
    text: str
    version_exemption: int | None = None


@dataclass
class XMLFrame:
    raw_tag: str
    tag: str
    text_parts: list[str]
    residual_pieces: list[XMLResidualPiece]
    raw_text_spans: list[tuple[int, int]]
    text_length: int
    child_values: list[tuple[str, str]]
    direct_child_values: list[tuple[str, str]]
    direct_child_raw_spans: list[list[tuple[int, int]]]
    direct_child_piece_ranges: list[tuple[int, int]]
    direct_child_is_leaf: list[bool]
    direct_child_output_indexes: list[int | None]
    has_children: bool
    has_direct_text: bool


class XMLInspectionError(Exception):
    pass


def git(root: Path, *args: str, text: bool = False) -> bytes | str:
    return subprocess.check_output(["git", "-C", str(root), *args], text=text)


def index_entries(root: Path) -> tuple[list[GitEntry], list[str]]:
    entries: list[GitEntry] = []
    failures: list[str] = []
    output = git(root, "ls-files", "--stage", "-z")
    assert isinstance(output, bytes)
    for record in output.split(b"\0"):
        if not record:
            continue
        metadata, raw_path = record.split(b"\t", 1)
        mode, oid, stage = metadata.decode("ascii").split()
        path = raw_path.decode("utf-8", "surrogateescape")
        if stage != "0":
            failures.append(f"{display_path(path)}: unmerged index entries cannot be sanitized")
            continue
        entries.append(GitEntry(path, mode, oid))
    return entries, failures


def commit_entries(root: Path, revision: str) -> list[GitEntry]:
    output = git(root, "ls-tree", "-r", "-z", "--full-tree", revision)
    assert isinstance(output, bytes)
    entries: list[GitEntry] = []
    for record in output.split(b"\0"):
        if not record:
            continue
        metadata, raw_path = record.split(b"\t", 1)
        mode, kind, oid = metadata.decode("ascii").split()
        if kind != "blob" and mode != "160000":
            continue
        entries.append(GitEntry(raw_path.decode("utf-8", "surrogateescape"), mode, oid))
    return entries


def history_entries(root: Path, revision_range: str) -> list[GitEntry]:
    output = git(root, "rev-list", "--reverse", revision_range, text=True)
    assert isinstance(output, str)
    entries: list[GitEntry] = []
    for revision in output.splitlines():
        if revision:
            entries.extend(commit_entries(root, revision))
    return entries


def is_versioned_component(part: str, families: set[str]) -> bool:
    """Match an exact data directory or a conventional numeric version suffix."""
    lowered = part.lower()
    for family in sorted(families, key=len, reverse=True):
        if lowered == family:
            return True
        if lowered.startswith(family + "-") or lowered.startswith(family + "_"):
            suffix = lowered[len(family) + 1:]
            if re.fullmatch(r"v?\d[0-9a-z._-]*", suffix):
                return True
    return False


def matches_named_family(part: str, families: set[str]) -> bool:
    """Match an exact local-only directory name or a hyphen/underscore variant."""
    lowered = part.lower()
    return any(
        lowered == family
        or lowered.startswith(family + "-")
        or lowered.startswith(family + "_")
        or lowered.startswith(family + ".")
        for family in sorted(families, key=len, reverse=True)
    )


def is_data_component(part: str) -> bool:
    lowered = part.lower()
    broad_inventory = any(
        lowered == family
        or lowered.startswith(family + "-")
        or lowered.startswith(family + "_")
        for family in ("inventory", "inventories")
    )
    return broad_inventory or is_versioned_component(part, DATA_PARTS)


def is_forbidden_component(part: str) -> bool:
    """Match ignored local-artifact directory families, including named variants."""
    return matches_named_family(part, FORBIDDEN_PARTS)


def is_unconditional_local_path(path: str) -> bool:
    """Mirror security-sensitive ignored directory families for forced adds."""
    parts = PurePosixPath(path).parts[:-1]
    if parts and matches_named_family(parts[0], ROOT_LOCAL_ONLY_FAMILIES):
        return True
    return any(matches_named_family(part, LOCAL_ONLY_COMPONENT_FAMILIES) for part in parts)


def is_telemetry_export_source(path: str) -> bool:
    """Allow only regular Go source names in the package named `export`."""
    pure = PurePosixPath(path)
    return pure.parent.as_posix() == "telemetry/internal/export" and pure.suffix == ".go"


def is_inventory_path(path: str) -> bool:
    pure = PurePosixPath(path)
    return any(
        part.lower() in {"inventory", "inventories"}
        or bool(
            re.search(
                r"(?i)(?:^|[-_.])(?:inventor(?:y|ies)|fingerprints?|device[-_.]?data)(?:[-_.]|$)",
                part,
            )
        )
        for part in pure.parts
    )


def bounded_logical_lines(contents: str) -> tuple[list[str], bool]:
    """Split every Unicode/Python logical line form without exceeding the value cap."""
    separators = {"\n", "\r", "\v", "\f", "\x1c", "\x1d", "\x1e", "\x85", "\u2028", "\u2029"}
    lines: list[str] = []
    start = 0
    index = 0
    while index < len(contents):
        character = contents[index]
        if character not in separators:
            index += 1
            continue
        lines.append(contents[start:index])
        if len(lines) > MAX_STRUCTURED_VALUES:
            return [], False
        if character == "\r" and index + 1 < len(contents) and contents[index + 1] == "\n":
            index += 1
        index += 1
        start = index
    if start < len(contents):
        lines.append(contents[start:])
        if len(lines) > MAX_STRUCTURED_VALUES:
            return [], False
    return lines, True


def is_environment_name(name: str) -> bool:
    """Match dotenv filenames; `.env.example` is exempt only as a file basename."""
    lowered = name.lower()
    return bool(
        lowered.startswith(".env")
        or ".env." in lowered
        or lowered.endswith(".env")
    )


def is_risk_shaped_path(path: str) -> bool:
    pure = PurePosixPath(path)
    parts = tuple(part.lower() for part in pure.parts)
    return bool(
        any(is_environment_name(part) for part in parts)
        or any(is_data_component(part) or is_forbidden_component(part) for part in parts[:-1])
        or any(RISK_DATA_NAME_RE.search(part) for part in parts)
        or any(is_forbidden_artifact(part) for part in parts)
    )


def read_blob(root: Path, entry: GitEntry) -> tuple[bytes | None, str | None]:
    size_output = git(root, "cat-file", "-s", entry.oid, text=True)
    assert isinstance(size_output, str)
    size = int(size_output.strip())
    if size > MAX_DATA_BYTES:
        return None, f"tracked blob exceeds the {MAX_DATA_BYTES // (1024 * 1024)} MiB review limit"
    contents = git(root, "cat-file", "blob", entry.oid)
    assert isinstance(contents, bytes)
    return contents, None


def path_identifier_categories(path: str) -> set[str]:
    """Return unsafe identifier classes embedded in a tracked path."""
    categories: set[str] = set()
    candidates = {path}
    component_candidates: dict[str, set[str]] = {}
    for component in PurePosixPath(path).parts:
        normalized_component = component.translate(IDNA_DOT_TRANSLATION)
        variants = {component, normalized_component}
        candidates.add(normalized_component)
        lowered_component = normalized_component.lower()
        if ".env." in lowered_component and not lowered_component.startswith(".env."):
            env_prefix = normalized_component[: lowered_component.index(".env.")]
            if env_prefix:
                variants.add(env_prefix)
                candidates.add(env_prefix)
        elif lowered_component.startswith(".env."):
            env_suffix = normalized_component[len(".env."):]
            if env_suffix:
                variants.add(env_suffix)
                candidates.add(env_suffix)
        candidate = normalized_component
        while "." in candidate:
            suffix = candidate.rsplit(".", 1)[1].lower()
            if suffix in {"example", "invalid", "test", "localhost"}:
                break
            candidate = candidate.rsplit(".", 1)[0]
            variants.add(candidate)
            candidates.add(candidate)
        component_candidates[component] = variants

    scan_text = "\n".join(sorted(candidates))
    for match in IPV4_RE.findall(scan_text):
        try:
            value = ipaddress.IPv4Address(match)
        except ipaddress.AddressValueError:
            categories.add("invalid IPv4-like identifier")
            continue
        if not allowed_v4(value):
            categories.add("non-documentation IPv4 identifier")

    for token in IPV6_TOKEN_RE.findall(scan_text):
        if token.count(":") < 2:
            continue
        try:
            value6 = ipaddress.IPv6Address(token.split("%", 1)[0])
        except ipaddress.AddressValueError:
            continue
        if not allowed_v6(value6):
            categories.add("non-documentation IPv6 identifier")

    uuid_masked_scan = UUID_RE.sub(" ", scan_text)
    compact_values = set(MAC_CONTEXTUAL_COMPACT_RE.findall(uuid_masked_scan))
    compact_values.update(MAC_CONTEXTUAL_TIGHT_RE.findall(uuid_masked_scan))
    if is_risk_shaped_path(path):
        compact_values.update(MAC_COMPACT_RE.findall(uuid_masked_scan))
        compact_values.update(MAC_HEX_COMPACT_RE.findall(uuid_masked_scan))
    mac_values = set(MAC_DELIMITED_RE.findall(scan_text)) | set(MAC_CISCO_RE.findall(scan_text)) | compact_values
    if any(not allowed_mac(value) for value in mac_values):
        categories.add("non-documentation MAC identifier")

    # Repeatedly remove filename extensions so `device.local.json.gz` is
    # checked as `device.local`; reserved public suffixes such as
    # `router.local.example` never become local-name candidates.
    for component in PurePosixPath(path).parts:
        if component == ".env":
            continue  # exact environment-file basename, not a hostname
        for candidate in component_candidates[component]:
            local_names = list(local_name_candidates(candidate))
            if any(
                not PURE_MDNS_SERVICE_RE.fullmatch(name)
                and not PLACEHOLDER_LOCAL_RE.fullmatch(name)
                for name in local_names
            ):
                categories.add("local/environment hostname identifier")
                break
    return categories


def display_path(path: str) -> str:
    if path_identifier_categories(path):
        # Never turn an Actions failure into a second disclosure. A per-run
        # ordinal has no reversible relationship to a low-entropy filename.
        if path not in OPAQUE_PATH_TOKENS:
            OPAQUE_PATH_TOKENS[path] = f"tracked-path#{len(OPAQUE_PATH_TOKENS) + 1}"
        token = OPAQUE_PATH_TOKENS[path]
        if SHOW_SENSITIVE_PATHS:
            raw = "".join(character if character.isprintable() else "?" for character in path)
            return f"{token} ({raw})"
        return token
    return "".join(character if character.isprintable() else "?" for character in path)


def is_data_file(path: str) -> bool:
    pure = PurePosixPath(path)
    parts = tuple(part.lower() for part in pure.parts)
    suffix = pure.suffix.lower()
    if path in CONTENT_SCAN_EXEMPT_FILES:
        return False
    if is_telemetry_export_source(path):
        return False
    if pure.name.lower() == ".env.example" or suffix in OPERATIONAL_SUFFIXES:
        return True
    if RISK_DATA_NAME_RE.search(pure.name) and suffix not in RISK_SOURCE_SUFFIXES:
        return True
    risky_parents = [
        part for part in parts[:-1]
        if RISK_DATA_NAME_RE.search(part) or is_forbidden_artifact(part) or is_forbidden_component(part)
    ]
    if risky_parents and (
        suffix not in RISK_SOURCE_SUFFIXES
        or any(is_forbidden_artifact(part) or is_forbidden_component(part) for part in risky_parents)
    ):
        return True
    if suffix in INSPECT_SUFFIXES:
        return True
    if any(is_data_component(part) for part in parts[:-1]):
        if path in SOURCE_FILE_EXEMPTIONS:
            return False
        return True
    return False


def is_recognized_binary_media(path: str, blob: bytes) -> bool:
    """Permit only exact reviewed media in explicit public/review asset paths."""
    pure = PurePosixPath(path)
    parts = tuple(part.lower() for part in pure.parts)
    lowered = path.lower()
    allowed_path = lowered.startswith(BINARY_MEDIA_PREFIXES) or (
        bool(parts)
        and parts[0] == "specs"
        and "assets" in parts[1:-1]
    )
    if not allowed_path:
        return False

    expected_digest = BINARY_MEDIA_SHA256.get(path)
    if expected_digest is None or hashlib.sha256(blob).hexdigest() != expected_digest:
        return False

    suffix = pure.suffix.lower()
    if suffix in IMAGE_MEDIA_SUFFIXES:
        return bool(
            blob.startswith(b"\x89PNG\r\n\x1a\n")
            or blob.startswith((b"GIF87a", b"GIF89a", b"\xff\xd8\xff"))
            or (len(blob) >= 12 and blob.startswith(b"RIFF") and blob[8:12] == b"WEBP")
            or blob.startswith(b"\x00\x00\x01\x00")
            or (len(blob) >= 12 and blob[4:12] in {b"ftypavif", b"ftypavis"})
        )
    if suffix in FONT_MEDIA_SUFFIXES:
        return bool(
            blob.startswith((b"wOFF", b"wOF2", b"OTTO", b"\x00\x01\x00\x00"))
        )
    if suffix in VIDEO_MEDIA_SUFFIXES:
        return bool(
            (suffix == ".mp4" and len(blob) >= 8 and blob[4:8] == b"ftyp")
            or (suffix == ".webm" and blob.startswith(b"\x1a\x45\xdf\xa3"))
        )
    return False


def has_binary_media_suffix(path: str) -> bool:
    suffix = PurePosixPath(path).suffix.lower()
    return suffix in BINARY_MEDIA_SUFFIXES


def is_reviewed_data_path(path: str) -> bool:
    parts = tuple(part.lower() for part in PurePosixPath(path).parts)
    if parts and parts[0] == "specs" and any(is_data_component(part) for part in parts):
        return True
    if any(is_data_component(part) for part in parts):
        return True
    return False


def has_extension_segment(name: str, suffix: str) -> bool:
    lowered = name.lower()
    return lowered.endswith(suffix) or f"{suffix}." in lowered


def is_forbidden_artifact(name: str) -> bool:
    return any(
        has_extension_segment(name, suffix)
        for suffix in FORBIDDEN_ARTIFACT_SUFFIXES + FORBIDDEN_ARCHIVE_SUFFIXES
    )


def allowed_v4(value: ipaddress.IPv4Address) -> bool:
    return (
        any(value in network for network in DOCUMENTATION_V4)
        or value.is_loopback
        or value.is_unspecified
        or value == ipaddress.ip_address("255.255.255.255")
        or value in STANDARD_MULTICAST_V4
    )


def allowed_v4_in_path(path: str, value: ipaddress.IPv4Address) -> bool:
    return allowed_v4(value) or value in PATH_V4_ALLOWLIST.get(path, set())


def allowed_v6(value: ipaddress.IPv6Address) -> bool:
    # Link-local/ULA values remain forbidden: they can contain a stable EUI-64
    # device identifier or disclose an operator's internal addressing scheme.
    return value in DOCUMENTATION_V6 or value.is_loopback or value.is_unspecified or value in STANDARD_MULTICAST_V6


def normalize_mac(value: str) -> str:
    return value.lower().replace(":", "").replace("-", "").replace(".", "")


def allowed_mac(value: str) -> bool:
    normalized = normalize_mac(value)
    # A locally administered MAC can still be a stable per-device identifier;
    # only standardized documentation/sentinel/multicast values are safe here.
    return (
        normalized.startswith("00005e0053")  # RFC 7042 documentation block
        or normalized.startswith("01005e")  # IPv4 multicast mapping
        or normalized.startswith("3333")  # IPv6 multicast mapping
        or normalized in {"000000000000", "ffffffffffff"}
    )


def local_name_candidates(contents: str) -> Iterable[str]:
    """Find private-suffix names in one linear pass, including Unicode labels."""
    suffixes = (".home.arpa", ".local", ".lan", ".home", ".internal", ".localdomain", ".corp")
    for match in LOCAL_TOKEN_RE.finditer(contents):
        token = match.group(0).translate(IDNA_DOT_TRANSLATION).rstrip(".")
        lowered = token.lower()
        suffix = next((candidate for candidate in suffixes if lowered.endswith(candidate)), "")
        if not suffix or len(lowered) <= len(suffix):
            continue
        # Safe exceptions apply only to the complete maximal token. Checking a
        # short suffix would let an identifying instance label ride in front of
        # an otherwise safe mDNS service or placeholder name.
        if (
            PURE_MDNS_SERVICE_RE.fullmatch(token)
            or PLACEHOLDER_LOCAL_RE.fullmatch(token)
            or LOCAL_WILDCARD_RE.fullmatch(token)
        ):
            continue
        yield token[-253:]


def line_number(contents: str, value: str) -> int:
    offset = contents.find(value)
    return contents.count("\n", 0, max(offset, 0)) + 1


def diagnostic(path: str, line: int, category: str) -> str:
    return f"{display_path(path)}:{line}: {category} (value redacted)"


def validate_host(
    path: str,
    contents: str,
    value: str,
    *,
    allow_public: bool = False,
    allow_pattern: bool = False,
) -> list[str]:
    candidate = value.strip().strip("[]").translate(IDNA_DOT_TRANSLATION).rstrip(".")
    if not candidate:
        return []
    try:
        address = ipaddress.ip_address(candidate.split("%", 1)[0])
    except ValueError:
        address = None
    if address is not None:
        return []  # The IP scanners report unsafe address values with better context.
    if TEMPLATE_HOST_RE.fullmatch(candidate):
        return []  # A complete configuration expression, not concrete data.
    if (
        allow_public
        and allow_pattern
        and re.search(r"[%_]", candidate)
        and re.fullmatch(r"[a-zA-Z0-9%_.-]+", candidate)
    ):
        return []  # SQL LIKE/GLOB domain pattern, not a concrete device name.

    lowered = candidate.lower()
    if not re.search(r"[a-z0-9]", lowered):
        return []  # SQL formatting/punctuation literal, not an identifier.
    if lowered in {"localhost", "placeholder"}:
        return []
    if PURE_MDNS_SERVICE_RE.fullmatch(lowered) or PLACEHOLDER_LOCAL_RE.fullmatch(lowered):
        return []
    synthetic_mac_domain = re.fullmatch(
        r"(?i)((?:[0-9a-f]{2}:){5}[0-9a-f]{2})\.([a-z0-9.-]+\.(?:example|invalid|test|localhost))",
        lowered,
    )
    if synthetic_mac_domain and allowed_mac(synthetic_mac_domain.group(1)) and DNS_NAME_RE.fullmatch(
        synthetic_mac_domain.group(2)
    ):
        return []  # Deliberately invalid, but documentation-only contract fixture.
    if not DNS_NAME_RE.fullmatch(lowered):
        return [diagnostic(path, line_number(contents, value), "invalid/composite hostname data value")]
    if lowered.endswith((".example", ".invalid", ".test", ".localhost")):
        return []
    local_suffixes = (".local", ".lan", ".home", ".home.arpa", ".internal", ".localdomain", ".corp")
    if "." not in lowered or lowered.endswith(local_suffixes) or not allow_public:
        return [diagnostic(path, line_number(contents, value), "local/environment hostname data value")]
    return []  # A multi-label public DNS name is not a local device identifier.


def inventory_note_host_candidates(value: str) -> Iterable[str]:
    """Find explicit or standalone hostname-shaped identifiers in note fields."""
    candidate = value.strip().strip("\"'").translate(IDNA_DOT_TRANSLATION).rstrip(".")
    if DNS_NAME_RE.fullmatch(candidate):
        yield candidate
    labeled = re.compile(
        r'''(?i)(?<![a-z0-9_])(?:device[_ -]?name|host(?:name)?|name)\s*[:=]\s*'''
        r'''["']?([a-z0-9][a-z0-9_.-]{0,252})["']?(?![a-z0-9_.-])'''
    )
    for match in labeled.finditer(value.translate(IDNA_DOT_TRANSLATION)):
        yield match.group(1).rstrip(".")
    tokenized = value.translate(IDNA_DOT_TRANSLATION)
    for match in re.finditer(
        r"(?i)(?<![a-z0-9_.-])([a-z0-9](?:[a-z0-9_.-]{0,251}[a-z0-9])?)(?![a-z0-9_.-])",
        tokenized,
    ):
        token = match.group(1).rstrip(".")
        if re.search(r"[-_.0-9]", token):
            yield token


def validate_typed_ip(path: str, contents: str, value: str) -> list[str]:
    candidate = value.strip().strip("[]")
    if not candidate or TEMPLATE_HOST_RE.fullmatch(candidate):
        return []
    try:
        address = ipaddress.ip_address(candidate.split("%", 1)[0])
    except ValueError:
        return [diagnostic(path, line_number(contents, value), "non-canonical IP data value")]
    if isinstance(address, ipaddress.IPv4Address):
        if not allowed_v4_in_path(path, address):
            return [diagnostic(path, line_number(contents, value), "non-documentation IPv4 data value")]
    elif not allowed_v6(address):
        return [diagnostic(path, line_number(contents, value), "non-documentation IPv6 data value")]
    return []


def validate_typed_mac(path: str, contents: str, value: str) -> list[str]:
    candidate = value.strip()
    if not candidate or TEMPLATE_HOST_RE.fullmatch(candidate):
        return []
    # Decimal integer MACs are non-canonical and can encode all 48 bits while
    # evading every textual MAC pattern.
    if re.fullmatch(r"[0-9]+", candidate) and len(candidate) != 12:
        return [diagnostic(path, line_number(contents, value), "non-canonical MAC data value")]
    compact = re.sub(r"[:.\-_\s]", "", candidate)
    if not re.fullmatch(r"(?i)[0-9a-f]{12}", compact):
        return [diagnostic(path, line_number(contents, value), "non-canonical MAC data value")]
    if not allowed_mac(compact):
        return [diagnostic(path, line_number(contents, value), "non-documentation MAC data value")]
    return []


def sql_statements(contents: str) -> Iterable[tuple[str, int]]:
    """Split SQLite statements without treating quoted/comment semicolons as terminators."""
    state = "normal"
    start = 0
    index = 0
    while index < len(contents):
        character = contents[index]
        following = contents[index + 1] if index + 1 < len(contents) else ""
        if state == "line-comment":
            if character == "\n":
                state = "normal"
        elif state == "block-comment":
            if character == "*" and following == "/":
                state = "normal"
                index += 1
        elif state == "bracket":
            if character == "]":
                state = "normal"
        elif state in {"'", '"', "`"}:
            if character == state:
                if following == state:
                    index += 1
                else:
                    state = "normal"
        elif character == "-" and following == "-":
            state = "line-comment"
            index += 1
        elif character == "/" and following == "*":
            state = "block-comment"
            index += 1
        elif character in {"'", '"', "`"}:
            state = character
        elif character == "[":
            state = "bracket"
        elif character == ";":
            yield contents[start:index], start
            start = index + 1
        index += 1
    if contents[start:].strip():
        yield contents[start:], start


def sql_lexing_failure(contents: str) -> str | None:
    """Reject unterminated SQL lexical states before any contextual parsing."""
    state = "normal"
    index = 0
    while index < len(contents):
        character = contents[index]
        following = contents[index + 1] if index + 1 < len(contents) else ""
        if state == "line-comment":
            if character == "\n":
                state = "normal"
        elif state == "block-comment":
            if character == "*" and following == "/":
                state = "normal"
                index += 1
        elif state == "bracket":
            if character == "]":
                state = "normal"
        elif state in {"'", '"', "`"}:
            if character == state:
                if following == state:
                    index += 1
                else:
                    state = "normal"
        elif character == "-" and following == "-":
            state = "line-comment"
            index += 1
        elif character == "/" and following == "*":
            state = "block-comment"
            index += 1
        elif character in {"'", '"', "`"}:
            state = character
        elif character == "[":
            state = "bracket"
        index += 1
    if state in {"block-comment", "bracket", "'", '"', "`"}:
        return "SQL contains an unterminated quote, identifier, or block comment"
    return None


def sql_quoted_region_count(contents: str) -> int:
    """Count quoted literals/identifiers while ignoring delimiters in comments."""
    state = "normal"
    regions = 0
    index = 0
    while index < len(contents):
        character = contents[index]
        following = contents[index + 1] if index + 1 < len(contents) else ""
        if state == "line-comment":
            if character == "\n":
                state = "normal"
        elif state == "block-comment":
            if character == "*" and following == "/":
                state = "normal"
                index += 1
        elif state == "bracket":
            if character == "]":
                state = "normal"
        elif state in {"'", '"', "`"}:
            if character == state:
                if following == state:
                    index += 1
                else:
                    state = "normal"
        elif character == "-" and following == "-":
            state = "line-comment"
            index += 1
        elif character == "/" and following == "*":
            state = "block-comment"
            index += 1
        elif character in {"'", '"', "`"}:
            regions += 1
            state = character
        elif character == "[":
            regions += 1
            state = "bracket"
        index += 1
    return regions


def sql_comment_texts(contents: str) -> Iterable[str]:
    """Yield comments with a single linear pass over lexically valid SQL."""
    state = "normal"
    index = 0
    while index < len(contents):
        character = contents[index]
        following = contents[index + 1] if index + 1 < len(contents) else ""
        if state in {"'", '"', "`"}:
            if character == state:
                if following == state:
                    index += 2
                    continue
                state = "normal"
            index += 1
            continue
        if state == "bracket":
            if character == "]":
                state = "normal"
            index += 1
            continue
        if character in {"'", '"', "`"}:
            state = character
            index += 1
            continue
        if character == "[":
            state = "bracket"
            index += 1
            continue
        if character == "-" and following == "-":
            end = contents.find("\n", index + 2)
            if end < 0:
                end = len(contents)
            yield contents[index:end]
            index = end
            continue
        if character == "/" and following == "*":
            end = contents.find("*/", index + 2)
            if end < 0:
                return
            yield contents[index:end + 2]
            index = end + 2
            continue
        index += 1


def strip_sql_comments(statement: str) -> str:
    output = list(statement)
    state = "normal"
    index = 0
    while index < len(statement):
        character = statement[index]
        following = statement[index + 1] if index + 1 < len(statement) else ""
        if state == "line-comment":
            if character == "\n":
                state = "normal"
            else:
                output[index] = " "
        elif state == "block-comment":
            output[index] = " "
            if character == "*" and following == "/":
                output[index + 1] = " "
                state = "normal"
                index += 1
        elif state == "bracket":
            if character == "]":
                state = "normal"
        elif state in {"'", '"', "`"}:
            if character == state:
                if following == state:
                    index += 1
                else:
                    state = "normal"
        elif character == "-" and following == "-":
            output[index] = output[index + 1] = " "
            state = "line-comment"
            index += 1
        elif character == "/" and following == "*":
            output[index] = output[index + 1] = " "
            state = "block-comment"
            index += 1
        elif character in {"'", '"', "`"}:
            state = character
        elif character == "[":
            state = "bracket"
        index += 1
    return "".join(output)


def mask_sql_quoted(statement: str) -> str:
    """Blank quoted regions while retaining offsets for keyword location."""
    output = list(statement)
    state = "normal"
    index = 0
    while index < len(statement):
        character = statement[index]
        following = statement[index + 1] if index + 1 < len(statement) else ""
        if state == "bracket":
            output[index] = " "
            if character == "]":
                state = "normal"
        elif state in {"'", '"', "`"}:
            output[index] = " "
            if character == state:
                if following == state:
                    output[index + 1] = " "
                    index += 1
                else:
                    state = "normal"
        elif character in {"'", '"', "`"}:
            output[index] = " "
            state = character
        elif character == "[":
            output[index] = " "
            state = "bracket"
        index += 1
    return "".join(output)


def sql_row_slices(rows: str, base_offset: int) -> Iterable[tuple[str, int]]:
    """Yield top-level SQL VALUES row bodies and their absolute offsets."""
    index = 0
    while index < len(rows):
        while index < len(rows) and rows[index].isspace():
            index += 1
        if index >= len(rows) or rows[index] != "(":
            return
        row_start = index + 1
        depth = 1
        quote = ""
        index += 1
        while index < len(rows) and depth:
            character = rows[index]
            if quote:
                if character == quote:
                    if index + 1 < len(rows) and rows[index + 1] == quote:
                        index += 2
                        continue
                    quote = ""
            elif character in {"'", '"'}:
                quote = character
            elif character == "(":
                depth += 1
            elif character == ")":
                depth -= 1
                if depth == 0:
                    yield rows[row_start:index], base_offset + row_start
            index += 1
        if depth:
            return
        while index < len(rows) and rows[index].isspace():
            index += 1
        if index >= len(rows) or rows[index] != ",":
            return  # ON CONFLICT/RETURNING belongs to the statement, not a row.
        index += 1


def sql_field_slices(row: str, base_offset: int) -> Iterable[tuple[str, int]]:
    quote = ""
    depth = 0
    field_start = 0
    index = 0
    while index <= len(row):
        character = row[index] if index < len(row) else ","
        if quote:
            if character == quote:
                if index + 1 < len(row) and row[index + 1] == quote:
                    index += 2
                    continue
                quote = ""
        elif character in {"'", '"'}:
            quote = character
        elif character == "(":
            depth += 1
        elif character == ")" and depth:
            depth -= 1
        elif character == "," and depth == 0:
            raw = row[field_start:index]
            leading = len(raw) - len(raw.lstrip())
            yield raw.strip(), base_offset + field_start + leading
            field_start = index + 1
        index += 1


def sql_scalar(token: str, offset: int) -> tuple[str, int, int]:
    blob = re.fullmatch(r"(?is)x'([0-9a-f]*)'", token)
    if blob:
        return blob.group(1), offset + 2, offset + len(token) - 1
    if len(token) >= 2 and token[0] in {"'", '"'} and token[-1] == token[0]:
        quote = token[0]
        raw = token[1:-1]
        return raw.replace(quote * 2, quote), offset + 1, offset + len(token) - 1
    return token, offset, offset + len(token)


def sql_literal_values(token: str, offset: int) -> list[tuple[str, int, int]]:
    values: list[tuple[str, int, int]] = []
    index = 0
    while index < len(token):
        quote = token[index]
        if quote not in {"'", '"'}:
            if quote == "`":
                end = index + 1
                while end < len(token):
                    if token[end] == "`":
                        if end + 1 < len(token) and token[end + 1] == "`":
                            end += 2
                            continue
                        end += 1
                        break
                    end += 1
                index = end
                continue
            if quote == "[":
                end = token.find("]", index + 1)
                index = len(token) if end < 0 else end + 1
                continue
            index += 1
            continue

        is_blob = (
            quote == "'"
            and index > 0
            and token[index - 1] in {"x", "X"}
            and (index < 2 or not (token[index - 2].isalnum() or token[index - 2] == "_"))
        )
        content_start = index + 1
        cursor = content_start
        decoded: list[str] = []
        while cursor < len(token):
            character = token[cursor]
            if character == quote:
                if cursor + 1 < len(token) and token[cursor + 1] == quote:
                    decoded.append(quote)
                    cursor += 2
                    continue
                break
            decoded.append(character)
            cursor += 1
        if cursor >= len(token):
            break
        value = "".join(decoded)
        if is_blob and not re.fullmatch(r"(?i)[0-9a-f]*", value):
            is_blob = False
        if is_blob:
            try:
                value = bytes.fromhex(value).decode("utf-8")
            except (UnicodeDecodeError, ValueError):
                pass
        values.append((value, offset + content_start, offset + cursor))
        index = cursor + 1
    return values


def strip_sql_outer_parentheses(token: str, offset: int = 0) -> tuple[str, int]:
    """Remove only balanced parentheses that enclose the complete expression."""
    masked = mask_sql_quoted(token)
    stack: list[int] = []
    pairs: dict[int, int] = {}
    for index, character in enumerate(masked):
        if character == "(":
            stack.append(index)
        elif character == ")" and stack:
            pairs[stack.pop()] = index

    left = 0
    right = len(token)
    while left < right and token[left].isspace():
        left += 1
    while right > left and token[right - 1].isspace():
        right -= 1
    while left < right and token[left] == "(" and pairs.get(left) == right - 1:
        left += 1
        right -= 1
        while left < right and token[left].isspace():
            left += 1
        while right > left and token[right - 1].isspace():
            right -= 1
    return token[left:right], offset + left


def sql_static_text(token: str, offset: int = 0) -> tuple[str, int, int] | None:
    """Evaluate a bounded expression made solely from literals and `||`."""
    token, offset = strip_sql_outer_parentheses(token, offset)
    if not SQL_LITERAL_CONCAT_RE.fullmatch(token):
        return None
    values = sql_literal_values(token, offset)
    if not values:
        return None
    decoded_length = sum(len(value.encode("utf-8")) for value, _start, _end in values)
    if decoded_length > MAX_SQL_STATIC_BYTES:
        return None
    return "".join(value for value, _start, _end in values), values[0][1], values[-1][2]


def sql_token_values(token: str, offset: int) -> list[tuple[str, int, int]]:
    values = sql_literal_values(token, offset)
    # Evaluate only an expression that is entirely a literal `||` chain. This
    # is linear in the input size. Arbitrary SQL functions are rejected below
    # when they populate an identifier-typed field; trying every literal
    # combination is both unsound and an attacker-controlled memory sink.
    static = sql_static_text(token, offset)
    if static is not None and static not in values:
        values.append(static)
    return list(dict.fromkeys(values))


def sql_identifier_tokens(text: str) -> list[tuple[str, str, int, int, bool]]:
    """Lex SQL identifiers without treating single-quoted values as names."""
    cleaned = strip_sql_comments(text)
    tokens: list[tuple[str, str, int, int, bool]] = []
    index = 0
    while index < len(cleaned):
        character = cleaned[index]
        if character == "'":
            index += 1
            while index < len(cleaned):
                if cleaned[index] == "'":
                    if index + 1 < len(cleaned) and cleaned[index + 1] == "'":
                        index += 2
                        continue
                    index += 1
                    break
                index += 1
            continue
        if character in {'"', "`", "["}:
            closing = "]" if character == "[" else character
            start = index
            index += 1
            while index < len(cleaned):
                if cleaned[index] == closing:
                    if closing != "]" and index + 1 < len(cleaned) and cleaned[index + 1] == closing:
                        index += 2
                        continue
                    index += 1
                    break
                index += 1
            raw = cleaned[start:index]
            normalized = normalize_sql_identifier(raw)
            if normalized:
                tokens.append((raw, normalized, start, index, True))
            continue
        if character.isalpha() or character == "_":
            start = index
            index += 1
            while index < len(cleaned) and (cleaned[index].isalnum() or cleaned[index] == "_"):
                index += 1
            raw = cleaned[start:index]
            tokens.append((raw, raw.lower(), start, index, False))
            continue
        index += 1
    return tokens


def sql_function_calls(text: str) -> list[tuple[str, int, int, int, bool]]:
    """Return real/possible calls, including SQLite-quoted function names."""
    cleaned = strip_sql_comments(text)
    masked = mask_sql_quoted(cleaned)
    pairs: dict[int, int] = {}
    stack: list[int] = []
    for index, character in enumerate(masked):
        if character == "(":
            stack.append(index)
        elif character == ")" and stack:
            pairs[stack.pop()] = index

    calls: list[tuple[str, int, int, int, bool]] = []
    for _raw, name, start, end, quoted in sql_identifier_tokens(cleaned):
        cursor = end
        while cursor < len(cleaned) and cleaned[cursor].isspace():
            cursor += 1
        if cursor >= len(cleaned) or cleaned[cursor] != "(":
            continue
        if name == "as":
            continue  # CTE bodies use `name(columns) AS (`; AS is not a call.
        open_index = cursor
        close_index = pairs.get(open_index)
        prefix = masked[max(0, start - 256):start]
        suffix = masked[close_index + 1:close_index + 32] if close_index is not None else ""
        named_declaration = bool(
            re.search(
                r"(?is)(?:\bcreate\s+(?:temp(?:orary)?\s+)?(?:table|view)\s+"
                r"(?:if\s+not\s+exists\s+)?|\b(?:insert(?:\s+or\s+[a-z]+)?|replace)\s+into\s+)"
                r"(?:[a-z_][a-z0-9_]*\s*\.\s*)?$",
                prefix,
            )
            or re.search(
                r"(?is)\bcreate\s+(?:unique\s+)?index\b[^;]*\bon\s+"
                r"(?:[a-z_][a-z0-9_]*\s*\.\s*)?$",
                prefix,
            )
        )
        cte_column_declaration = close_index is not None and bool(
            re.match(r"(?is)^\s+as\s*\(", suffix)
        )
        if named_declaration or cte_column_declaration:
            continue
        calls.append((name, start, open_index, close_index if close_index is not None else len(cleaned), quoted))
    return calls


def sql_function_names(text: str) -> set[str]:
    return {name for name, _start, _open, _close, _quoted in sql_function_calls(text)}


def sql_has_literal_keyword(text: str) -> bool:
    masked = mask_sql_quoted(strip_sql_comments(text))
    return bool(
        re.search(r"(?i)\b(?:true|false|current_date|current_time|current_timestamp)\b", masked)
    )


def sql_has_arithmetic_synthesis(text: str) -> bool:
    masked = mask_sql_quoted(strip_sql_comments(text))
    if re.search(
        r"<<|>>|(?<!\|)\|(?!\|)|(?<![<>=!])[+/%~&](?![=])|(?<![-<>=!])-(?![->=])",
        masked,
    ):
        return True
    multiplication = re.compile(
        r"(?is)(\b[a-z_][a-z0-9_]*\b|\b\d+(?:\.\d+)?\b|\))\s*\*\s*"
        r"(\b[a-z_][a-z0-9_]*\b|\b\d+(?:\.\d+)?\b|\()"
    )
    return any(
        match.group(1).lower() not in {"all", "distinct", "select"}
        for match in multiplication.finditer(masked)
    )


def sql_has_literal_comparison_synthesis(text: str) -> bool:
    cleaned = strip_sql_comments(text)
    return bool(
        re.search(
            rf'''(?is){SQL_LITERAL_TOKEN}\s*(?:=|!=|<>|\bis\s+(?:not\s+)?|\blike\b|\bglob\b)\s*{SQL_LITERAL_TOKEN}''',
            cleaned,
        )
        or re.search(r"(?i)\bnull\s+is\s+(?:not\s+)?null\b", mask_sql_quoted(cleaned))
    )


def sql_expression_constructs_data(token: str) -> bool:
    """Whether a non-literal expression can synthesize fixture data.

    Literal values and complete literal concatenations are decoded and scanned
    directly. For all other expressions, fail closed in identifier-typed
    fields when a function/operator receives alphanumeric literal material or
    numeric constants (for example replace(), printf(), lower(), or char()).
    Structural copies and punctuation-only fallback expressions remain valid.
    """
    if sql_static_text(token) is not None or SQL_NUMERIC_LITERAL_RE.fullmatch(token):
        return False
    structural_functions = {"coalesce", "nullif"}
    if sql_function_names(token) - structural_functions:
        return True
    if (
        sql_has_literal_keyword(token)
        or sql_has_arithmetic_synthesis(token)
        or sql_has_literal_comparison_synthesis(token)
    ):
        return True
    if any(re.search(r"[a-z0-9]", value, re.IGNORECASE) for value, _start, _end in sql_literal_values(token, 0)):
        return True
    return bool(SQL_NUMERIC_TOKEN_RE.search(mask_sql_quoted(token)))


def sql_expression_has_data(token: str) -> bool:
    return bool(
        any(re.search(r"[a-z0-9]", value, re.IGNORECASE) for value, _start, _end in sql_literal_values(token, 0))
        or SQL_NUMERIC_TOKEN_RE.search(mask_sql_quoted(token))
    )


def sql_typed_expression_unsafe(token: str, effective_key: str) -> bool:
    numeric_identity = bool(SQL_NUMERIC_LITERAL_RE.fullmatch(token)) and effective_key not in VERSION_KEYS
    blob_identity = bool(re.search(r"(?i)(?<![a-z0-9_])x'[0-9a-f]*'", token))
    return numeric_identity or blob_identity or sql_expression_constructs_data(token)


def top_level_sql_keyword(text: str, keyword: str) -> int | None:
    masked = mask_sql_quoted(text)
    depth = 0
    pattern = re.compile(rf"(?i)\b{re.escape(keyword)}\b")
    matches = iter(pattern.finditer(masked))
    next_match = next(matches, None)
    for index, character in enumerate(masked):
        if character == "(":
            depth += 1
        elif character == ")" and depth:
            depth -= 1
        while next_match is not None and next_match.start() == index:
            if depth == 0:
                return index
            next_match = next(matches, None)
    return None


def top_level_sql_operator(text: str, operator: str) -> int | None:
    masked = mask_sql_quoted(text)
    depth = 0
    for index, character in enumerate(masked):
        if character == "(":
            depth += 1
        elif character == ")" and depth:
            depth -= 1
        elif character == operator and depth == 0:
            return index
    return None


def normalize_structured_key(value: Any) -> str:
    candidate = str(value).strip().lstrip("\ufeff")
    # Normalize common external-schema styles before assigning identity type:
    # `deviceHostname`, `Device Hostname`, and `device-hostname` must be the
    # same field for both duplicate detection and value inspection.
    candidate = re.sub(r"([A-Z]+)([A-Z][a-z])", r"\1_\2", candidate)
    candidate = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", candidate)
    candidate = re.sub(r"[^A-Za-z0-9]+", "_", candidate).strip("_").lower()
    return STRUCTURED_KEY_ALIASES.get(candidate, candidate)


def normalize_sql_identifier(raw: str, *, allow_single_quoted: bool = False) -> str:
    candidate = raw.strip().rsplit(".", 1)[-1].strip()
    quoted_pairs = {("`", "`"), ('"', '"'), ("[", "]")}
    if allow_single_quoted:
        quoted_pairs.add(("'", "'"))
    if len(candidate) >= 2 and (candidate[0], candidate[-1]) in quoted_pairs:
        candidate = candidate[1:-1].strip()
    if not re.fullmatch(r"(?i)[a-z_][a-z0-9_]*", candidate):
        return ""
    return candidate.lower()


def canonical_sql_typed_key(raw: str) -> str:
    candidate = normalize_structured_key(raw)
    if candidate in TYPED_ATTRIBUTE_KEYS:
        return candidate
    for suffix, canonical in (
        ("_host_name", "hostname"),
        ("_hostname", "hostname"),
        ("_host", "hostname"),
        ("_mac_address", "mac"),
        ("_mac", "mac"),
        ("_ip_address", "ip"),
        ("_ip", "ip"),
        ("_firmware_version", "firmware_version"),
        ("_hardware_revision", "hardware_revision"),
        ("_version", "version"),
    ):
        if candidate.endswith(suffix):
            return canonical
    return ""


def sql_top_level_parts(text: str, keyword: str, base_offset: int) -> list[tuple[str, int]]:
    text, base_offset = strip_sql_outer_parentheses(text, base_offset)
    masked = mask_sql_quoted(text)
    matches: list[tuple[int, int]] = []
    depth = 0
    pattern = re.compile(rf"(?i)\b{re.escape(keyword)}\b")
    candidates = {match.start(): match.end() for match in pattern.finditer(masked)}
    for index, character in enumerate(masked):
        if character == "(":
            depth += 1
        elif character == ")" and depth:
            depth -= 1
        elif depth == 0 and index in candidates:
            matches.append((index, candidates[index]))
    if not matches:
        return [(text, base_offset)]
    parts: list[tuple[str, int]] = []
    start = 0
    for match_start, match_end in matches:
        raw = text[start:match_start]
        leading = len(raw) - len(raw.lstrip())
        parts.append((raw.strip(), base_offset + start + leading))
        start = match_end
    raw = text[start:]
    leading = len(raw) - len(raw.lstrip())
    parts.append((raw.strip(), base_offset + start + leading))
    return parts


def sql_where_attribute_context(
    where: str, base_offset: int
) -> tuple[str, bool, list[tuple[int, str]]]:
    """Resolve an AND-only exact EAV attribute predicate conservatively."""
    failures: list[tuple[int, str]] = []
    has_attribute = bool(SQL_ATTRIBUTE_IDENTIFIER_RE.search(where))
    if not has_attribute:
        return "", False, failures

    masked = mask_sql_quoted(where)
    if re.search(r"(?i)\b(?:or|not)\b", masked):
        failures.append((base_offset, "SQL EAV attribute predicate cannot be mapped safely"))
        return "", True, failures

    attributes: set[str] = set()
    comparisons = 0
    for clause, clause_offset in sql_top_level_parts(where, "and", base_offset):
        clause, clause_offset = strip_sql_outer_parentheses(clause, clause_offset)
        equals = top_level_sql_operator(clause, "=")
        if equals is None:
            if SQL_ATTRIBUTE_IDENTIFIER_RE.search(clause):
                failures.append((clause_offset, "SQL EAV attribute predicate cannot be mapped safely"))
            continue
        left = clause[:equals].strip()
        right = clause[equals + 1:].strip()
        left_is_attribute = normalize_sql_identifier(left) == "attribute"
        right_is_attribute = normalize_sql_identifier(right) == "attribute"
        if not left_is_attribute and not right_is_attribute:
            if SQL_ATTRIBUTE_IDENTIFIER_RE.search(clause):
                failures.append((clause_offset, "SQL EAV attribute predicate cannot be mapped safely"))
            continue
        if left_is_attribute == right_is_attribute:
            failures.append((clause_offset, "SQL EAV attribute predicate cannot be mapped safely"))
            continue
        expression = right if left_is_attribute else left
        expression_offset = clause_offset + (clause.find(expression) if expression else 0)
        static = sql_static_text(expression, expression_offset)
        if static is None:
            failures.append((expression_offset, "SQL EAV attribute predicate cannot be mapped safely"))
            continue
        comparisons += 1
        attributes.add(canonical_sql_typed_key(static[0]))

    if comparisons != 1 or len(attributes) != 1:
        failures.append((base_offset, "SQL EAV attribute predicate is ambiguous"))
        return "", True, failures
    return next(iter(attributes)), True, failures


def validate_sql_field_expressions(
    fields: list[tuple[str, str, int]],
    failures: list[tuple[int, str]],
    *,
    where_attribute: str = "",
    has_where_attribute: bool = False,
) -> dict[str, str]:
    """Fail closed for constructed identity values and ambiguous EAV rows."""
    contexts: dict[str, str] = {}
    type_fields_present: set[str] = set()
    if has_where_attribute and where_attribute:
        for value_key in RELATIONAL_TYPE_VALUE_KEYS["attribute"]:
            contexts[value_key] = where_attribute

    for type_key, value_keys in RELATIONAL_TYPE_VALUE_KEYS.items():
        type_fields = [(token, offset) for column, token, offset in fields if column == type_key]
        if not type_fields:
            continue
        type_fields_present.add(type_key)
        resolved: set[str] = set()
        for token, token_offset in type_fields:
            static = sql_static_text(token, token_offset)
            if static is None:
                if sql_expression_has_data(token) or sql_has_data_constructor(token):
                    failures.append((token_offset, f"SQL relational {type_key} expression cannot be sanitized safely"))
                continue
            resolved.add(canonical_sql_typed_key(static[0]))
        if len(resolved) != 1:
            failures.append((type_fields[0][1], f"SQL relational {type_key} expression is ambiguous"))
        else:
            resolved_key = next(iter(resolved))
            if resolved_key:
                for value_key in value_keys:
                    contexts[value_key] = resolved_key

    for column, token, token_offset in fields:
        if column in RELATIONAL_TYPE_VALUE_KEYS:
            continue
        effective_key = canonical_sql_typed_key(column)
        if column in contexts:
            effective_key = contexts[column]
        elif any(column in RELATIONAL_TYPE_VALUE_KEYS[type_key] for type_key in type_fields_present):
            if sql_expression_has_data(token) or sql_has_data_constructor(token):
                failures.append((token_offset, "SQL relational value cannot be mapped to one typed field safely"))
                continue
        if effective_key:
            if sql_typed_expression_unsafe(token, effective_key):
                failures.append((token_offset, f"SQL {effective_key} expression cannot be sanitized safely"))
    return contexts


def relational_typed_entries(
    row: Iterable[tuple[str, str]],
) -> Iterable[tuple[int, str, str]]:
    """Yield the exact value occurrence consumed by each unambiguous relation."""
    materialized = list(row)
    for type_key, value_keys in RELATIONAL_TYPE_VALUE_KEYS.items():
        types = {
            canonical_sql_typed_key(value)
            for key, value in materialized
            if key == type_key and canonical_sql_typed_key(value)
        }
        if len(types) != 1:
            continue
        resolved_type = next(iter(types))
        for index, (key, value) in enumerate(materialized):
            if key in value_keys:
                yield index, resolved_type, value


def relational_typed_pairs(row: Iterable[tuple[str, str]]) -> Iterable[tuple[str, str]]:
    for _index, resolved_type, value in relational_typed_entries(row):
        yield resolved_type, value


def relational_sequence_entries(
    row: Iterable[tuple[str, str]],
) -> Iterable[tuple[int, str, str]]:
    active: dict[str, str] = {}
    for index, (key, value) in enumerate(row):
        if key in RELATIONAL_TYPE_VALUE_KEYS:
            active[key] = canonical_sql_typed_key(value)
            continue
        for type_key, value_keys in RELATIONAL_TYPE_VALUE_KEYS.items():
            if key in value_keys and active.get(type_key):
                yield index, active[type_key], value


def relational_sequence_pairs(row: Iterable[tuple[str, str]]) -> Iterable[tuple[str, str]]:
    for _index, resolved_type, value in relational_sequence_entries(row):
        yield resolved_type, value


def add_relational_typed_values(
    values: list[tuple[str, str, int, int]],
    mapped_row: list[tuple[str, str, int, int]],
    contexts: dict[str, str],
) -> set[str]:
    mapped_columns: set[str] = set()
    for key, value, value_start, value_end in mapped_row:
        if key in contexts:
            values.append((contexts[key], value, value_start, value_end))
            mapped_columns.add(key)
    return mapped_columns


def analyze_sql(
    contents: str, path: str = ""
) -> tuple[list[tuple[str, str, int, int]], list[tuple[int, str]]]:
    """Map typed DML values or fail closed when a VALUES statement is ambiguous."""
    values: list[tuple[str, str, int, int]] = []
    failures: list[tuple[int, str]] = []
    if len(contents.encode("utf-8")) > MAX_SQL_BYTES:
        return values, [(0, "SQL exceeds the safe parser byte limit")]
    if (reason := sql_lexing_failure(contents)) is not None:
        return values, [(0, reason)]
    masked_for_limits = mask_sql_quoted(strip_sql_comments(contents))
    if masked_for_limits.count(";") > MAX_SQL_STATEMENTS:
        return values, [(0, "SQL contains too many statements to sanitize safely")]
    if sql_quoted_region_count(contents) * 2 > MAX_SQL_LITERAL_MARKS:
        return values, [(0, "SQL contains too many literal delimiters to sanitize safely")]
    if masked_for_limits.count("(") + masked_for_limits.count(")") > MAX_SQL_PARENTHESIS_MARKS:
        return values, [(0, "SQL contains too many parentheses to sanitize safely")]
    if masked_for_limits.count(",") > MAX_SQL_FIELD_MARKS:
        return values, [(0, "SQL contains too many fields to sanitize safely")]
    if sum(1 for _match in re.finditer(r"(?i)\b(?:and|or)\b", masked_for_limits)) > MAX_SQL_BOOLEAN_OPERATORS:
        return values, [(0, "SQL contains too many boolean operators to sanitize safely")]
    if sum(
        1
        for _match in re.finditer(
            r"(?i)\b(?:select|join|on|having)\b", masked_for_limits
        )
    ) > MAX_SQL_QUERY_KEYWORDS:
        return values, [(0, "SQL contains too many query keywords to sanitize safely")]
    if policy_failures := sql_role_policy_failures(path, contents):
        return values, policy_failures
    locator = re.compile(r"(?is)\b(?:insert(?:\s+or\s+[a-z]+)?|replace)\s+into\b")

    for statement, statement_offset in sql_statements(contents):
        cleaned = strip_sql_comments(statement)
        masked = mask_sql_quoted(cleaned)
        location = locator.search(masked)
        if not location:
            continue
        prefix = cleaned[: location.start()]
        if sql_expression_has_data(prefix) or sql_has_data_constructor(prefix):
            failures.append(
                (statement_offset, "SQL literals before INSERT/REPLACE cannot be mapped safely")
            )
            continue
        failure_offset = statement_offset + location.start()
        tail = cleaned[location.start():]
        masked_tail = masked[location.start():]
        if not re.search(r"(?i)\bvalues\b", masked_tail):
            select_match = SQL_DML_SELECT_RE.match(tail)
            if not select_match:
                if sql_expression_has_data(tail) or sql_has_data_constructor(tail):
                    failures.append((failure_offset, "SQL INSERT/REPLACE literals could not be mapped safely"))
                continue  # Literal-free structural copy DML carries no fixture values.
            columns_text = select_match.group("columns")
            projection = select_match.group("projection")
            from_offset = top_level_sql_keyword(projection, "from")
            if from_offset is not None:
                source_expression = projection[from_offset:]
                if sql_expression_has_data(source_expression) or sql_has_data_constructor(source_expression):
                    failures.append((failure_offset, "SQL INSERT SELECT source cannot be sanitized safely"))
                    continue
                projection = projection[:from_offset]
            projection_offset = statement_offset + location.start() + select_match.start("projection")
            projection_fields = list(sql_field_slices(projection, projection_offset))
            has_data = any(
                sql_expression_has_data(token) or sql_has_data_constructor(token)
                for token, _token_offset in projection_fields
            )
            if not has_data:
                continue
            if not columns_text:
                failures.append((failure_offset, "SQL INSERT SELECT literals must name target columns"))
                continue
            columns = [
                normalize_sql_identifier(column, allow_single_quoted=True)
                for column in columns_text.split(",")
            ]
            if not all(columns):
                failures.append((failure_offset, "SQL INSERT SELECT columns could not be mapped safely"))
                continue
            if len(projection_fields) != len(columns):
                failures.append((failure_offset, "SQL INSERT SELECT literals could not be mapped safely"))
                continue
            mapped_row: list[tuple[str, str, int, int]] = []
            expression_fields: list[tuple[str, str, int]] = []
            for column, (token, token_offset) in zip(columns, projection_fields):
                expression_fields.append((column, token, token_offset))
                for value, value_start, value_end in sql_token_values(token, token_offset):
                    mapped_row.append((column, value, value_start, value_end))
            contexts = validate_sql_field_expressions(expression_fields, failures)
            relational_columns = add_relational_typed_values(values, mapped_row, contexts)
            values.extend(
                item for item in mapped_row if item[0] not in relational_columns
            )
            continue
        if re.search(r"(?i)\bdefault\s+values\b", masked_tail):
            continue
        match = SQL_DML_VALUES_RE.match(tail)
        if not match:
            failures.append((failure_offset, "SQL VALUES statement could not be sanitized safely"))
            continue
        columns_text = match.group("columns")
        if not columns_text:
            failures.append((failure_offset, "SQL VALUES inserts must name columns for sanitation"))
            continue
        columns = [
            normalize_sql_identifier(column, allow_single_quoted=True)
            for column in columns_text.split(",")
        ]
        if not all(columns):
            failures.append((failure_offset, "SQL VALUES columns could not be mapped safely"))
            continue
        rows_text = match.group("rows")
        rows_offset = statement_offset + location.start() + match.start("rows")
        upsert_index = top_level_sql_keyword(rows_text, "on")
        if upsert_index is not None and re.match(r"(?is)on\s+conflict\b", rows_text[upsert_index:].lstrip()):
            upsert = rows_text[upsert_index:]
            if sql_expression_has_data(upsert) or sql_has_data_constructor(upsert):
                failures.append((rows_offset + upsert_index, "SQL UPSERT tail cannot be sanitized safely"))
            rows_text = rows_text[:upsert_index]
        rows = list(sql_row_slices(rows_text, rows_offset))
        if not rows:
            failures.append((failure_offset, "SQL VALUES rows could not be sanitized safely"))
            continue
        statement_failed = False
        for row, row_offset in rows:
            fields = list(sql_field_slices(row, row_offset))
            if len(fields) != len(columns):
                failures.append((failure_offset, "SQL VALUES columns and fields could not be mapped safely"))
                statement_failed = True
                break
            mapped_row: list[tuple[str, str, int, int]] = []
            expression_fields: list[tuple[str, str, int]] = []
            for column, (token, token_offset) in zip(columns, fields):
                expression_fields.append((column, token, token_offset))
                literals = sql_token_values(token, token_offset)
                if literals:
                    for value, value_start, value_end in literals:
                        mapped_row.append((column, value, value_start, value_end))
                else:
                    value, value_start, value_end = sql_scalar(token, token_offset)
                    mapped_row.append((column, value, value_start, value_end))
            contexts = validate_sql_field_expressions(expression_fields, failures)
            relational_columns = add_relational_typed_values(values, mapped_row, contexts)
            values.extend(
                item for item in mapped_row if item[0] not in relational_columns
            )
        if statement_failed:
            continue

    update_locator = re.compile(
        r"(?is)\bupdate(?:\s+or\s+[a-z]+)?\s+[a-z_][a-z0-9_.]*"
        r"(?:\s+(?:as\s+)?[a-z_][a-z0-9_]*)?\s+set\b"
    )
    for statement, statement_offset in sql_statements(contents):
        cleaned = strip_sql_comments(statement)
        masked = mask_sql_quoted(cleaned)
        update = update_locator.search(masked)
        if not update:
            if (
                re.search(r"(?is)\bupdate\b", masked)
                and (sql_expression_has_data(cleaned) or sql_has_data_constructor(cleaned))
                and (
                    re.match(r"(?is)^\s*(?:with|update)\b", masked)
                    or re.search(r"(?is)\bbegin\s+update\b", masked)
                )
            ):
                failures.append((statement_offset, "SQL UPDATE literals cannot be mapped safely"))
            continue
        prefix = cleaned[: update.start()]
        if sql_expression_has_data(prefix) or sql_has_data_constructor(prefix):
            failures.append((statement_offset, "SQL literals before UPDATE cannot be mapped safely"))
            continue
        tail = cleaned[update.start():]
        set_index = top_level_sql_keyword(tail, "set")
        if set_index is None:
            if sql_expression_has_data(tail) or sql_has_data_constructor(tail):
                failures.append((statement_offset + update.start(), "SQL UPDATE literals could not be mapped safely"))
            continue
        assignments = tail[set_index + len("set"):]
        assignments_offset = statement_offset + update.start() + set_index + len("set")
        where_index = top_level_sql_keyword(assignments, "where")
        where_text = ""
        where_offset = assignments_offset
        if where_index is not None:
            where_text = assignments[where_index + len("where"):]
            where_offset = assignments_offset + where_index + len("where")
            where_ends = [
                index
                for keyword in ("returning", "order", "limit")
                if (index := top_level_sql_keyword(where_text, keyword)) is not None
            ]
            if where_ends:
                where_text = where_text[: min(where_ends)]
        ends = [
            index
            for keyword in ("from", "where", "returning", "order", "limit")
            if (index := top_level_sql_keyword(assignments, keyword)) is not None
        ]
        if ends:
            assignments = assignments[: min(ends)]
        mapped_update: list[tuple[str, str, int, int]] = []
        expression_fields: list[tuple[str, str, int]] = []
        for assignment, assignment_offset in sql_field_slices(assignments, assignments_offset):
            equals = top_level_sql_operator(assignment, "=")
            literal_probe = sql_expression_has_data(assignment) or sql_has_data_constructor(assignment)
            if equals is None:
                if literal_probe:
                    failures.append((assignment_offset, "SQL UPDATE assignment could not be mapped safely"))
                continue
            column = normalize_sql_identifier(
                assignment[:equals], allow_single_quoted=True
            )
            rhs = assignment[equals + 1:]
            rhs_offset = assignment_offset + equals + 1
            literals = sql_token_values(rhs, rhs_offset)
            if not column:
                if sql_expression_has_data(rhs) or sql_has_data_constructor(rhs):
                    failures.append((assignment_offset, "SQL UPDATE column could not be mapped safely"))
                continue
            expression_fields.append((column, rhs, rhs_offset))
            for value, value_start, value_end in literals:
                mapped_update.append((column, value, value_start, value_end))
        has_attribute_assignment = any(column == "attribute" for column, _token, _offset in expression_fields)
        where_attribute = ""
        has_where_attribute = False
        if not has_attribute_assignment:
            where_attribute, has_where_attribute, where_failures = sql_where_attribute_context(
                where_text, where_offset
            )
            failures.extend(where_failures)
        contexts = validate_sql_field_expressions(
            expression_fields,
            failures,
            where_attribute=where_attribute,
            has_where_attribute=has_where_attribute,
        )
        relational_columns = add_relational_typed_values(values, mapped_update, contexts)
        values.extend(
            item for item in mapped_update if item[0] not in relational_columns
        )
    return values, failures


def sql_field_values(contents: str) -> Iterable[tuple[str, str, int, int]]:
    yield from analyze_sql(contents)[0]


def sql_contextual_values(contents: str) -> Iterable[tuple[str, str]]:
    """Recover typed literals from comparisons, constraints, and comments."""
    all_comment_pairs: list[tuple[str, str]] = []
    for comment in sql_comment_texts(contents):
        for match in GENERIC_KEY_VALUE_RE.finditer(comment):
            between = comment[match.end(1):match.start(2)]
            key = normalize_structured_key(match.group(1))
            supported_colon_key = bool(
                key in {"hostname", "mac", "mac_address"}
                or key in RELATIONAL_TYPE_VALUE_KEYS
                or key in RELATIONAL_ALL_VALUE_KEYS
            )
            if "=" not in between and not (":" in between and supported_colon_key):
                continue
            value = match.group(2)
            all_comment_pairs.append((key, value))
            typed = canonical_sql_typed_key(key)
            if typed:
                yield typed, value
    yield from relational_typed_pairs(all_comment_pairs)
    yield from relational_sequence_pairs(all_comment_pairs)

    identifier = SQL_IDENTIFIER_TOKEN
    comparison = re.compile(
        rf'''(?is)({identifier})\s*(?:=|!=|<>|<=|>=|<|>|\blike\b|\bglob\b|\bmatch\b|'''
        rf'''\bregexp\b|\bis\s+(?:not\s+)?|\bbetween\b[^)]*|\bin\s*\([^)]*)\s*\(*\s*$'''
    )
    default_value = re.compile(
        rf'''(?is)({identifier})(?:\s+[a-z_][a-z0-9_]*(?:\s*\([^)]*\))?)?'''
        r'''(?:\s+(?:not\s+null|null|unique|primary\s+key|collate\s+[a-z_][a-z0-9_]*))*\s+default\s*\(*\s*$'''
    )
    alias = re.compile(rf'''(?is)^\s*\)*\s+(?:as\s+)?({identifier})(?![a-z0-9_])''')
    for value, start, end in sql_literal_values(contents, 0):
        prefix_end = max(0, start - 1)
        if start >= 2 and contents[start - 1] == "'" and contents[start - 2] in {"x", "X"}:
            prefix_end = start - 2
        prefix = contents[max(0, prefix_end - 256):prefix_end]
        match = comparison.search(prefix) or default_value.search(prefix)
        if match:
            typed = canonical_sql_typed_key(normalize_sql_identifier(match.group(1)))
            if typed:
                yield typed, value
        suffix_start = min(len(contents), end + 1)
        alias_match = alias.match(contents[suffix_start:suffix_start + 256])
        if alias_match:
            typed = canonical_sql_typed_key(normalize_sql_identifier(alias_match.group(1)))
            if typed:
                yield typed, value

    # Relational discriminator/value predicates are scoped to one statement.
    # This covers DELETE predicates and UPDATE predicates for every supported
    # discriminator family, not only the legacy `attribute` pair.
    equality = re.compile(
        rf'''(?is)({identifier})\s*=\s*({SQL_LITERAL_TOKEN})|'''
        rf'''({SQL_LITERAL_TOKEN})\s*=\s*({identifier})'''
    )
    for statement, _statement_offset in sql_statements(contents):
        pairs: list[tuple[str, str]] = []
        for match in equality.finditer(strip_sql_comments(statement)):
            raw_key = match.group(1) or match.group(4)
            raw_value = match.group(2) or match.group(3)
            static = sql_static_text(raw_value)
            key = normalize_sql_identifier(raw_key)
            if static is not None and key:
                pairs.append((key, static[0]))
        yield from relational_typed_pairs(pairs)

        # A quoted literal anywhere in an identifier-typed column definition
        # (DEFAULT, CHECK, or generated expression) inherits that column's type.
        ddl_pairs: list[tuple[str, str]] = []
        for field, _field_offset in create_table_fields(statement, 0):
            first_identifier = re.match(rf'''(?is)^\s*({SQL_IDENTIFIER_TOKEN})''', field)
            if not first_identifier:
                continue
            column = normalize_sql_identifier(first_identifier.group(1))
            typed = canonical_sql_typed_key(column)
            field_tail = field[first_identifier.end():]
            field_values = [value for value, _start, _end in sql_literal_values(field_tail, 0)]
            if typed:
                for field_value in field_values:
                    yield typed, field_value
            ddl_pairs.extend((column, field_value) for field_value in field_values)
        yield from relational_typed_pairs(ddl_pairs)
        cleaned_statement = strip_sql_comments(statement)
        masked_statement = mask_sql_quoted(cleaned_statement)
        alter_add = re.search(r"(?is)^\s*alter\s+table\b.*?\badd\s+(?:column\s+)?", masked_statement)
        if alter_add:
            clause = cleaned_statement[alter_add.end():]
            first_identifier = re.match(rf"(?is)^\s*({SQL_IDENTIFIER_TOKEN})", clause)
            typed = canonical_sql_typed_key(normalize_sql_identifier(first_identifier.group(1))) if first_identifier else ""
            if typed:
                clause_tail = clause[first_identifier.end():] if first_identifier else clause
                for field_value, _start, _end in sql_literal_values(clause_tail, 0):
                    yield typed, field_value


def sql_has_data_constructor(text: str) -> bool:
    """Detect data-building expressions in a typed contextual clause."""
    if re.search(r"(?i)(?<![a-z0-9_])x'", text):
        return True
    safe_predicate_functions = {
        "check", "coalesce", "in", "length", "nullif", "octet_length",
        "select", "values", "where", "when",
    }
    if sql_function_names(text) - safe_predicate_functions:
        return True
    if sql_has_literal_keyword(text) or sql_has_arithmetic_synthesis(text):
        return True
    return False


def sql_identifiers(text: str) -> set[str]:
    """Return normalized bare and SQLite-quoted identifiers, excluding strings."""
    cleaned = strip_sql_comments(text)
    masked = mask_sql_quoted(cleaned)
    identifiers = {
        match.group(0).lower()
        for match in re.finditer(r"(?i)\b[a-z_][a-z0-9_]*\b", masked)
    }
    index = 0
    while index < len(cleaned):
        character = cleaned[index]
        if character == "'":
            index += 1
            while index < len(cleaned):
                if cleaned[index] == "'":
                    if index + 1 < len(cleaned) and cleaned[index + 1] == "'":
                        index += 2
                        continue
                    index += 1
                    break
                index += 1
            continue
        if character not in {'"', "`", "["}:
            index += 1
            continue
        closing = "]" if character == "[" else character
        start = index
        index += 1
        while index < len(cleaned):
            if cleaned[index] == closing:
                if closing != "]" and index + 1 < len(cleaned) and cleaned[index + 1] == closing:
                    index += 2
                    continue
                index += 1
                break
            index += 1
        normalized = normalize_sql_identifier(cleaned[start:index])
        if normalized:
            identifiers.add(normalized)
    return identifiers


def sql_typed_identifiers(text: str) -> set[str]:
    return {
        canonical_sql_typed_key(identifier)
        for identifier in sql_identifiers(text)
        if canonical_sql_typed_key(identifier)
    }


def sql_relational_contexts(text: str) -> set[str]:
    identifiers = sql_identifiers(text)
    return {
        type_key
        for type_key, value_keys in RELATIONAL_TYPE_VALUE_KEYS.items()
        if type_key in identifiers and any(value_key in identifiers for value_key in value_keys)
    }


def create_table_fields(statement: str, base_offset: int) -> list[tuple[str, int]]:
    masked = mask_sql_quoted(strip_sql_comments(statement))
    match = re.search(r"(?is)\bcreate\s+(?:temp(?:orary)?\s+)?table\b", masked)
    if not match:
        return []
    left = masked.find("(", match.end())
    if left < 0:
        return []
    depth = 0
    right = -1
    for index in range(left, len(masked)):
        if masked[index] == "(":
            depth += 1
        elif masked[index] == ")":
            depth -= 1
            if depth == 0:
                right = index
                break
    if right < 0:
        return []
    return list(sql_field_slices(statement[left + 1:right], base_offset + left + 1))


def sql_identity_column(column: str) -> bool:
    return bool(
        canonical_sql_typed_key(column)
        or column in RELATIONAL_TYPE_VALUE_KEYS
        or column in RELATIONAL_ALL_VALUE_KEYS
    )


def sql_scoped_identity_reference(text: str) -> bool:
    for identifier in sql_identifiers(text):
        typed = canonical_sql_typed_key(identifier)
        if typed and typed not in VERSION_KEYS:
            return True
        if identifier in RELATIONAL_TYPE_VALUE_KEYS or identifier in RELATIONAL_ALL_VALUE_KEYS:
            return True
    return False


def sql_parameter(text: str) -> re.Match[str] | None:
    return SQL_PARAMETER_RE.search(mask_sql_quoted(strip_sql_comments(text)))


def sql_statement_head(masked_statement: str) -> str:
    match = re.match(
        r"(?is)^\s*(?:explain(?:\s+query\s+plan)?\s+)?([a-z]+)", masked_statement
    )
    return match.group(1).lower() if match else ""


def sql_expression_has_review_data(text: str) -> bool:
    return sql_expression_has_data(text) or sql_has_literal_keyword(text)


def sql_direct_static_expression(expression: str) -> bool:
    expression, _offset = strip_sql_outer_parentheses(expression)
    return bool(
        re.fullmatch(rf"(?is)\s*(?:{SQL_LITERAL_TOKEN}|[+-]?{SQL_NUMERIC_BODY}|null)\s*", expression)
    )


def sql_copy_fallback_expression(expression: str, depth: int = 0) -> bool:
    """Allow only copied identifiers, NULL, and punctuation-only fallbacks."""
    if depth > 32:
        return False
    expression, _offset = strip_sql_outer_parentheses(expression)
    stripped = expression.strip()
    if re.fullmatch(r"(?i)null", stripped):
        return True
    if sql_has_literal_keyword(stripped) or sql_parameter(stripped):
        return False
    static = sql_static_text(stripped)
    if static is not None:
        return not re.search(r"[a-z0-9]", static[0], re.IGNORECASE)
    identifier_reference = rf"{SQL_IDENTIFIER_TOKEN}(?:\s*\.\s*{SQL_IDENTIFIER_TOKEN})*"
    if re.fullmatch(rf"(?is)\s*{identifier_reference}\s*", stripped):
        return True
    calls = sql_function_calls(stripped)
    if len(calls) != 1:
        return False
    name, start, open_index, close_index, _quoted = calls[0]
    if name not in {"coalesce", "nullif"} or start != 0 or close_index != len(stripped) - 1:
        return False
    arguments = list(sql_field_slices(stripped[open_index + 1:close_index], 0))
    return bool(arguments) and all(
        sql_copy_fallback_expression(argument, depth + 1)
        for argument, _argument_offset in arguments
    )


def sql_structural_projection(expression: str) -> bool:
    expression, _offset = strip_sql_outer_parentheses(expression)
    wildcard = rf"(?:{SQL_IDENTIFIER_TOKEN}\s*\.\s*)?\*"
    return bool(
        re.fullmatch(rf"(?is)\s*{wildcard}\s*", expression)
        or sql_copy_fallback_expression(expression)
    )


def sql_structural_copy_query(statement: str) -> bool:
    """Accept query definitions made only from copied fields and fallbacks."""
    cleaned = strip_sql_comments(statement)
    masked = mask_sql_quoted(cleaned)
    if (
        sql_expression_has_data(cleaned)
        or sql_parameter(cleaned)
        or sql_has_literal_keyword(cleaned)
        or sql_has_arithmetic_synthesis(cleaned)
        or re.search(r"(?is)\|\||\bcase\b", masked)
    ):
        return False
    for name, start, _open_index, close_index, quoted in sql_function_calls(cleaned):
        if quoted or not sql_copy_fallback_expression(cleaned[start:close_index + 1]):
            return False
    return all(
        sql_structural_projection(sql_projection_expression(field, offset)[1])
        for field, offset in sql_select_projection_fields(cleaned, 0)
    )


def sql_safe_length_predicate(statement: str) -> bool:
    where = top_level_sql_keyword(statement, "where")
    if where is None or sql_expression_has_review_data(statement[:where]):
        return False
    clause = statement[where + len("where"):]
    return bool(
        re.fullmatch(
            rf"(?is)\s*length\s*\(\s*{SQL_IDENTIFIER_TOKEN}\s*\)\s*(?:<=|<)\s*\d+\s*;?\s*",
            clause,
        )
    )


def sql_safe_update_eav_predicate(where: str, base_offset: int) -> bool:
    attribute, has_attribute, failures = sql_where_attribute_context(where, base_offset)
    if not attribute or not has_attribute or failures:
        return False
    for clause, clause_offset in sql_top_level_parts(where, "and", base_offset):
        clause, _clause_offset = strip_sql_outer_parentheses(clause, clause_offset)
        if SQL_ATTRIBUTE_IDENTIFIER_RE.search(clause):
            continue
        if sql_sensitive_expression_region(clause):
            return False
    return True


def sql_sensitive_expression_region(text: str) -> bool:
    return sql_scoped_identity_reference(text) and bool(
        sql_expression_has_review_data(text)
        or sql_function_calls(text)
        or sql_has_arithmetic_synthesis(text)
    )


def sql_strict_data_constructor(text: str, *, structural_calls: bool = True) -> bool:
    dangerous_calls = {
        "char", "cast", "format", "hex", "lower", "printf", "quote", "randomblob",
        "replace", "substr", "substring", "typeof", "unicode", "unhex", "unistr",
        "upper", "zeroblob",
    }
    for name, _start, open_index, close_index, quoted in sql_function_calls(text):
        if quoted or name in dangerous_calls:
            return True
        if structural_calls and name in {"coalesce", "nullif"}:
            arguments = text[open_index + 1:close_index]
            if not all(
                sql_copy_fallback_expression(argument)
                for argument, _argument_offset in sql_field_slices(arguments, 0)
            ):
                return True
    return bool(
        sql_has_arithmetic_synthesis(text)
        or sql_has_literal_comparison_synthesis(text)
    )


def sql_positional_identity_names(statement: str) -> set[str]:
    """Recognize single-quoted identifiers only in identifier grammar slots."""
    names: set[str] = set()
    for field, _field_offset in create_table_fields(statement, 0):
        match = re.match(rf"(?is)^\s*({SQL_POSITIONAL_IDENTIFIER_TOKEN})", field)
        if match:
            name = normalize_sql_identifier(match.group(1), allow_single_quoted=True)
            if sql_identity_column(name):
                names.add(name)
    for match in re.finditer(
        rf"(?is)\bas\s+({SQL_POSITIONAL_IDENTIFIER_TOKEN})\s*(?:[,;)\n]|$)", statement
    ):
        name = normalize_sql_identifier(match.group(1), allow_single_quoted=True)
        if sql_identity_column(name):
            names.add(name)
    declaration = re.compile(
        rf"(?is)(?:\bcreate\s+(?:temp(?:orary)?\s+)?view\s+|\bwith\s+(?:recursive\s+)?)"
        rf"{SQL_POSITIONAL_IDENTIFIER_TOKEN}\s*\((?P<columns>[^)]*)\)"
    )
    for match in declaration.finditer(statement):
        for field, _field_offset in sql_field_slices(match.group("columns"), 0):
            name = normalize_sql_identifier(field, allow_single_quoted=True)
            if sql_identity_column(name):
                names.add(name)
    return names


def sql_dot_command_failures(path: str, contents: str) -> list[tuple[int, str]]:
    failures: list[tuple[int, str]] = []
    offset = 0
    for line in contents.splitlines(keepends=True):
        match = re.match(r"^[ \t]*(\.[a-z][a-z0-9_-]*)\b(.*)$", line, re.IGNORECASE)
        if match:
            command = match.group(1).lower()
            argument = match.group(2).strip().lower()
            harmless_argument = (
                command in {".echo", ".headers", ".timer"} and argument in {"on", "off"}
            ) or (
                command == ".mode"
                and argument in {
                    "ascii", "box", "column", "csv", "html", "json", "line", "list",
                    "markdown", "quote", "table", "tabs", "tcl",
                }
            )
            if path not in SQL_READ_ONLY_FILES or command not in SQL_HARMLESS_DOT_COMMANDS or not harmless_argument:
                failures.append((offset, "SQL shell dot command is not allowed by the file role"))
        offset += len(line)
    return failures


def sql_strict_dml_failures(statement: str, base_offset: int) -> list[tuple[int, str]]:
    failures: list[tuple[int, str]] = []
    cleaned = strip_sql_comments(statement)
    masked = mask_sql_quoted(cleaned)
    locator = re.search(r"(?is)\b(?:insert(?:\s+or\s+[a-z]+)?|replace)\s+into\b", masked)
    if locator:
        tail = cleaned[locator.start():]
        select = SQL_DML_SELECT_RE.match(tail)
        values_match = SQL_DML_VALUES_RE.match(tail)
        match = select or values_match
        columns = [
            normalize_sql_identifier(field, allow_single_quoted=True)
            for field, _field_offset in sql_field_slices(match.group("columns") or "", 0)
        ] if match else []
        if select and (not columns or any(sql_identity_column(column) for column in columns)):
            failures.append((base_offset + locator.start(), "restricted SQL forbids identity-bearing INSERT SELECT"))
        if (
            select
            and sql_scoped_identity_reference(select.group("projection"))
            and sql_expression_has_review_data(select.group("projection"))
        ):
            failures.append((
                base_offset + locator.start() + select.start("projection"),
                "restricted SQL INSERT SELECT identity expressions must be structural",
            ))
        if values_match and columns:
            rows_text = values_match.group("rows")
            for row, row_offset in sql_row_slices(rows_text, base_offset + locator.start() + values_match.start("rows")):
                fields = list(sql_field_slices(row, row_offset))
                if len(fields) != len(columns):
                    continue
                for column, (expression, expression_offset) in zip(columns, fields):
                    if (
                        sql_scoped_identity_reference(expression)
                        and sql_expression_has_review_data(expression)
                    ):
                        failures.append((
                            expression_offset,
                            "restricted SQL VALUES identity expressions must be structural",
                        ))
                    if sql_identity_column(column) and not sql_direct_static_expression(expression):
                        failures.append((expression_offset, "restricted SQL identity VALUES must be direct static literals"))

    update = re.search(r"(?is)\bupdate\b", masked)
    if update:
        tail = cleaned[update.start():]
        set_index = top_level_sql_keyword(tail, "set")
        if set_index is not None:
            update_tail = tail[set_index + len("set"):]
            update_tail_offset = base_offset + update.start() + set_index + len("set")
            assignments = update_tail
            ends = [
                index
                for keyword in ("from", "where", "returning", "order", "limit")
                if (index := top_level_sql_keyword(assignments, keyword)) is not None
            ]
            if ends:
                assignments = assignments[:min(ends)]
            assignment_offset = update_tail_offset
            for assignment, field_offset in sql_field_slices(assignments, assignment_offset):
                equals = top_level_sql_operator(assignment, "=")
                if equals is None:
                    continue
                left, _left_offset = strip_sql_outer_parentheses(assignment[:equals])
                targets = [
                    normalize_sql_identifier(field, allow_single_quoted=True)
                    for field, _target_offset in sql_field_slices(left, 0)
                ]
                expression = assignment[equals + 1:]
                if (
                    sql_scoped_identity_reference(expression)
                    and sql_expression_has_review_data(expression)
                ):
                    failures.append((
                        field_offset + equals + 1,
                        "restricted SQL UPDATE identity expressions must be structural",
                    ))
                if len(targets) > 1 and any(sql_identity_column(target) for target in targets):
                    failures.append((field_offset, "restricted SQL forbids tuple assignment to identity fields"))
                elif len(targets) == 1 and sql_identity_column(targets[0]) and not sql_direct_static_expression(expression):
                    failures.append((field_offset + equals + 1, "restricted SQL identity UPDATE must be a direct static literal"))

            where = top_level_sql_keyword(update_tail, "where")
            if where is not None:
                where_text = update_tail[where + len("where"):]
                where_offset = update_tail_offset + where + len("where")
                where_ends = [
                    index
                    for keyword in ("returning", "order", "limit")
                    if (index := top_level_sql_keyword(where_text, keyword)) is not None
                ]
                if where_ends:
                    where_text = where_text[:min(where_ends)]
                sensitive_where = sql_sensitive_expression_region(where_text)
                if sensitive_where and not sql_safe_update_eav_predicate(where_text, where_offset):
                    failures.append((where_offset, "restricted SQL identity UPDATE predicate must be structural"))

            for keyword in ("from", "order", "limit"):
                clause = top_level_sql_keyword(update_tail, keyword)
                if clause is None:
                    continue
                clause_text = update_tail[clause + len(keyword):]
                clause_offset = update_tail_offset + clause + len(keyword)
                clause_ends = [
                    index
                    for terminator in ("from", "where", "returning", "order", "limit")
                    if terminator != keyword
                    and (index := top_level_sql_keyword(clause_text, terminator)) is not None
                ]
                if clause_ends:
                    clause_text = clause_text[:min(clause_ends)]
                if sql_sensitive_expression_region(clause_text):
                    failures.append((clause_offset, f"restricted SQL identity UPDATE {keyword.upper()} expression must be structural"))

            returning = top_level_sql_keyword(update_tail, "returning")
            if returning is not None:
                returning_text = update_tail[returning + len("returning"):]
                returning_offset = update_tail_offset + returning + len("returning")
                returning_ends = [
                    index
                    for keyword in ("order", "limit")
                    if (index := top_level_sql_keyword(returning_text, keyword)) is not None
                ]
                if returning_ends:
                    returning_text = returning_text[:min(returning_ends)]
                for field, field_offset in sql_field_slices(returning_text, returning_offset):
                    key, expression, expression_offset = sql_projection_expression(field, field_offset)
                    if (
                        (sql_identity_column(key) or sql_scoped_identity_reference(expression))
                        and not sql_structural_projection(expression)
                    ):
                        failures.append((expression_offset, "restricted SQL identity RETURNING output must be structural"))
    return failures


def sql_typed_ddl_failures(statement: str, base_offset: int) -> list[tuple[int, str]]:
    failures: list[tuple[int, str]] = []
    field_sets = create_table_fields(statement, base_offset)
    masked = mask_sql_quoted(strip_sql_comments(statement))
    alter = re.search(r"(?is)^\s*alter\s+table\b.*?\badd\s+(?:column\s+)?", masked)
    if alter:
        field_sets.append((statement[alter.end():], base_offset + alter.end()))
    for field, field_offset in field_sets:
        first = re.match(rf"(?is)^\s*({SQL_POSITIONAL_IDENTIFIER_TOKEN})", field)
        first_name = normalize_sql_identifier(
            first.group(1), allow_single_quoted=True
        ) if first else ""
        table_constraint = first_name in {"check", "constraint"}
        if (
            table_constraint
            and sql_scoped_identity_reference(field)
            and sql_expression_has_review_data(field)
        ):
            failures.append((field_offset, "restricted SQL identity table constraints must be structural"))
        if sql_relational_contexts(field) and sql_expression_has_review_data(field):
            failures.append((field_offset, "restricted SQL relational table constraints must be structural"))
        if not first:
            continue
        column = first_name
        canonical_column = canonical_sql_typed_key(column)
        foreign_sensitive_identity = any(
            identity not in VERSION_KEYS and identity != canonical_column
            for identity in sql_typed_identifiers(field)
        ) or any(
            identifier != column
            and (identifier in RELATIONAL_TYPE_VALUE_KEYS or identifier in RELATIONAL_ALL_VALUE_KEYS)
            for identifier in sql_identifiers(field)
        )
        if foreign_sensitive_identity and sql_expression_has_review_data(field):
            failures.append((field_offset, "restricted SQL field constraints mix identity contexts"))
        if not sql_identity_column(column):
            continue
        field_masked = mask_sql_quoted(field)
        generated = re.search(r"(?is)\b(?:generated\s+always\s+)?as\s*\(", field_masked)
        if generated:
            failures.append((field_offset + generated.start(), "restricted SQL forbids generated identity columns"))
        default = top_level_sql_keyword(field, "default")
        if default is not None:
            expression = field[default + len("default"):]
            ends = [
                index for keyword in ("constraint", "not", "null", "unique", "primary", "check", "collate", "references", "generated")
                if (index := top_level_sql_keyword(expression, keyword)) is not None
            ]
            if ends:
                expression = expression[:min(ends)]
            if not sql_direct_static_expression(expression):
                failures.append((field_offset + default, "restricted SQL identity DEFAULT must be a direct static literal"))
        check = top_level_sql_keyword(field, "check")
        if check is not None:
            clause = field[check + len("check"):]
            safe_length = bool(
                re.fullmatch(
                    rf"(?is)\s*\(\s*length\s*\(\s*{SQL_IDENTIFIER_TOKEN}\s*\)\s*(?:<=|<)\s*\d+\s*\)\s*",
                    clause,
                )
            )
            safe_version = canonical_sql_typed_key(column) in VERSION_KEYS and not sql_strict_data_constructor(clause)
            safe_discriminator = (
                column in RELATIONAL_TYPE_VALUE_KEYS
                and not sql_strict_data_constructor(clause)
            )
            if not safe_length and not safe_version and not safe_discriminator:
                failures.append((field_offset + check, "restricted SQL identity CHECK is outside the allowed subset"))
    return failures


def sql_unsupported_typed_grammar(text: str) -> bool:
    masked = mask_sql_quoted(strip_sql_comments(text))
    return bool(
        re.search(
            r"(?is)==|\bcollate\b|\|\||\bnot\s+(?:like|in)\b|"
            r"\bis\s+(?:not\s+)?distinct\s+from\b",
            masked,
        )
        or re.search(
            rf"(?is)(?<![a-z0-9_])\(\s*{SQL_IDENTIFIER_TOKEN}\s*\)\s*(?:=|<|>|\blike\b|\bin\b)",
            text,
        )
        or re.search(
            rf"(?is){SQL_LITERAL_TOKEN}\s+(?:not\s+)?like\s+{SQL_IDENTIFIER_TOKEN}",
            text,
        )
    )


def sql_restricted_migration_failures(contents: str) -> list[tuple[int, str]]:
    failures: list[tuple[int, str]] = []
    parameter = sql_parameter(contents)
    if parameter:
        failures.append((parameter.start(), "restricted SQL parameters are not reviewable static data"))
    for statement, statement_offset in sql_statements(contents):
        cleaned = strip_sql_comments(statement)
        masked = mask_sql_quoted(cleaned)
        head = sql_statement_head(masked)
        failures.extend(sql_strict_dml_failures(cleaned, statement_offset))
        failures.extend(sql_typed_ddl_failures(cleaned, statement_offset))
        identities = sql_typed_identifiers(cleaned) | sql_positional_identity_names(cleaned)
        relational = sql_relational_contexts(cleaned)
        sensitive = any(identity not in VERSION_KEYS for identity in identities) or bool(relational)
        schema_ddl = bool(re.search(r"(?is)^\s*create\s+(?:temp(?:orary)?\s+)?table\b", masked))
        if relational and not schema_ddl and re.search(
            r"(?is)(?:!=|<>|<=|>=|<|>|\blike\b|\bglob\b|\bmatch\b|"
            r"\bregexp\b|\bis\b|\bin\b|\bbetween\b)",
            masked,
        ):
            failures.append((statement_offset, "restricted SQL relational predicates permit only direct equality"))
        if (identities or relational) and sql_strict_data_constructor(cleaned):
            failures.append((statement_offset, "restricted SQL combines identity fields with constructed data"))
        if (identities or relational) and sql_unsupported_typed_grammar(cleaned):
            failures.append((statement_offset, "restricted SQL uses unsupported identity comparison grammar"))
        query_definition = bool(
            re.search(r"(?is)^\s*create\s+(?:temp(?:orary)?\s+)?view\b", masked)
            or re.search(r"(?is)^\s*create\s+(?:temp(?:orary)?\s+)?table\b.*\bas\s+select\b", masked)
            or head == "with"
        )
        if query_definition and (identities or relational) and not sql_structural_copy_query(cleaned):
            failures.append((statement_offset, "restricted SQL typed query definitions must be structural copies"))
        for projection, projection_offset in sql_select_projection_fields(cleaned, statement_offset):
            key, expression, expression_offset = sql_projection_expression(projection, projection_offset)
            if sql_identity_column(key) and not sql_copy_fallback_expression(expression):
                failures.append((expression_offset, "restricted SQL typed output must be a structural copy"))
        if relational and top_level_sql_keyword(cleaned, "returning") is not None and sql_expression_has_review_data(cleaned):
            failures.append((statement_offset, "restricted SQL relational RETURNING output must be structural"))
        create_query_object = bool(
            head == "create" and re.search(r"(?is)\b(?:view|index|trigger)\b", masked)
        )
        sensitive_query_context = bool(
            head in {"select", "delete", "with"}
            or create_query_object
            or re.search(r"(?is)^\s*create\s+(?:temp(?:orary)?\s+)?table\b.*\bas\s+select\b", masked)
        )
        safe_length_index = bool(
            head == "create"
            and re.search(r"(?is)\bindex\b", masked)
            and sql_safe_length_predicate(cleaned)
        )
        if (
            sensitive
            and sensitive_query_context
            and sql_expression_has_review_data(cleaned)
            and not safe_length_index
        ):
            failures.append((statement_offset, "restricted SQL combines identity query context with data"))
        non_version_identity = any(identity not in VERSION_KEYS for identity in identities)
        if non_version_identity and head in {"select", "delete"} and SQL_NUMERIC_TOKEN_RE.search(masked):
            failures.append((statement_offset, "restricted SQL compares identity data with a numeric expression"))
        if head == "create" and re.search(r"(?is)\b(?:view|index|trigger)\b", masked):
            if (identities or relational) and sql_expression_has_data(cleaned) and sql_unsupported_typed_grammar(cleaned):
                failures.append((statement_offset, "restricted SQL identity query/index expression is not static"))
    return list(dict.fromkeys(failures))


def sql_read_only_failures(contents: str) -> list[tuple[int, str]]:
    failures: list[tuple[int, str]] = []
    masked_contents = mask_sql_quoted(strip_sql_comments(contents))
    parameter = sql_parameter(contents)
    if parameter:
        failures.append((parameter.start(), "read-only SQL parameters are not allowed"))
    write = SQL_WRITE_CAPABILITY_RE.search(masked_contents)
    if write:
        failures.append((write.start(), "SQL report role forbids write and schema capabilities"))
    for statement, statement_offset in sql_statements(contents):
        cleaned = strip_sql_comments(statement)
        masked = mask_sql_quoted(cleaned)
        head = sql_statement_head(masked)
        if head not in {"select", "with"}:
            failures.append((statement_offset, "SQL report role permits only SELECT/WITH statements"))
            continue
        identities = sql_typed_identifiers(cleaned) | sql_positional_identity_names(cleaned)
        relational = sql_relational_contexts(cleaned)
        sensitive = any(identity not in VERSION_KEYS for identity in identities) or bool(relational)
        if identities and sql_strict_data_constructor(cleaned, structural_calls=False):
            failures.append((statement_offset, "SQL report constructs identity-shaped output"))
        if sensitive and sql_expression_has_review_data(cleaned):
            failures.append((statement_offset, "SQL report combines identity query context with data"))
        if head == "with" and (identities or relational) and not sql_structural_copy_query(cleaned):
            failures.append((statement_offset, "SQL report typed query definitions must be structural copies"))
        for projection, projection_offset in sql_select_projection_fields(cleaned, statement_offset):
            key, expression, expression_offset = sql_projection_expression(projection, projection_offset)
            if sql_identity_column(key) and not sql_copy_fallback_expression(expression):
                failures.append((expression_offset, "SQL report typed output is not a structural copy"))
    return failures


def sql_static_fixture_failures(contents: str) -> list[tuple[int, str]]:
    """Permit static VALUES fixtures plus the seed script's cleanup/report roles."""
    failures: list[tuple[int, str]] = []
    cleanup = re.compile(
        rf"(?is)^\s*delete\s+from\s+events\s+where\s+source_hash\s+like\s+{SQL_LITERAL_TOKEN}"
        rf"\s+or\s+domain\s+like\s+{SQL_LITERAL_TOKEN}\s+or\s+domain\s+like\s+{SQL_LITERAL_TOKEN}"
        rf"\s+or\s+domain\s+like\s+{SQL_LITERAL_TOKEN}\s*;?\s*$"
    )
    for statement, statement_offset in sql_statements(contents):
        cleaned = strip_sql_comments(statement)
        masked = mask_sql_quoted(cleaned)
        head_match = re.match(r"(?is)^\s*([a-z]+)", masked)
        head = head_match.group(1).lower() if head_match else ""
        fixed_cleanup = bool(head == "delete" and cleanup.fullmatch(cleaned))
        if not fixed_cleanup:
            failures.extend(
                (statement_offset + failure_offset, reason)
                for failure_offset, reason in sql_restricted_migration_failures(statement)
            )
        if head == "select":
            continue
        if fixed_cleanup:
            continue
        if head == "insert":
            locator = re.search(r"(?is)\binsert(?:\s+or\s+[a-z]+)?\s+into\b", masked)
            if locator and SQL_DML_VALUES_RE.match(cleaned[locator.start():]):
                continue
        failures.append((statement_offset, "SQL static-fixture role permits only direct VALUES and fixed cleanup/report statements"))
    return list(dict.fromkeys(failures))


def sql_role_policy_failures(path: str, contents: str) -> list[tuple[int, str]]:
    failures = sql_dot_command_failures(path, contents)
    if failures:
        return failures
    digest = hashlib.sha256(contents.encode("utf-8")).hexdigest()
    if path in LEGACY_SQL_SHA256 and digest == LEGACY_SQL_SHA256[path]:
        return []
    if path in SQL_READ_ONLY_SHA256 and digest == SQL_READ_ONLY_SHA256[path]:
        return []
    if path in SQL_READ_ONLY_FILES:
        return sql_read_only_failures(contents)
    if path in SQL_STATIC_FIXTURE_FILES:
        return sql_static_fixture_failures(contents)
    return sql_restricted_migration_failures(contents)


def sql_select_projection_fields(statement: str, base_offset: int) -> list[tuple[str, int]]:
    """Return projection fields for every SELECT, including nested CTE SELECTs."""
    masked = mask_sql_quoted(strip_sql_comments(statement))
    depths: list[int] = [0] * (len(masked) + 1)
    depth = 0
    for index, character in enumerate(masked):
        depths[index] = depth
        if character == "(":
            depth += 1
        elif character == ")" and depth:
            depth -= 1
    depths[len(masked)] = depth
    terminator_pattern = re.compile(
        r"(?i)\b(?:from|where|group|having|order|limit|union|intersect|except|returning)\b"
    )
    terminators = list(terminator_pattern.finditer(masked))
    fields: list[tuple[str, int]] = []
    for select in re.finditer(r"(?i)\bselect\b", masked):
        start = select.end()
        level = depths[select.start()]
        ends = [
            match.start()
            for match in terminators
            if match.start() >= start and depths[match.start()] == level
        ]
        if level:
            ends.extend(
                index
                for index in range(start, len(masked))
                if masked[index] == ")" and depths[index] == level
            )
        ends.extend(
            index
            for index in range(start, len(masked))
            if masked[index] == ";" and depths[index] == level
        )
        end = min(ends) if ends else len(statement)
        fields.extend(sql_field_slices(statement[start:end], base_offset + start))
    return fields


def sql_projection_expression(field: str, field_offset: int) -> tuple[str, str, int]:
    """Resolve a SELECT/RETURNING expression's output key when it names one."""
    alias = re.search(rf'''(?is)\s+(?:as\s+)?({SQL_POSITIONAL_IDENTIFIER_TOKEN})\s*$''', field)
    if alias:
        expression = field[:alias.start()].rstrip()
        return normalize_sql_identifier(
            alias.group(1), allow_single_quoted=True
        ), expression, field_offset
    return normalize_sql_identifier(field, allow_single_quoted=True), field, field_offset


def safe_version_value(value: str) -> bool:
    candidate = value.strip()
    if not VERSION_VALUE_RE.fullmatch(candidate):
        return False
    # A vendor version may legitimately look like a public dotted quad, but an
    # RFC1918/link-local/reserved address remains identifier material even when
    # it is placed in a field named "version".
    for match in IPV4_RE.findall(candidate):
        try:
            address = ipaddress.IPv4Address(match)
        except ipaddress.AddressValueError:
            octets = [int(part) for part in match.split(".")]
            private_or_link_local_prefix = (
                octets[0] == 10
                or (octets[0] == 172 and 16 <= octets[1] <= 31)
                or octets[:2] == [192, 168]
                or octets[:2] == [169, 254]
            )
            if private_or_link_local_prefix:
                return False
            continue  # A non-private >255 component is ordinary version syntax.
        if not allowed_v4(address) and not address.is_global:
            return False
    return True


def identifier_candidate_spans(value: str) -> list[tuple[int, int]]:
    """Return identifier-shaped ranges used to detect cross-field assembly."""
    spans: set[tuple[int, int]] = set()
    spans.update(match.span(1) for match in IPV4_RE.finditer(value))
    for pattern in (MAC_DELIMITED_RE, MAC_CISCO_RE, MAC_COMPACT_RE):
        spans.update(match.span(0) for match in pattern.finditer(value))
    for pattern in (
        MAC_CONTEXTUAL_COMPACT_RE,
        MAC_CONTEXTUAL_TIGHT_RE,
        MAC_HEX_COMPACT_RE,
    ):
        spans.update(match.span(1) for match in pattern.finditer(value))
    for match in LOCAL_TOKEN_RE.finditer(value):
        if any(True for _candidate in local_name_candidates(match.group(0))):
            spans.add(match.span(0))
    return sorted(spans)


def csv_records_with_spans(
    contents: str, delimiter: str
) -> tuple[list[list[tuple[str, int, int]]], bool]:
    """Parse CSV/TSV records while retaining exact raw field boundaries."""
    raw_records: list[list[tuple[int, int]]] = []
    fields: list[tuple[int, int]] = []
    field_start = 0
    quote = False
    index = 0
    field_count = 0
    while index < len(contents):
        character = contents[index]
        if quote:
            if character == '"':
                if index + 1 < len(contents) and contents[index + 1] == '"':
                    index += 2
                    continue
                quote = False
        elif character == '"':
            quote = True
        elif character == delimiter:
            fields.append((field_start, index))
            field_count += 1
            if field_count > MAX_STRUCTURED_VALUES:
                return [], False
            field_start = index + 1
        elif character in {"\r", "\n"}:
            if fields or field_start != index:
                fields.append((field_start, index))
                field_count += 1
                if field_count > MAX_STRUCTURED_VALUES:
                    return [], False
                raw_records.append(fields)
            fields = []
            if character == "\r" and index + 1 < len(contents) and contents[index + 1] == "\n":
                index += 1
            field_start = index + 1
        index += 1
    if quote:
        return [], False
    if field_start < len(contents) or fields:
        fields.append((field_start, len(contents)))
        field_count += 1
        if field_count > MAX_STRUCTURED_VALUES:
            return [], False
        raw_records.append(fields)

    records: list[list[tuple[str, int, int]]] = []
    try:
        for record_index, raw_record in enumerate(raw_records):
            record: list[tuple[str, int, int]] = []
            for field_index, (start, end) in enumerate(raw_record):
                raw = contents[start:end]
                if record_index == 0 and field_index == 0:
                    raw = raw.removeprefix("\ufeff")
                if raw == "":
                    record.append(("", start, end))
                    continue
                parsed = next(csv.reader([raw], delimiter=delimiter, strict=True))
                if len(parsed) != 1:
                    return [], False
                record.append((parsed[0], start, end))
            records.append(record)
    except (csv.Error, StopIteration):
        return [], False
    return records, True


def delimited_records_valid(
    records: list[list[tuple[str, int, int]]], delimiter: str
) -> bool:
    if not records:
        return True
    header_width = len(records[0])
    if len({normalize_structured_key(value) for value, _start, _end in records[0]}) != header_width:
        return False
    if any(len(row) != header_width for row in records[1:]):
        return False
    if header_width == 1:
        alternate_delimiters = {";", "|", "\t", ","} - {delimiter}
        if any(marker in records[0][0][0] for marker in alternate_delimiters):
            return False
    return True


def inventory_format_failures(path: str, contents: str) -> list[str]:
    """Require identity-bearing inventory/fingerprint files to use a known schema."""
    if not is_inventory_path(path):
        return []
    suffix = PurePosixPath(path).suffix.lower()
    if suffix == ".json":
        documents, valid_json = json_documents(path, contents)
        if not valid_json:
            return []  # The ordinary JSON validation reports this first.
        pending: list[dict[str, Any]] = []
        for document in documents:
            if isinstance(document, dict):
                pending.append(document)
            elif isinstance(document, list) and all(isinstance(item, dict) for item in document):
                pending.extend(document)
            else:
                return [f"{display_path(path)}: inventory JSON must contain records or record arrays"]
        while pending:
            value = pending.pop()
            for raw_key, child in value.items():
                key = normalize_structured_key(raw_key)
                if key not in INVENTORY_SCHEMA_KEYS:
                    return [f"{display_path(path)}: inventory JSON contains an unapproved schema key"]
                if key in INVENTORY_COLLECTION_KEYS:
                    if not isinstance(child, list) or not all(isinstance(item, dict) for item in child):
                        return [f"{display_path(path)}: inventory collection must be an array of records"]
                    pending.extend(child)
                elif isinstance(child, dict):
                    pending.append(child)
                elif isinstance(child, list):
                    nested: list[Any] = list(child)
                    while nested:
                        item = nested.pop()
                        if isinstance(item, dict):
                            pending.append(item)
                        elif isinstance(item, list):
                            nested.extend(item)
        return []
    if suffix in {".csv", ".tsv"}:
        delimiter = "\t" if suffix == ".tsv" else ","
        records, valid_csv = csv_records_with_spans(contents, delimiter)
        if not valid_csv or not records:
            return []  # The ordinary delimited validation reports malformed data.
        for raw_key, _start, _end in records[0]:
            if normalize_structured_key(raw_key) not in INVENTORY_SCHEMA_KEYS:
                return [f"{display_path(path)}: inventory table contains an unapproved schema header"]
    return []


OUI_PREFIX_RE = re.compile(r"^[0-9a-f]{6}$")


def oui_table_failures(path: str, contents: str) -> list[str]:
    """Validate the embedded IEEE OUI table's safe shape.

    This is public IEEE reference data, so it is exempt from the identity scans (its
    vendor names legitimately look like hostnames). In their place we enforce the
    structural contract that keeps it safe: a fixed ``prefix,vendor`` header, exactly two
    columns per row, and a 6-hex-digit prefix in column one. That guarantees the
    identity-bearing column cannot carry an IP/MAC/hostname while accepting arbitrary
    public vendor text in column two.
    """
    records, valid_csv = csv_records_with_spans(contents, ",")
    if not valid_csv or not records:
        return [f"{display_path(path)}: OUI table could not be decoded safely"]
    # Compare the header literally \u2014 the generator emits exactly "prefix,vendor", so a
    # case- or whitespace-variant header is drift worth catching. Tolerate only a leading
    # UTF-8 BOM on the first cell.
    header = [value for value, _s, _e in records[0]]
    if header:
        header[0] = header[0].lstrip("\ufeff")
    if header != ["prefix", "vendor"]:
        return [f"{display_path(path)}: OUI table header must be exactly 'prefix,vendor'"]
    for row_number, row in enumerate(records[1:], start=2):
        if len(row) != 2:
            return [f"{display_path(path)}:{row_number}: OUI row must have exactly two columns"]
        prefix = row[0][0].strip()
        vendor = row[1][0].strip()
        if not OUI_PREFIX_RE.match(prefix):
            return [f"{display_path(path)}:{row_number}: OUI prefix must be 6 lowercase hex digits"]
        if not vendor:
            return [f"{display_path(path)}:{row_number}: OUI row has an empty vendor"]
    return []


def public_domain_list_failures(path: str, contents: str) -> list[str]:
    """Validate the one embedded newline-delimited public-domain allowlist."""
    if path != PUBLIC_DOMAIN_LIST_PATH:
        return []
    lines, valid_lines = bounded_logical_lines(contents)
    if not valid_lines:
        return [f"{display_path(path)}: public-domain list contains too many logical lines"]
    seen: set[str] = set()
    reserved_suffixes = (
        ".example",
        ".invalid",
        ".test",
        ".localhost",
        ".local",
        ".lan",
        ".home",
        ".home.arpa",
        ".internal",
        ".localdomain",
        ".corp",
    )
    for index, raw_line in enumerate(lines, 1):
        candidate = raw_line.strip()
        if not candidate or candidate.startswith("#"):
            continue
        try:
            address = ipaddress.ip_address(candidate.rstrip("."))
        except ValueError:
            address = None
        valid = bool(
            raw_line == candidate
            and candidate == candidate.lower()
            and "." in candidate
            and DNS_NAME_RE.fullmatch(candidate)
            and address is None
            and not candidate.endswith(reserved_suffixes)
            and not TEMPLATE_HOST_RE.fullmatch(candidate)
            and candidate not in seen
        )
        if not valid:
            return [f"{display_path(path)}:{index}: public-domain list entry is not canonical and public"]
        seen.add(candidate)
    return []


def unifi_log_failures(path: str, contents: str) -> list[str]:
    """Validate identity-bearing fields in the reviewed synthetic UniFi logs."""
    if not path.startswith(ALLOWED_LOG_PREFIXES) or not has_extension_segment(PurePosixPath(path).name, ".log"):
        return []
    lines, valid_lines = bounded_logical_lines(contents)
    if not valid_lines:
        return [f"{display_path(path)}: reviewed log contains too many logical lines"]
    syslog = re.compile(
        r"^<\d{1,3}>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+(\S+)\s+(.+)$"
    )
    dhcp_ack = re.compile(r"\bDHCPACK\([^)]*\)\s+\S+\s+\S+\s+(\S+)")
    log_field = re.compile(r"(?i)(?<![a-z0-9_])([a-z][a-z0-9_-]*)=(?:\"([^\"]*)\"|([^\s|]+))")
    explicit_log_hosts = {"dhost", "shost", "dvchost"}

    def check_host(value: str, line_number_value: int) -> list[str]:
        candidate = value.strip().strip('"\'')
        if SYNTHETIC_LOG_HOST_RE.fullmatch(candidate):
            return []
        failures = validate_host(path, contents, candidate)
        if failures:
            return [diagnostic(path, line_number_value, "non-synthetic hostname in reviewed log")]
        return []

    for index, line in enumerate(lines, 1):
        if not line.strip():
            continue
        match = syslog.match(line)
        if not match:
            if line in ALLOWED_UNIFI_NOISE_LINES:
                continue
            return [f"{display_path(path)}:{index}: reviewed log line is not an approved synthetic syslog fixture"]
        failures = check_host(match.group(1), index)
        if failures:
            return failures
        body = match.group(2)
        ack = dhcp_ack.search(body)
        if ack:
            failures = check_host(ack.group(1), index)
            if failures:
                return failures
        for field in log_field.finditer(body):
            key = normalize_structured_key(field.group(1))
            effective_key = canonical_sql_typed_key(key)
            if effective_key in HOST_KEYS or key in explicit_log_hosts:
                failures = check_host(field.group(2) if field.group(2) is not None else field.group(3), index)
                if failures:
                    return failures
    return []


GENERIC_LINE_RE = re.compile(
    r'''^(?P<indent>[ \t]*)(?P<list>-\s*)?'''
    r'''(?P<key>"[^"\r\n]+"|'[^'\r\n]+'|[a-z][a-z0-9 ._-]*?)'''
    r'''\s*[:=]\s*(?P<value>.*?)\s*$''',
    re.IGNORECASE,
)
YAML_MAPPING_LINE_RE = re.compile(
    r'''^[ \t]*(?:-\s*)?(?:"[^"\r\n]+"|'[^'\r\n]+'|[a-z][a-z0-9 ._-]*?)\s*:\s*''',
    re.IGNORECASE,
)


def generic_fields(path: str, contents: str) -> tuple[list[GenericField], list[str]]:
    """Parse bounded scalar records with stable YAML/list and INI/TOML scopes."""
    suffix = PurePosixPath(path).suffix.lower()
    fields: list[GenericField] = []
    failures: list[str] = []
    section: tuple[str, ...] = ()
    seen_sections: set[tuple[str, ...]] = set()
    yaml_stack: list[tuple[int, str]] = []
    yaml_list_serial: dict[tuple[int, tuple[str, ...]], int] = {}
    yaml_block_indent: int | None = None
    text_record = 0
    offset = 0

    lines = contents.splitlines(keepends=True)
    if contents and not lines:
        lines = [contents]
    if len(lines) > MAX_STRUCTURED_VALUES:
        return [], [f"{display_path(path)}: structured text contains too many logical lines"]

    for line_number_value, raw_line in enumerate(lines, 1):
        line = raw_line.rstrip("\r\n\v\f\x1c\x1d\x1e\x85\u2028\u2029")
        stripped = line.strip()
        current_indent = len(line[: len(line) - len(line.lstrip(" \t"))].expandtabs(8))
        if suffix in {".yaml", ".yml"} and yaml_block_indent is not None:
            if not stripped or current_indent > yaml_block_indent:
                offset += len(raw_line)
                continue
            yaml_block_indent = None
        if not stripped:
            if suffix == ".txt":
                text_record += 1
            offset += len(raw_line)
            continue
        if stripped.startswith(("#", ";")):
            offset += len(raw_line)
            continue

        section_match = re.fullmatch(r"\[([A-Za-z0-9_. -]+)\]", stripped) if suffix in {".toml", ".ini"} else None
        if section_match:
            components = tuple(
                normalize_structured_key(component)
                for component in section_match.group(1).split(".")
                if normalize_structured_key(component)
            )
            if not components or components in seen_sections:
                failures.append(
                    f"{display_path(path)}:{line_number_value}: structured section is duplicate or ambiguous"
                )
                return fields, failures
            seen_sections.add(components)
            section = components
            offset += len(raw_line)
            continue

        if suffix in {".yaml", ".yml"} and stripped in {"---", "..."}:
            yaml_stack.clear()
            offset += len(raw_line)
            continue

        match = GENERIC_LINE_RE.match(line)
        if not match:
            offset += len(raw_line)
            continue
        raw_key = match.group("key")
        if len(raw_key) >= 2 and raw_key[0] == raw_key[-1] and raw_key[0] in {"'", '"'}:
            raw_key = raw_key[1:-1]
        key = normalize_structured_key(raw_key)
        raw_value = match.group("value").strip()
        value = raw_value
        if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
            value = value[1:-1]

        if suffix in {".yaml", ".yml"}:
            indent = len(match.group("indent").expandtabs(8))
            while yaml_stack and indent <= yaml_stack[-1][0]:
                yaml_stack.pop()
            parent = tuple(item for _level, item in yaml_stack)
            if match.group("list"):
                serial_key = (indent, parent)
                yaml_list_serial[serial_key] = yaml_list_serial.get(serial_key, 0) + 1
                yaml_stack.append((indent, f"[]#{yaml_list_serial[serial_key]}"))
                parent = tuple(item for _level, item in yaml_stack)
            scope = parent
            if re.fullmatch(r"[|>][+-]?", raw_value):
                yaml_block_indent = indent
            if raw_value == "":
                yaml_stack.append((indent + (1 if match.group("list") else 0), key))
        elif suffix in {".toml", ".ini"}:
            scope = section
        elif suffix == ".txt":
            scope = (f"record#{text_record}",)
        else:
            scope = ()

        value_start = offset + match.start("value")
        # Point at the decoded scalar inside optional quotes for exact span use.
        relative = raw_line[match.start("value"):match.end("value")].find(value)
        if relative >= 0:
            value_start += relative
        fields.append(
            GenericField(
                key=key,
                value=value,
                value_start=value_start,
                value_end=value_start + len(value),
                line=line_number_value,
                scope=scope,
            )
        )
        offset += len(raw_line)
    return fields, failures


def generic_structured_values(path: str, contents: str) -> Iterable[tuple[str, str]]:
    """Map bounded, scoped YAML/TOML/INI/text scalars and EAV pairs."""
    fields, failures = generic_fields(path, contents)
    if failures:
        return
    scoped: dict[tuple[str, ...], list[tuple[str, str]]] = {}
    for field in fields:
        scoped.setdefault(field.scope, []).append((field.key, field.value))
    for row in scoped.values():
        relational = list(relational_typed_entries(row))
        mapped_indexes = {index for index, _key, _value in relational}
        yield from (item for index, item in enumerate(row) if index not in mapped_indexes)
        yield from ((key, value) for _index, key, value in relational)


REVERSIBLE_STRUCTURED_ESCAPE_RE = re.compile(
    r"\\(?:x[0-9a-fA-F]{2}|u[0-9a-fA-F]{4}|U[0-9a-fA-F]{8})"
)
YAML_UNSUPPORTED_TOKEN_RE = re.compile(
    r"(?:^|[\[{},:])\s*(?:(?:---|[-?])\s*)*(?:!{1,2}[^\s,\[\]{}]*|!<[^>]*>|[&*][^\s,\[\]{}]+)"
)


def reversible_structured_escape_unsafe(text: str) -> bool:
    """Decode bounded x/u/U escapes and reject assembled private identifiers."""
    if not REVERSIBLE_STRUCTURED_ESCAPE_RE.search(text):
        return False

    def decode(match: re.Match[str]) -> str:
        token = match.group(0)
        try:
            return chr(int(token[2:], 16))
        except (OverflowError, ValueError):
            return token

    decoded = REVERSIBLE_STRUCTURED_ESCAPE_RE.sub(decode, text)
    for match in IPV4_RE.findall(decoded):
        try:
            address = ipaddress.IPv4Address(match)
        except ipaddress.AddressValueError:
            return True
        if not allowed_v4(address):
            return True
    for token in IPV6_TOKEN_RE.findall(decoded):
        if token.count(":") < 2:
            continue
        try:
            address6 = ipaddress.IPv6Address(token.split("%", 1)[0])
        except ipaddress.AddressValueError:
            continue
        if not allowed_v6(address6):
            return True
    mac_values = set(MAC_DELIMITED_RE.findall(decoded)) | set(MAC_CISCO_RE.findall(decoded))
    uuid_masked = UUID_RE.sub(" ", decoded)
    mac_values.update(MAC_COMPACT_RE.findall(uuid_masked))
    mac_values.update(MAC_CONTEXTUAL_COMPACT_RE.findall(uuid_masked))
    mac_values.update(MAC_CONTEXTUAL_TIGHT_RE.findall(uuid_masked))
    mac_values.update(MAC_HEX_COMPACT_RE.findall(uuid_masked))
    if any(not allowed_mac(value) for value in mac_values):
        return True
    return any(True for _candidate in local_name_candidates(decoded))


def github_actions_expression_end(text: str, start: int) -> int | None:
    """Return the end of one quote-aware GitHub expression, or None if incomplete."""
    index = start + 3
    quote = ""
    while index < len(text) - 1:
        char = text[index]
        if quote:
            if char == quote:
                # GitHub expressions escape a single quote by doubling it.
                if quote == "'" and index + 1 < len(text) and text[index + 1] == "'":
                    index += 2
                    continue
                quote = ""
            elif char == "\\" and quote == '"':
                index += 2
                continue
        elif char in {"'", '"'}:
            quote = char
        elif text.startswith("}}", index):
            return index + 2
        index += 1
    return None


def scan_github_actions_expressions(
    text: str,
) -> tuple[list[tuple[int, int]], int | None]:
    """Return complete expression spans and any quote-aware incomplete start."""
    spans: list[tuple[int, int]] = []
    cursor = 0
    while True:
        start = text.find("${{", cursor)
        if start < 0:
            return spans, None
        end = github_actions_expression_end(text, start)
        if end is None:
            return spans, start
        spans.append((start, end))
        cursor = end


def github_actions_expression_spans(text: str) -> list[tuple[int, int]]:
    """Locate complete GitHub expression spans without trusting their contents."""
    return scan_github_actions_expressions(text)[0]


def yaml_plain_scalar_terminator_unsafe(text: str) -> bool:
    """Reject YAML comment/mapping terminators in a proven plain scalar."""
    for index, char in enumerate(text):
        if char == ":" and (index + 1 == len(text) or text[index + 1].isspace()):
            return True
        if char == "#" and (index == 0 or text[index - 1].isspace()):
            return True
    return False


def structured_quote_syntax_unsafe(
    text: str,
    suffix: str,
    value_context: bool,
    allow_github_expressions: bool = False,
) -> bool:
    """Fail closed on decoded strings while preserving proven literal spans."""
    if reversible_structured_escape_unsafe(text):
        return True
    masked = list(text)
    yaml_quoted_end: int | None = None

    def mask(start: int, end: int) -> None:
        masked[start:end] = " " * (end - start)

    if suffix in {".yaml", ".yml"}:
        # YAML plain scalars may contain apostrophes. A literal string is
        # recognized only when it is the complete mapped value.
        if value_context and text.startswith("'"):
            index = 1
            while index < len(text):
                if text[index] != "'":
                    index += 1
                    continue
                if index + 1 < len(text) and text[index + 1] == "'":
                    index += 2
                    continue
                suffix_text = text[index + 1:].lstrip()
                if suffix_text and not suffix_text.startswith("#"):
                    return True
                mask(0, index + 1)
                yaml_quoted_end = index + 1
                break
            else:
                return True
        elif value_context and text.startswith('"'):
            end = text.find('"', 1)
            if end < 0 or "\\" in text[1:end]:
                return True
            suffix_text = text[end + 1:].lstrip()
            if suffix_text and not suffix_text.startswith("#"):
                return True
            mask(0, end + 1)
            yaml_quoted_end = end + 1
        elif re.search(r'"[^"\r\n]*\\', text):
            return True
    elif suffix == ".toml":
        # Only the entire mapped value may establish literal-string context.
        # Opportunistically masking quotes after arbitrary prefixes recreates
        # a reversible-escape bypass in malformed pseudo-TOML.
        if value_context and text.startswith("'''"):
            end = text.find("'''", 3)
            if end < 0:
                return True
            suffix_text = text[end + 3:].lstrip()
            if suffix_text and not suffix_text.startswith("#"):
                return True
            mask(0, end + 3)
        elif value_context and text.startswith("'"):
            end = text.find("'", 1)
            if end < 0:
                return True
            suffix_text = text[end + 1:].lstrip()
            if suffix_text and not suffix_text.startswith("#"):
                return True
            mask(0, end + 1)
        elif value_context and text.startswith('"'):
            if text.startswith('"""'):
                return True
            end = text.find('"', 1)
            if end < 0 or "\\" in text[1:end]:
                return True
            suffix_text = text[end + 1:].lstrip()
            if suffix_text and not suffix_text.startswith("#"):
                return True
            mask(0, end + 1)
        elif re.search(r'"[^"\r\n]*\\', text) or '"""' in text:
            return True

    if suffix in {".yaml", ".yml"} and allow_github_expressions:
        # A complete `${{ ... }}` mapped value is one YAML plain scalar. Its
        # internal `!`, comma, and braces are expression syntax, not YAML node
        # boundaries. Mask only for tag-token recognition; reversible escapes
        # and raw identifiers were inspected before this point.
        expression_text = text
        if yaml_quoted_end is not None:
            expression_text = text[:yaml_quoted_end]
        else:
            comment = re.search(r"(?<!\S)#", expression_text)
            if comment:
                expression_text = expression_text[:comment.start()]
        expression_spans, incomplete_expression = scan_github_actions_expressions(expression_text)
        if incomplete_expression is not None:
            return True
        for start, end in expression_spans:
            mask(start, end)
            # Retain a harmless scalar character. Otherwise a suffix such as
            # `&& ${{ ... }}` or `!important` is moved to the apparent start
            # of the YAML value and can be mistaken for an anchor or tag.
            masked[start] = "x"

    visible = "".join(masked)
    if suffix in {".yaml", ".yml"}:
        code = re.split(r"(?<!\S)#", visible, maxsplit=1)[0]
        if code.lstrip().startswith("%TAG") or YAML_UNSUPPORTED_TOKEN_RE.search(code):
            return True
    return False


def generic_format_failures(path: str, contents: str) -> list[str]:
    suffix = PurePosixPath(path).suffix.lower()
    generic_suffixes = {".yaml", ".yml", ".toml", ".ini", ".txt"} | OPERATIONAL_SUFFIXES
    if suffix not in generic_suffixes:
        return []
    lines, valid_lines = bounded_logical_lines(contents)
    if not valid_lines:
        return [f"{display_path(path)}: structured text contains too many logical lines"]
    strict_text = suffix == ".txt" and path != PUBLIC_DOMAIN_LIST_PATH and (
        is_inventory_path(path) or bool(RISK_DATA_NAME_RE.search(PurePosixPath(path).name))
    )
    strict_document = (
        suffix in {".yaml", ".yml", ".toml", ".ini"}
        and (is_reviewed_data_path(path) or bool(RISK_DATA_NAME_RE.search(PurePosixPath(path).name)))
    ) or strict_text
    duplicate_policy = suffix in {".yaml", ".yml", ".toml", ".ini"} or strict_text
    inventory_document = is_inventory_path(path)
    fields, parse_failures = generic_fields(path, contents)
    if parse_failures:
        return parse_failures
    github_multiline_plain_scalar_lines: set[int] = set()
    if suffix in {".yaml", ".yml"} and path.startswith(".github/workflows/"):
        # GitHub permits an `if` plain scalar (with or without `${{ }}`) to fold
        # across more-indented physical YAML lines. Establish that scalar's
        # exact boundary before the per-line tag lexer so `!cancelled()` is not
        # reinterpreted as a YAML tag. This exception is limited to workflow
        # `if` values and never crosses a peer key.
        line_index = 0
        while line_index < len(lines):
            start_match = GENERIC_LINE_RE.match(lines[line_index])
            if not start_match:
                line_index += 1
                continue
            raw_key = start_match.group("key")
            if len(raw_key) >= 2 and raw_key[0] == raw_key[-1] and raw_key[0] in {"'", '"'}:
                raw_key = raw_key[1:-1]
            first_value = start_match.group("value").strip()
            list_prefix = start_match.group("list") or ""
            if normalize_structured_key(raw_key) == "if" and (
                "\t" in start_match.group("indent") or "\t" in list_prefix
            ):
                return [
                    f"{display_path(path)}:{line_index + 1}: multiline GitHub condition uses tab indentation"
                ]
            plain_start_forbidden = first_value[:1] in set("!&*{}[],#|>@`\"'%") or (
                first_value[:1] in {"-", "?", ":"}
                and (len(first_value) == 1 or first_value[1].isspace())
            )
            if (
                normalize_structured_key(raw_key) != "if"
                or not first_value
                or plain_start_forbidden
                or (list_prefix and not list_prefix[1:].isspace())
                or re.search(r"(?<!\S)#", first_value)
            ):
                line_index += 1
                continue
            base_indent = len(
                (start_match.group("indent") + list_prefix).expandtabs(8)
            )
            continuation_end = line_index + 1
            while continuation_end < len(lines):
                continuation = lines[continuation_end]
                continuation_stripped = continuation.strip()
                continuation_prefix = continuation[
                    : len(continuation) - len(continuation.lstrip(" \t"))
                ]
                if "\t" in continuation_prefix:
                    return [
                        f"{display_path(path)}:{continuation_end + 1}: multiline GitHub condition uses tab indentation"
                    ]
                continuation_indent = len(continuation_prefix)
                if continuation_stripped and continuation_indent <= base_indent:
                    break
                continuation_end += 1
            if continuation_end == line_index + 1:
                line_index += 1
                continue
            pieces = [first_value, *lines[line_index + 1:continuation_end]]
            combined = "\n".join(pieces)
            _expression_spans, incomplete_expression = scan_github_actions_expressions(combined)
            if incomplete_expression is not None:
                return [
                    f"{display_path(path)}:{line_index + 1}: multiline GitHub expression is not closed within its YAML scalar"
                ]
            if yaml_plain_scalar_terminator_unsafe(combined):
                return [
                    f"{display_path(path)}:{line_index + 1}: multiline GitHub condition crosses a YAML scalar terminator"
                ]
            for continuation_line in lines[line_index + 1:continuation_end]:
                continuation_stripped = continuation_line.strip()
                if not continuation_stripped:
                    continue
                if (
                    YAML_MAPPING_LINE_RE.match(continuation_line)
                    or continuation_stripped in {"---", "..."}
                    or continuation_stripped.startswith("%")
                    or re.match(r"^[-?]\s+", continuation_stripped)
                    or re.search(r"(?<!\S)#", continuation_stripped)
                ):
                    return [
                        f"{display_path(path)}:{line_index + 1}: multiline GitHub condition contains a structured YAML continuation"
                    ]
            if reversible_structured_escape_unsafe(combined):
                return [
                    f"{display_path(path)}:{line_index + 1}: quoted/tagged structured syntax cannot be sanitized safely"
                ]
            github_multiline_plain_scalar_lines.update(
                range(line_index, continuation_end)
            )
            line_index = continuation_end
    seen_by_scope: dict[tuple[str, ...], set[str]] = {}
    field_by_line = {field.line: field for field in fields}
    yaml_block_indent: int | None = None
    for index, line in enumerate(lines):
        stripped = line.strip()
        current_indent = len(line[: len(line) - len(line.lstrip(" \t"))].expandtabs(8))
        if suffix in {".yaml", ".yml"} and yaml_block_indent is not None:
            if not stripped or current_indent > yaml_block_indent:
                if reversible_structured_escape_unsafe(line):
                    return [
                        f"{display_path(path)}:{index + 1}: reversible structured escape cannot be sanitized safely"
                    ]
                continue
            yaml_block_indent = None
        if not stripped:
            continue
        match = GENERIC_LINE_RE.match(line)
        if suffix in {".yaml", ".yml", ".toml"} and index not in github_multiline_plain_scalar_lines:
            syntax_text = match.group("value").strip() if match else stripped
            if index == 0 and suffix in {".yaml", ".yml"} and syntax_text.startswith("\ufeff"):
                syntax_text = syntax_text[1:].lstrip()
            if structured_quote_syntax_unsafe(
                syntax_text,
                suffix,
                match is not None,
                path.startswith(".github/workflows/"),
            ):
                return [
                    f"{display_path(path)}:{index + 1}: quoted/tagged structured syntax cannot be sanitized safely"
                ]
        if stripped.startswith(("#", ";")):
            continue
        section = re.fullmatch(r"\[([A-Za-z0-9_. -]+)\]", stripped) if suffix in {".toml", ".ini"} else None
        if section:
            section_keys = {
                normalize_structured_key(component) for component in section.group(1).split(".")
            }
            if inventory_document and any(key not in INVENTORY_SCHEMA_KEYS for key in section_keys):
                return [f"{display_path(path)}:{index + 1}: inventory section is not an approved schema key"]
            continue
        if suffix in {".yaml", ".yml"} and stripped in {"---", "..."}:
            continue
        if not match:
            if strict_document:
                return [f"{display_path(path)}:{index + 1}: structured line cannot be sanitized safely"]
            continue
        field = field_by_line.get(index + 1)
        if field is None:
            if strict_document:
                return [f"{display_path(path)}:{index + 1}: structured field cannot be mapped safely"]
            continue
        key = field.key
        if inventory_document and key not in INVENTORY_SCHEMA_KEYS:
            return [f"{display_path(path)}:{index + 1}: inventory field is not an approved schema key"]
        if duplicate_policy:
            seen = seen_by_scope.setdefault(field.scope, set())
            if key in seen:
                return [f"{display_path(path)}:{index + 1}: duplicate normalized structured key"]
            seen.add(key)
        typed = bool(canonical_sql_typed_key(key) or key in RELATIONAL_TYPE_VALUE_KEYS or key in RELATIONAL_ALL_VALUE_KEYS)
        raw_value = match.group("value").strip()
        if suffix in {".yaml", ".yml"} and re.fullmatch(r"[|>][+-]?", raw_value):
            yaml_block_indent = current_indent
        if (typed or strict_document) and raw_value.startswith((">", "|", "[", "{")):
            return [f"{display_path(path)}:{index + 1}: structured value uses unsupported syntax"]
        if not typed:
            continue
        if raw_value == "" and index + 1 < len(lines):
            following = lines[index + 1]
            if following[:1].isspace() and following.strip() and not GENERIC_LINE_RE.match(following):
                return [f"{display_path(path)}:{index + 1}: typed structured continuation cannot be sanitized safely"]
    return []


def json_version_value_spans(contents: str) -> list[tuple[int, int]]:
    """Map JSON version scalars to exact raw tokens with immediate-object scope."""
    spans: list[tuple[int, int]] = []
    length = len(contents)

    def skip_space(index: int) -> int:
        while index < length and contents[index] in " \t\r\n":
            index += 1
        return index

    def parse_string(index: int) -> tuple[int, str, int, int]:
        match = JSON_STRING_RE.match(contents, index)
        if not match:
            raise ValueError("invalid JSON string token")
        return match.end(), str(json.loads(match.group(0))), match.start(), match.end()

    def collect_row(row: list[tuple[str, str, int, int]]) -> None:
        pairs = [(key, value) for key, value, _start, _end in row]
        mapped = list(relational_typed_entries(pairs))
        mapped_indexes = {index for index, _key, _value in mapped}
        for index, (key, value, start, end) in enumerate(row):
            if (
                index not in mapped_indexes
                and canonical_sql_typed_key(key) in VERSION_KEYS
                and safe_version_value(value)
            ):
                spans.append((start, end))
        for index, effective_key, value in mapped:
            if effective_key in VERSION_KEYS and safe_version_value(value):
                spans.append((row[index][2], row[index][3]))

    def parse_value(index: int) -> tuple[int, tuple[str, int, int] | None]:
        index = skip_space(index)
        if index >= length:
            raise ValueError("missing JSON value")
        if contents[index] == '"':
            end, value, start, raw_end = parse_string(index)
            return end, (value, start, raw_end)
        if contents[index] == "{":
            return parse_object(index), None
        if contents[index] == "[":
            return parse_array(index), None
        end = index
        while end < length and contents[end] not in " \t\r\n,]}":
            end += 1
        if end == index:
            raise ValueError("invalid JSON scalar")
        json.loads(contents[index:end])
        return end, None

    def parse_object(index: int) -> int:
        row: list[tuple[str, str, int, int]] = []
        index = skip_space(index + 1)
        if index < length and contents[index] == "}":
            return index + 1
        while True:
            end, raw_key, _key_start, _key_end = parse_string(index)
            key = normalize_structured_key(raw_key)
            index = skip_space(end)
            if index >= length or contents[index] != ":":
                raise ValueError("JSON object key has no value")
            index, scalar = parse_value(index + 1)
            if scalar is not None:
                value, start, raw_end = scalar
                row.append((key, value, start, raw_end))
            index = skip_space(index)
            if index >= length:
                raise ValueError("unterminated JSON object")
            if contents[index] == "}":
                collect_row(row)
                return index + 1
            if contents[index] != ",":
                raise ValueError("invalid JSON object separator")
            index = skip_space(index + 1)

    def parse_array(index: int) -> int:
        index = skip_space(index + 1)
        if index < length and contents[index] == "]":
            return index + 1
        while True:
            index, _scalar = parse_value(index)
            index = skip_space(index)
            if index >= length:
                raise ValueError("unterminated JSON array")
            if contents[index] == "]":
                return index + 1
            if contents[index] != ",":
                raise ValueError("invalid JSON array separator")
            index = skip_space(index + 1)

    try:
        index = 1 if contents.startswith("\ufeff") else 0
        while (index := skip_space(index)) < length:
            index, _scalar = parse_value(index)
    except (json.JSONDecodeError, RecursionError, ValueError):
        return []
    return sorted(set(spans))


def version_value_spans(
    path: str,
    contents: str,
    sql_analysis: tuple[list[tuple[str, str, int, int]], list[tuple[int, str]]] | None = None,
    xml_analysis: tuple[
        list[tuple[str, str]], list[str], list[tuple[int, int]]
    ]
    | None = None,
) -> list[tuple[int, int]]:
    """Locate only version-typed occurrences eligible for dotted-quad syntax."""
    suffix = PurePosixPath(path).suffix.lower()
    spans: list[tuple[int, int]] = []

    if suffix in {".yaml", ".yml", ".toml", ".ini", ".txt"}:
        fields, generic_failures = generic_fields(path, contents)
        if not generic_failures:
            scoped: dict[tuple[str, ...], list[GenericField]] = {}
            for field in fields:
                scoped.setdefault(field.scope, []).append(field)
                if field.key in VERSION_KEYS and safe_version_value(field.value):
                    spans.append((field.value_start, field.value_end))
            for row in scoped.values():
                for type_key, value_keys in RELATIONAL_TYPE_VALUE_KEYS.items():
                    resolved = {
                        canonical_sql_typed_key(field.value)
                        for field in row
                        if field.key == type_key and canonical_sql_typed_key(field.value)
                    }
                    if len(resolved) != 1 or not resolved.issubset(VERSION_KEYS):
                        continue
                    for field in row:
                        if field.key in value_keys and safe_version_value(field.value):
                            spans.append((field.value_start, field.value_end))

    if suffix == ".json":
        spans.extend(json_version_value_spans(contents))

    if suffix in {".csv", ".tsv"}:
        delimiter = "\t" if suffix == ".tsv" else ","
        records, valid_csv = csv_records_with_spans(contents, delimiter)
        if valid_csv and records:
            header = [normalize_structured_key(value) for value, _start, _end in records[0]]
            version_columns = {index for index, name in enumerate(header) if name in VERSION_KEYS}
            for row in records[1:]:
                if len(row) != len(header):
                    continue
                row_version_columns = set(version_columns)
                for type_key, value_keys in RELATIONAL_TYPE_VALUE_KEYS.items():
                    discriminator_columns = [index for index, name in enumerate(header) if name == type_key]
                    resolved = {
                        canonical_sql_typed_key(row[index][0])
                        for index in discriminator_columns
                        if canonical_sql_typed_key(row[index][0])
                    }
                    if len(resolved) == 1 and resolved.issubset(VERSION_KEYS):
                        row_version_columns.update(
                            index for index, name in enumerate(header) if name in value_keys
                        )
                for index, (value, start, end) in enumerate(row):
                    if index not in row_version_columns or not safe_version_value(value):
                        continue
                    raw = contents[start:end]
                    relative = raw.find(value)
                    if relative >= 0:
                        spans.append((start + relative, start + relative + len(value)))

    if suffix == ".xml":
        parsed_xml = xml_analysis if xml_analysis is not None else xml_structured_values(contents)
        if not parsed_xml[1]:
            spans.extend(parsed_xml[2])
    if suffix == ".sql":
        sql_values = sql_analysis[0] if sql_analysis is not None else list(sql_field_values(contents))
        for key, value, start, end in sql_values:
            if key in VERSION_KEYS and safe_version_value(value):
                spans.append((start, end))

    merged: list[tuple[int, int]] = []
    for start, end in sorted(set(spans)):
        if merged and start <= merged[-1][1]:
            merged[-1] = (merged[-1][0], max(end, merged[-1][1]))
        else:
            merged.append((start, end))
    return merged


def span_contains(spans: list[tuple[int, int]], starts: list[int], start: int, end: int) -> bool:
    """Test containment in sorted non-overlapping spans in logarithmic time."""
    index = bisect_right(starts, start) - 1
    return index >= 0 and spans[index][0] <= start and end <= spans[index][1]


def json_documents(path: str, contents: str) -> tuple[list[Any], bool]:
    """Decode strict JSON, with JSON-lines allowed only in its reviewed corpus."""
    candidate = contents.removeprefix("\ufeff")

    def unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        normalized_keys: set[str] = set()
        for key, value in pairs:
            normalized = normalize_structured_key(key)
            if key in result or normalized in normalized_keys:
                raise ValueError("duplicate JSON key")
            result[key] = value
            normalized_keys.add(normalized)
        return result

    def reject_constant(_value: str) -> None:
        raise ValueError("non-finite JSON number")

    def decode(value: str) -> Any:
        return json.loads(value, object_pairs_hook=unique_object, parse_constant=reject_constant)

    def shape_size(document: Any) -> int | None:
        pending = [document]
        seen_values = 0
        while pending:
            value = pending.pop()
            seen_values += 1
            if seen_values > MAX_STRUCTURED_VALUES:
                return None
            if isinstance(value, list):
                seen_values += sum(not isinstance(item, (dict, list)) for item in value)
                if seen_values > MAX_STRUCTURED_VALUES:
                    return None
                pending.extend(item for item in value if isinstance(item, (dict, list)))
                continue
            if not isinstance(value, dict):
                continue
            relational_contexts: dict[str, str] = {}
            for type_key, value_keys in RELATIONAL_TYPE_VALUE_KEYS.items():
                type_value = next(
                    (child for raw_key, child in value.items() if normalize_structured_key(raw_key) == type_key),
                    "",
                )
                if isinstance(type_value, (dict, list)):
                    return None
                resolved_type = canonical_sql_typed_key(type_value)
                if resolved_type:
                    for value_key in value_keys:
                        relational_contexts[value_key] = resolved_type
            for raw_key, child in value.items():
                if not isinstance(child, (dict, list)):
                    seen_values += 1
                    if seen_values > MAX_STRUCTURED_VALUES:
                        return None
                key = normalize_structured_key(raw_key)
                if isinstance(child, (dict, list)):
                    if (
                        key in RELATIONAL_TYPE_VALUE_KEYS
                        or canonical_sql_typed_key(key)
                        or key in relational_contexts
                    ):
                        return None
                    pending.append(child)
        return seen_values

    if path.startswith(JSON_LINES_PREFIXES):
        documents: list[Any] = []
        lines, valid_lines = bounded_logical_lines(candidate)
        if not valid_lines:
            return [], False
        total_values = 0
        try:
            for line in lines:
                if line.strip():
                    document = decode(line)
                    document_values = shape_size(document)
                    if document_values is None or total_values + document_values > MAX_STRUCTURED_VALUES:
                        return [], False
                    total_values += document_values
                    documents.append(document)
        except (json.JSONDecodeError, ValueError, RecursionError):
            return [], False
        return documents, True
    try:
        document = decode(candidate)
        return ([document], True) if shape_size(document) is not None else ([], False)
    except (json.JSONDecodeError, ValueError, RecursionError):
        return [], False


def xml_structured_values(
    contents: str,
) -> tuple[list[tuple[str, str]], list[str], list[tuple[int, int]]]:
    """Strictly decode XML without DTDs and retain EAV scope per element."""
    if XML_UNSAFE_DECL_RE.search(contents):
        return [], ["XML DTD/entity/CDATA constructs cannot be sanitized safely"], []

    output: list[tuple[str, str]] = []
    suppressed_output_indexes: set[int] = set()
    version_spans: list[tuple[int, int]] = []
    frames: list[XMLFrame] = []
    element_count = 0
    root_seen = False
    root_closed = False
    declaration_seen = False
    next_version_exemption = 0
    name_pattern = re.compile(r"[A-Za-z_][A-Za-z0-9_.:-]*")

    def append_output(key: str, value: str) -> None:
        if len(output) >= MAX_XML_OUTPUT_VALUES:
            raise XMLInspectionError("XML contains too many values to sanitize safely")
        output.append((key, value))

    def local_name(raw: str) -> str:
        return normalize_structured_key(raw.rsplit(":", 1)[-1])

    def decode_entities(raw: str) -> str:
        decoded: list[str] = []
        index = 0
        named = {"amp": "&", "lt": "<", "gt": ">", "apos": "'", "quot": '"'}
        while index < len(raw):
            if raw[index] != "&":
                codepoint = ord(raw[index])
                if not (
                    codepoint in {0x9, 0xA, 0xD}
                    or 0x20 <= codepoint <= 0xD7FF
                    or 0xE000 <= codepoint <= 0xFFFD
                    or 0x10000 <= codepoint <= 0x10FFFF
                ):
                    raise XMLInspectionError("XML contains an invalid raw character")
                decoded.append(raw[index])
                index += 1
                continue
            end = raw.find(";", index + 1, min(len(raw), index + 32))
            if end < 0:
                raise XMLInspectionError("XML contains an invalid entity reference")
            entity = raw[index + 1:end]
            if entity in named:
                value = named[entity]
            elif re.fullmatch(r"#[0-9]+", entity):
                value = chr(int(entity[1:], 10))
            elif re.fullmatch(r"#x[0-9a-fA-F]+", entity):
                value = chr(int(entity[2:], 16))
            else:
                raise XMLInspectionError("XML contains an unknown entity reference")
            codepoint = ord(value)
            if not (
                codepoint in {0x9, 0xA, 0xD}
                or 0x20 <= codepoint <= 0xD7FF
                or 0xE000 <= codepoint <= 0xFFFD
                or 0x10000 <= codepoint <= 0x10FFFF
            ):
                raise XMLInspectionError("XML contains an invalid character reference")
            decoded.append(value)
            index = end + 1
        return "".join(decoded)

    def start_element(
        raw_tag: str, raw_attributes: list[tuple[str, str, int, int]]
    ) -> None:
        nonlocal element_count, root_seen, root_closed
        if not frames:
            if root_seen or root_closed:
                raise XMLInspectionError("XML must contain exactly one root element")
            root_seen = True
        element_count += 1
        if element_count > MAX_XML_ELEMENTS:
            raise XMLInspectionError("XML contains too many elements to sanitize safely")
        if len(frames) >= MAX_XML_DEPTH:
            raise XMLInspectionError("XML nesting is too deep to sanitize safely")
        if ":" in raw_tag:
            raise XMLInspectionError("XML namespaces are not supported by the sanitation grammar")
        if frames:
            frames[-1].has_children = True
        append_output(STRUCTURED_NAME_KEY, raw_tag)

        attributes: list[tuple[str, str]] = []
        seen: set[str] = set()
        attribute_raw_spans: list[tuple[int, int]] = []
        for raw_key, value, raw_start, raw_end in raw_attributes:
            if ":" in raw_key:
                raise XMLInspectionError("XML namespaces are not supported by the sanitation grammar")
            key = local_name(raw_key)
            if key in seen:
                raise XMLInspectionError("XML contains duplicate normalized attributes")
            seen.add(key)
            append_output(STRUCTURED_NAME_KEY, raw_key)
            attributes.append((key, value))
            attribute_raw_spans.append((raw_start, raw_end))

        relational = list(relational_typed_entries(attributes))
        mapped_indexes = {index for index, _key, _value in relational}
        for index, (key, value) in enumerate(attributes):
            if index not in mapped_indexes:
                append_output(key, value)
        for _index, key, value in relational:
            append_output(key, value)
        for index, (key, value) in enumerate(attributes):
            if (
                index not in mapped_indexes
                and canonical_sql_typed_key(key) in VERSION_KEYS
                and safe_version_value(value)
            ):
                version_spans.append(attribute_raw_spans[index])
        for index, key, value in relational:
            if key in VERSION_KEYS and safe_version_value(value):
                version_spans.append(attribute_raw_spans[index])

        attribute_map = dict(attributes)
        address_type = normalize_structured_key(attribute_map.get("addrtype", ""))
        address = attribute_map.get("addr", "")
        if address and address_type == "mac":
            append_output("mac", address)
        elif address and address_type in {"ipv4", "ip"}:
            append_output("ip", address)
        tag = local_name(raw_tag)
        if tag == "hostname" and attribute_map.get("name"):
            append_output("hostname", attribute_map["name"])
        frames.append(
            XMLFrame(
                raw_tag=raw_tag,
                tag=tag,
                text_parts=[],
                residual_pieces=[],
                raw_text_spans=[],
                text_length=0,
                child_values=[],
                direct_child_values=[],
                direct_child_raw_spans=[],
                direct_child_piece_ranges=[],
                direct_child_is_leaf=[],
                direct_child_output_indexes=[],
                has_children=False,
                has_direct_text=False,
            )
        )

    def character_data(data: str, raw_start: int, raw_end: int) -> None:
        if not frames or not data:
            return
        frame = frames[-1]
        frame.text_length += len(data)
        if frame.text_length > MAX_XML_VALUE_CHARS:
            raise XMLInspectionError("XML element text is too large to sanitize safely")
        frame.text_parts.append(data)
        frame.residual_pieces.append(XMLResidualPiece(data))
        frame.raw_text_spans.append((raw_start, raw_end))
        if data.strip():
            frame.has_direct_text = True

    def end_element(raw_tag: str) -> None:
        nonlocal root_closed, next_version_exemption
        if not frames:
            raise XMLInspectionError("XML closing tag has no matching start tag")
        frame = frames.pop()
        if frame.raw_tag != raw_tag:
            raise XMLInspectionError("XML closing tag does not match its start tag")
        aggregate = "".join(frame.text_parts).strip()
        for type_key in RELATIONAL_TYPE_VALUE_KEYS:
            discriminator_values = [
                value for key, value in frame.direct_child_values if key == type_key
            ]
            if len(discriminator_values) > 1:
                raise XMLInspectionError("XML relational discriminator is ambiguous")
        relational_entries = list(relational_typed_entries(frame.child_values))
        relational_entries.extend(relational_sequence_entries(frame.child_values))
        relational_entries = list(dict.fromkeys(relational_entries))
        relational = list(dict.fromkeys((key, value) for _index, key, value in relational_entries))
        direct_relational_entries = list(relational_typed_entries(frame.direct_child_values))
        direct_relational_entries.extend(relational_sequence_entries(frame.direct_child_values))
        direct_relational_entries = list(dict.fromkeys(direct_relational_entries))
        for index, key, value in direct_relational_entries:
            if key in VERSION_KEYS and safe_version_value(value):
                version_spans.extend(frame.direct_child_raw_spans[index])
        effective_tag = canonical_sql_typed_key(frame.tag)
        if not frame.has_children and effective_tag in VERSION_KEYS and safe_version_value(aggregate):
            version_spans.extend(frame.raw_text_spans)
        mapped_indexes: set[int] = set()
        if relational:
            # Child EAV values are emitted before their parent closes. Suppress
            # only the exact direct-child outputs consumed by this relation;
            # matching by decoded text would let an unrelated escaped value
            # inherit another occurrence's type.
            mapped_indexes = {
                index
                for index, _key, _value in relational_typed_entries(frame.direct_child_values)
            }
            mapped_indexes.update(
                index
                for index, _key, _value in relational_sequence_entries(frame.direct_child_values)
            )
            for index in mapped_indexes:
                output_index = frame.direct_child_output_indexes[index]
                if output_index is not None:
                    suppressed_output_indexes.add(output_index)
        for key, value in relational:
            append_output(key, value)

        # Mark exact, complete, direct-leaf version occurrences. The original
        # pieces and their occurrence IDs propagate through wrappers so an
        # ancestor can still detect an identifier assembled across boundaries.
        maskable_indexes = {
            index
            for index, key, value in relational_typed_entries(frame.direct_child_values)
            if key in VERSION_KEYS and safe_version_value(value)
        }
        maskable_indexes.update(
            index
            for index, key, value in relational_sequence_entries(frame.direct_child_values)
            if key in VERSION_KEYS and safe_version_value(value)
        )
        maskable_indexes.update(
            index
            for index, (key, value) in enumerate(frame.direct_child_values)
            if canonical_sql_typed_key(key) in VERSION_KEYS and safe_version_value(value)
        )
        for child_index in sorted(maskable_indexes):
            if not frame.direct_child_is_leaf[child_index]:
                continue
            piece_start, piece_end = frame.direct_child_piece_ranges[child_index]
            next_version_exemption += 1
            for piece in frame.residual_pieces[piece_start:piece_end]:
                piece.version_exemption = next_version_exemption
        if not frame.has_children and effective_tag in VERSION_KEYS and safe_version_value(aggregate):
            next_version_exemption += 1
            for piece in frame.residual_pieces:
                piece.version_exemption = next_version_exemption

        full_aggregate = "".join(piece.text for piece in frame.residual_pieces)
        if any(piece.version_exemption is not None for piece in frame.residual_pieces):
            exemption_owners: list[int | None] = []
            for piece in frame.residual_pieces:
                exemption_owners.extend([piece.version_exemption] * len(piece.text))
            uncovered_prefix = [0]
            for owner in exemption_owners:
                uncovered_prefix.append(uncovered_prefix[-1] + (owner is None))
            cleared_exemptions: set[int] = set()
            for candidate_start, candidate_end in identifier_candidate_spans(full_aggregate):
                if uncovered_prefix[candidate_end] == uncovered_prefix[candidate_start]:
                    continue
                cleared_exemptions.update(
                    owner
                    for owner in exemption_owners[candidate_start:candidate_end]
                    if owner is not None
                )
            if cleared_exemptions:
                for piece in frame.residual_pieces:
                    if piece.version_exemption in cleared_exemptions:
                        piece.version_exemption = None
        residual_aggregate = "".join(
            "\n" if piece.version_exemption is not None else piece.text
            for piece in frame.residual_pieces
        ).strip()
        aggregate_output_index: int | None = None
        output_aggregate = (
            aggregate
            if not frame.has_children and effective_tag in VERSION_KEYS and safe_version_value(aggregate)
            else residual_aggregate
        )
        if output_aggregate and (
            not frame.has_children
            or canonical_sql_typed_key(frame.tag)
            or frame.tag in RELATIONAL_TYPE_VALUE_KEYS
            or frame.tag in RELATIONAL_ALL_VALUE_KEYS
            or frame.has_direct_text
            or len(frame.direct_child_values) > 1
        ):
            aggregate_output_index = len(output)
            append_output(frame.tag, output_aggregate)
        if frames and aggregate:
            parent = frames[-1]
            parent.text_length += len(aggregate)
            if parent.text_length > MAX_XML_VALUE_CHARS:
                raise XMLInspectionError("XML element text is too large to sanitize safely")
            piece_start = len(parent.residual_pieces)
            parent.text_parts.append(aggregate)
            parent.residual_pieces.extend(frame.residual_pieces)
            piece_end = len(parent.residual_pieces)
            parent.raw_text_spans.extend(frame.raw_text_spans)
            parent.direct_child_values.append((frame.tag, aggregate))
            parent.direct_child_raw_spans.append(
                [] if frame.has_children else list(frame.raw_text_spans)
            )
            parent.direct_child_piece_ranges.append((piece_start, piece_end))
            parent.direct_child_is_leaf.append(not frame.has_children)
            parent.direct_child_output_indexes.append(aggregate_output_index)
            parent.child_values.append((frame.tag, aggregate))
            parent.child_values.extend(frame.child_values)
        elif not frames:
            root_closed = True

    try:
        index = 1 if contents.startswith("\ufeff") else 0
        while index < len(contents):
            if contents[index] != "<":
                end = contents.find("<", index)
                if end < 0:
                    end = len(contents)
                raw_text = contents[index:end]
                if frames:
                    if "]]>" in raw_text:
                        raise XMLInspectionError("XML contains a forbidden CDATA terminator")
                    character_data(decode_entities(raw_text), index, end)
                elif raw_text.strip():
                    raise XMLInspectionError("XML contains text outside its root element")
                index = end
                continue

            if contents.startswith("<!--", index):
                raise XMLInspectionError("XML comments cannot be sanitized safely")
            if contents.startswith("<?", index):
                if declaration_seen:
                    raise XMLInspectionError("XML declaration may appear only once")
                end = contents.find("?>", index + 2)
                if end < 0:
                    raise XMLInspectionError("XML processing instruction is not terminated safely")
                instruction = contents[index + 2:end].strip()
                if root_seen or not XML_DECLARATION_RE.fullmatch(instruction):
                    raise XMLInspectionError("XML processing instructions cannot be sanitized safely")
                if "&" in instruction or "<" in instruction or ">" in instruction:
                    raise XMLInspectionError("XML declaration cannot be sanitized safely")
                declaration_seen = True
                index = end + 2
                continue
            if contents.startswith("<!", index):
                raise XMLInspectionError("XML declarations cannot be sanitized safely")
            if contents.startswith("</", index):
                cursor = index + 2
                while cursor < len(contents) and contents[cursor].isspace():
                    cursor += 1
                match = name_pattern.match(contents, cursor)
                if not match:
                    raise XMLInspectionError("XML closing tag cannot be mapped safely")
                raw_tag = match.group(0)
                cursor = match.end()
                while cursor < len(contents) and contents[cursor].isspace():
                    cursor += 1
                if cursor >= len(contents) or contents[cursor] != ">":
                    raise XMLInspectionError("XML closing tag is not terminated safely")
                end_element(raw_tag)
                index = cursor + 1
                continue

            cursor = index + 1
            match = name_pattern.match(contents, cursor)
            if not match:
                raise XMLInspectionError("XML start tag cannot be mapped safely")
            raw_tag = match.group(0)
            cursor = match.end()
            attributes: list[tuple[str, str, int, int]] = []
            self_closing = False
            while True:
                whitespace_start = cursor
                while cursor < len(contents) and contents[cursor].isspace():
                    cursor += 1
                had_whitespace = cursor > whitespace_start
                if cursor >= len(contents):
                    raise XMLInspectionError("XML start tag is not terminated safely")
                if contents.startswith("/>", cursor):
                    self_closing = True
                    cursor += 2
                    break
                if contents[cursor] == ">":
                    cursor += 1
                    break
                if not had_whitespace:
                    raise XMLInspectionError("XML attributes must be separated safely")
                attribute = name_pattern.match(contents, cursor)
                if not attribute:
                    raise XMLInspectionError("XML attribute cannot be mapped safely")
                raw_key = attribute.group(0)
                cursor = attribute.end()
                while cursor < len(contents) and contents[cursor].isspace():
                    cursor += 1
                if cursor >= len(contents) or contents[cursor] != "=":
                    raise XMLInspectionError("XML attribute must have a quoted value")
                cursor += 1
                while cursor < len(contents) and contents[cursor].isspace():
                    cursor += 1
                if cursor >= len(contents) or contents[cursor] not in {"'", '"'}:
                    raise XMLInspectionError("XML attribute must have a quoted value")
                quote = contents[cursor]
                value_start = cursor + 1
                value_end = contents.find(quote, value_start)
                if value_end < 0:
                    raise XMLInspectionError("XML attribute value is not terminated safely")
                raw_value = contents[value_start:value_end]
                if "<" in raw_value:
                    raise XMLInspectionError("XML attribute contains an invalid delimiter")
                attributes.append(
                    (raw_key, decode_entities(raw_value), value_start, value_end)
                )
                cursor = value_end + 1

            start_element(raw_tag, attributes)
            if self_closing:
                end_element(raw_tag)
            index = cursor

        if frames:
            raise XMLInspectionError("XML document is not terminated safely")
        if not root_seen or not root_closed:
            raise XMLInspectionError("XML must contain exactly one complete root element")
    except (UnicodeError, ValueError, XMLInspectionError) as error:
        reason = str(error) if isinstance(error, XMLInspectionError) else "XML could not be decoded safely"
        return [], [reason], []
    return [
        value for index, value in enumerate(output) if index not in suppressed_output_indexes
    ], [], sorted(set(version_spans))


def structured_values(
    path: str,
    contents: str,
    sql_analysis: tuple[list[tuple[str, str, int, int]], list[tuple[int, str]]] | None = None,
    xml_analysis: tuple[
        list[tuple[str, str]], list[str], list[tuple[int, int]]
    ]
    | None = None,
) -> Iterable[tuple[str, str]]:
    suffix = PurePosixPath(path).suffix.lower()
    parsed_structured = False

    if suffix == ".json":
        documents, valid_json = json_documents(path, contents)

        def walk(root: Any) -> Iterable[tuple[str, str]]:
            pending: list[tuple[Any, str]] = [(root, "")]
            while pending:
                value, inherited_key = pending.pop()
                if isinstance(value, dict):
                    scalar_row: list[tuple[str, str]] = []
                    children: list[tuple[Any, str]] = []
                    for key, child in value.items():
                        normalized = normalize_structured_key(key)
                        yield STRUCTURED_NAME_KEY, str(key)
                        if isinstance(child, (str, int, float)) and not isinstance(child, bool):
                            scalar_row.append((normalized, str(child)))
                            if inherited_key:
                                yield inherited_key, str(child)
                        elif isinstance(child, (dict, list)):
                            children.append((child, canonical_sql_typed_key(normalized) or inherited_key))
                    relational = list(relational_typed_entries(scalar_row))
                    mapped_indexes = {index for index, _key, _value in relational}
                    yield from (
                        item for index, item in enumerate(scalar_row) if index not in mapped_indexes
                    )
                    yield from ((key, value) for _index, key, value in relational)
                    pending.extend(reversed(children))
                elif isinstance(value, list):
                    for child in reversed(value):
                        if isinstance(child, (dict, list)):
                            pending.append((child, inherited_key))
                        elif isinstance(child, (str, int, float)) and not isinstance(child, bool):
                            yield inherited_key, str(child)
                elif isinstance(value, (str, int, float)) and not isinstance(value, bool):
                    yield inherited_key, str(value)

        if valid_json:
            parsed_structured = True
            for document in documents:
                yield from walk(document)

    if suffix in {".csv", ".tsv"}:
        delimiter = "\t" if suffix == ".tsv" else ","
        records, valid_csv = csv_records_with_spans(contents, delimiter)
        valid_csv = valid_csv and delimited_records_valid(records, delimiter)
        if valid_csv and records:
            for value, _start, _end in records[0]:
                yield STRUCTURED_NAME_KEY, value
            header = [normalize_structured_key(value) for value, _start, _end in records[0]]
            for raw_row in records[1:] if valid_csv else []:
                if len(raw_row) != len(header):
                    valid_csv = False
                    break
                scalar_row: list[tuple[str, str]] = []
                for key, (value, _start, _end) in zip(header, raw_row):
                    if key and value:
                        scalar_row.append((key, value.strip()))
                relational = list(relational_typed_entries(scalar_row))
                mapped_indexes = {index for index, _key, _value in relational}
                yield from (item for index, item in enumerate(scalar_row) if index not in mapped_indexes)
                yield from ((key, value) for _index, key, value in relational)
            parsed_structured = valid_csv

    if suffix == ".xml":
        xml_values, xml_failures, _xml_version_spans = (
            xml_analysis if xml_analysis is not None else xml_structured_values(contents)
        )
        if not xml_failures:
            parsed_structured = True
            yield from xml_values

    if suffix == ".sql":
        sql_values, sql_failures = sql_analysis if sql_analysis is not None else analyze_sql(contents)
        for key, value, _start, _end in sql_values:
            yield key, value
        if not sql_failures:
            yield from sql_contextual_values(contents)

    # Covers JSON-lines, key=value, and lightweight text fixtures without
    # depending on a successful structured parse. SQL assignments are not
    # records: treating `display_name = CASE` as host data creates false hits.
    if (
        suffix not in {".sql", ".json"}
        and suffix in (INSPECT_SUFFIXES | OPERATIONAL_SUFFIXES)
        and not parsed_structured
    ):
        yield from generic_structured_values(path, contents)


def inspect_data(path: str, contents: str) -> list[str]:
    failures: list[str] = []
    suffix = PurePosixPath(path).suffix.lower()

    size_limit = {
        ".json": MAX_JSON_BYTES,
        ".csv": MAX_DELIMITED_BYTES,
        ".tsv": MAX_DELIMITED_BYTES,
        ".xml": MAX_XML_BYTES,
        ".sql": MAX_SQL_BYTES,
    }.get(suffix)
    if size_limit is not None and len(contents.encode("utf-8")) > size_limit:
        return [f"{display_path(path)}: structured data exceeds its safe parser limit"]

    if path == OUI_TABLE_PATH:
        # Public IEEE reference data: validate its structural shape instead of running the
        # identity scans, which false-positive on real vendor names. See OUI_TABLE_PATH.
        return oui_table_failures(path, contents)

    sql_analysis: tuple[list[tuple[str, str, int, int]], list[tuple[int, str]]] | None = None
    xml_analysis: tuple[
        list[tuple[str, str]], list[str], list[tuple[int, int]]
    ] | None = None
    failures.extend(generic_format_failures(path, contents))
    if failures:
        return failures
    if suffix == ".sql":
        sql_analysis = analyze_sql(contents, path)
        for offset, reason in sql_analysis[1]:
            failures.append(f"{display_path(path)}:{contents.count(chr(10), 0, offset) + 1}: {reason}")
        if failures:
            return list(dict.fromkeys(failures))
    if suffix == ".json":
        _documents, valid_json = json_documents(path, contents)
        if not valid_json:
            return [f"{display_path(path)}: JSON could not be decoded safely"]
    if suffix in {".csv", ".tsv"}:
        delimiter = "\t" if suffix == ".tsv" else ","
        records, valid_csv = csv_records_with_spans(contents, delimiter)
        valid_csv = valid_csv and delimited_records_valid(records, delimiter)
        if not valid_csv:
            return [f"{display_path(path)}: delimited data could not be decoded safely"]
    if suffix == ".xml":
        xml_analysis = xml_structured_values(contents)
        for reason in xml_analysis[1]:
            failures.append(f"{display_path(path)}: {reason}")
        if failures:
            return list(dict.fromkeys(failures))

    failures.extend(inventory_format_failures(path, contents))
    failures.extend(public_domain_list_failures(path, contents))
    failures.extend(unifi_log_failures(path, contents))
    if failures:
        return list(dict.fromkeys(failures))

    # Parse only after strict format validation. In particular, malformed XML
    # must not reach the legacy span regexes, whose backtracking assumptions
    # apply only to valid, size-bounded documents.
    values = list(structured_values(path, contents, sql_analysis, xml_analysis))
    version_spans = version_value_spans(path, contents, sql_analysis, xml_analysis)
    version_span_starts = [start for start, _end in version_spans]

    for occurrence in IPV4_RE.finditer(contents):
        raw_value = occurrence.group(1)
        if span_contains(
            version_spans,
            version_span_starts,
            occurrence.start(1),
            occurrence.end(1),
        ):
            continue
        try:
            value = ipaddress.IPv4Address(raw_value)
        except ipaddress.AddressValueError:
            # Keep rejecting private-looking invalid values. Prefix-preserving
            # redaction can still disclose topology and is a common evasion.
            failures.append(
                diagnostic(path, contents.count("\n", 0, occurrence.start()) + 1, "invalid IPv4-like data value")
            )
            return failures
        if not allowed_v4_in_path(path, value):
            failures.append(
                diagnostic(path, contents.count("\n", 0, occurrence.start(1)) + 1, "non-documentation IPv4 data value")
            )
            return failures

    # Structured parsers expose values hidden by JSON Unicode escapes or XML
    # numeric entities. Re-run address checks on every decoded scalar, while
    # retaining the narrow typed-version exception only when the parser emitted
    # that effective key for this value.
    for key, decoded in values:
        if key in VERSION_KEYS and safe_version_value(decoded):
            continue
        for occurrence in IPV4_RE.finditer(decoded):
            try:
                decoded_v4 = ipaddress.IPv4Address(occurrence.group(1))
            except ipaddress.AddressValueError:
                failures.append(diagnostic(path, line_number(contents, decoded), "invalid IPv4-like data value"))
                return failures
            if not allowed_v4_in_path(path, decoded_v4):
                failures.append(
                    diagnostic(path, line_number(contents, decoded), "non-documentation IPv4 data value")
                )
                return failures

    for token in sorted(set(IPV6_TOKEN_RE.findall(contents))):
        if token.count(":") < 2:
            continue
        try:
            value6 = ipaddress.IPv6Address(token.split("%", 1)[0])
        except ipaddress.AddressValueError:
            continue
        if not allowed_v6(value6):
            failures.append(diagnostic(path, line_number(contents, token), "non-documentation IPv6 data value"))
            return failures

    for key, decoded in values:
        if key in VERSION_KEYS and safe_version_value(decoded):
            continue
        for token in set(IPV6_TOKEN_RE.findall(decoded)):
            if token.count(":") < 2:
                continue
            try:
                decoded_v6 = ipaddress.IPv6Address(token.split("%", 1)[0])
            except ipaddress.AddressValueError:
                continue
            if not allowed_v6(decoded_v6):
                failures.append(diagnostic(path, line_number(contents, decoded), "non-documentation IPv6 data value"))
                return failures

    uuid_masked_contents = UUID_RE.sub(" ", contents)
    mac_values = (
        set(MAC_DELIMITED_RE.findall(contents))
        | set(MAC_CISCO_RE.findall(contents))
        | set(MAC_COMPACT_RE.findall(uuid_masked_contents))
        | set(MAC_CONTEXTUAL_COMPACT_RE.findall(uuid_masked_contents))
        | set(MAC_CONTEXTUAL_TIGHT_RE.findall(uuid_masked_contents))
        | set(MAC_HEX_COMPACT_RE.findall(uuid_masked_contents))
    )
    for key, value in values:
        mac_values.update(MAC_DELIMITED_RE.findall(value))
        mac_values.update(MAC_CISCO_RE.findall(value))
        uuid_masked_value = UUID_RE.sub(" ", value)
        if key == STRUCTURED_NAME_KEY:
            if not re.fullmatch(r"(?i)[0-9a-f]{64}", uuid_masked_value):
                mac_values.update(MAC_COMPACT_EMBEDDED_RE.findall(uuid_masked_value))
        else:
            mac_values.update(MAC_COMPACT_RE.findall(uuid_masked_value))
            mac_values.update(MAC_CONTEXTUAL_COMPACT_RE.findall(uuid_masked_value))
            mac_values.update(MAC_CONTEXTUAL_TIGHT_RE.findall(uuid_masked_value))
            mac_values.update(MAC_HEX_COMPACT_RE.findall(uuid_masked_value))
    for match in sorted(mac_values):
        if not allowed_mac(match):
            failures.append(diagnostic(path, line_number(contents, match), "non-documentation MAC data value"))
            return failures

    local_names = set(local_name_candidates(contents))
    for _key, decoded in values:
        local_names.update(local_name_candidates(decoded))
    for match in sorted(local_names):
        if PURE_MDNS_SERVICE_RE.fullmatch(match) or PLACEHOLDER_LOCAL_RE.fullmatch(match):
            continue
        failures.append(diagnostic(path, line_number(contents, match), "local/environment hostname data value"))
        return failures

    inventory_document = is_inventory_path(path)
    contextual_host_keys = HOST_KEYS | ({"name"} if inventory_document else set())
    seen_typed: set[tuple[str, str]] = set()
    for key, value in values:
        effective_key = canonical_sql_typed_key(key)
        marker = (effective_key, value)
        if not effective_key or marker in seen_typed:
            continue
        seen_typed.add(marker)
        if effective_key in IP_KEYS:
            failures.extend(validate_typed_ip(path, contents, value))
        elif effective_key in MAC_KEYS:
            failures.extend(validate_typed_mac(path, contents, value))
        if failures:
            return list(dict.fromkeys(failures))

    seen_hosts: set[str] = set()
    for key, value in values:
        effective_key = canonical_sql_typed_key(key)
        if (
            effective_key in HOST_KEYS
            or key in contextual_host_keys
            or key.endswith(("_host", "_hostname"))
        ) and value not in seen_hosts:
            seen_hosts.add(value)
            failures.extend(
                validate_host(
                    path,
                    contents,
                    value,
                    allow_public=effective_key in PUBLIC_DOMAIN_KEYS,
                    allow_pattern=path in SQL_STATIC_FIXTURE_FILES,
                )
            )
            if failures:
                return list(dict.fromkeys(failures))

    if inventory_document:
        seen_note_hosts: set[str] = set()
        for key, value in values:
            if normalize_structured_key(key) not in {"note", "notes", "comment", "comments"}:
                continue
            for candidate in inventory_note_host_candidates(value):
                if candidate in seen_note_hosts:
                    continue
                seen_note_hosts.add(candidate)
                failures.extend(validate_host(path, contents, candidate))
                if failures:
                    return list(dict.fromkeys(failures))

    return list(dict.fromkeys(failures))


def inspect_entry(root: Path, entry: GitEntry) -> tuple[list[str], bool]:
    failures: list[str] = []
    path = entry.path
    safe_path = display_path(path)
    pure = PurePosixPath(path)
    lowered = path.lower()
    path_parts = tuple(part.lower() for part in pure.parts)
    basename = pure.name.lower()

    if entry.mode == "160000":
        return [f"{safe_path}: tracked gitlinks/submodules cannot be sanitized"], False
    for category in sorted(path_identifier_categories(path)):
        failures.append(f"{safe_path}: tracked path contains {category} (value redacted)")
    if entry.mode == "120000":
        failures.append(f"{safe_path}: tracked symbolic links cannot be sanitized safely")
        return failures, True
    if is_unconditional_local_path(path):
        failures.append(f"{safe_path}: files from security-sensitive local-only directories must not be tracked")
    telemetry_source = is_telemetry_export_source(path) and entry.mode in {"100644", "100755"}
    if any(is_forbidden_component(part) for part in path_parts[:-1]) and not telemetry_source:
        failures.append(f"{safe_path}: files from local lab/capture/export directories must not be tracked")
    if pure.name != ".env.example" and is_environment_name(basename):
        failures.append(f"{safe_path}: environment files must not be tracked")
    if any(is_environment_name(part) for part in path_parts[:-1]):
        failures.append(f"{safe_path}: files nested under environment-shaped paths must not be tracked")
    if is_forbidden_artifact(basename):
        failures.append(f"{safe_path}: generated database/capture/export/archive artifact must not be tracked")
    if any(is_forbidden_artifact(part.lower()) for part in pure.parts[:-1]):
        failures.append(f"{safe_path}: files nested under artifact/archive-shaped paths must not be tracked")
    if basename.endswith("~"):
        failures.append(f"{safe_path}: editor backup files must not be tracked")
    if has_extension_segment(basename, ".log") and not path.startswith(ALLOWED_LOG_PREFIXES):
        failures.append(f"{safe_path}: raw logs are allowed only in the reviewed synthetic UniFi corpus")
    if lowered.endswith(".sql") and path not in ALLOWED_SQL_FILES and not path.startswith(ALLOWED_SQL_PREFIXES):
        failures.append(f"{safe_path}: SQL is allowed only in reviewed migration/maintenance paths")
    if (
        RISK_DATA_NAME_RE.search(basename)
        and pure.suffix.lower() not in RISK_SOURCE_SUFFIXES
        and pure.suffix.lower() != ".sql"
        and not is_reviewed_data_path(path)
    ):
        failures.append(f"{safe_path}: inventory/export/scanner data must live in a reviewed corpus or fixture path")

    reviewable_text = is_data_file(path)
    blob, size_failure = read_blob(root, entry)
    if size_failure:
        failures.append(f"{safe_path}: {size_failure}")
        return failures, True
    assert blob is not None
    if LFS_POINTER_RE.fullmatch(blob):
        failures.append(f"{safe_path}: Git LFS pointers cannot hide repository data from review")
        return failures, True
    if has_binary_media_suffix(path):
        if entry.mode != "100644" or not is_recognized_binary_media(path, blob):
            failures.append(
                f"{safe_path}: opaque media must match an exact reviewed path and SHA-256 digest"
            )
            return failures, True
        return failures, False
    if b"\0" in blob:
        failures.append(f"{safe_path}: reviewable tracked files must not contain NUL bytes")
        return failures, True
    if not reviewable_text:
        return failures, False
    try:
        contents = blob.decode("utf-8")
    except UnicodeDecodeError:
        failures.append(f"{safe_path}: tracked data must be reviewable UTF-8 text")
        return failures, True
    failures.extend(inspect_data(path, contents))
    return failures, True


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("root", nargs="?", help="Git repository root (defaults to the current repository)")
    parser.add_argument(
        "--history-range",
        action="append",
        default=[],
        metavar="REVISION_RANGE",
        help="also inspect every committed tree in this git rev-list range (repeatable)",
    )
    parser.add_argument(
        "--show-paths",
        action="store_true",
        help="show identifier-bearing paths for local remediation (never use in public CI logs)",
    )
    return parser.parse_args()


def main() -> int:
    global SHOW_SENSITIVE_PATHS
    args = parse_args()
    SHOW_SENSITIVE_PATHS = args.show_paths
    if args.root:
        root = Path(args.root).resolve()
    else:
        root = Path(subprocess.check_output(["git", "rev-parse", "--show-toplevel"], text=True).strip())

    failures: list[str] = []
    entries, index_failures = index_entries(root)
    failures.extend(index_failures)
    for revision_range in args.history_range:
        entries.extend(history_entries(root, revision_range))

    inspected_count = 0
    unique_entries: set[GitEntry] = set()
    for entry in entries:
        if entry in unique_entries:
            continue
        unique_entries.add(entry)
        entry_failures, inspected = inspect_entry(root, entry)
        failures.extend(entry_failures)
        inspected_count += int(inspected)

    if failures:
        print("Repository sanitation check FAILED:", file=sys.stderr)
        for failure in sorted(set(failures)):
            print(f"  - {failure}", file=sys.stderr)
        print(
            "Use RFC 5737/RFC 3849 IPs, RFC 7042 MACs, and reserved/placeholder hostnames; "
            "keep real artifacts under ignored .local/ or lab/ paths.",
            file=sys.stderr,
        )
        return 1

    print(
        f"Repository sanitation check passed: {len(unique_entries)} unique tracked entries, "
        f"{inspected_count} data blobs inspected"
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print("Repository sanitation check FAILED:", file=sys.stderr)
        print(f"  - repository data could not be inspected safely ({type(exc).__name__})", file=sys.stderr)
        raise SystemExit(2) from None
