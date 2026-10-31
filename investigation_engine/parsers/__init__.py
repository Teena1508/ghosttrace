"""
GhostTrace Parsers Subpackage.
Provides multi-format log parsers for Windows Event Logs (XML & JSON), Linux Syslog/Auth,
and arbitrary JSON/JSONL security telemetry.
"""

from investigation_engine.parsers.base import BaseLogParser, ParserResult
from investigation_engine.parsers.windows_xml import WindowsXmlParser
from investigation_engine.parsers.windows_json import WindowsJsonParser
from investigation_engine.parsers.linux_auth import LinuxAuthParser
from investigation_engine.parsers.json_importer import JsonLogParser
from investigation_engine.parsers.dispatcher import (
    detect_parser,
    get_available_parsers,
    parse_and_normalize_logs,
)

__all__ = [
    "BaseLogParser",
    "ParserResult",
    "WindowsXmlParser",
    "WindowsJsonParser",
    "LinuxAuthParser",
    "JsonLogParser",
    "detect_parser",
    "get_available_parsers",
    "parse_and_normalize_logs",
]
