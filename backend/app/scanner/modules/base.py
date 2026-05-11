from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Literal

from app.scanner.crawler import FormData, ParameterData
from app.utils.http_client import RateLimitedClient


@dataclass
class RawFinding:
    vuln_type: str
    affected_url: str
    affected_parameter: str
    payload_used: str
    evidence_request: str
    evidence_response: str
    confidence: Literal["confirmed", "tentative"]


class BaseModule(ABC):
    """Abstract base for all detection modules.

    Subclasses implement run() and declare which vulnerability types they detect.
    The scan engine calls run() and converts RawFindings into scored Finding records.
    """

    @property
    @abstractmethod
    def name(self) -> str:
        """Human-readable module name, e.g. 'SQL Injection'."""

    @property
    @abstractmethod
    def vuln_types(self) -> list[str]:
        """Vulnerability type keys this module can emit, e.g. ['sqli_error', 'sqli_blind_boolean']."""

    @abstractmethod
    async def run(
        self,
        target_urls: set[str],
        forms: list[FormData],
        parameters: list[ParameterData],
        http_client: RateLimitedClient,
    ) -> list[RawFinding]:
        """Execute detection logic and return raw findings (unscored).

        Args:
            target_urls:  All URLs discovered by the crawler.
            forms:        All forms extracted by the crawler.
            parameters:   All injectable parameters extracted by the crawler.
            http_client:  Shared rate-limited HTTP client for all requests.

        Returns:
            List of RawFinding instances; empty if nothing was detected.
        """
