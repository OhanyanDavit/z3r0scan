"""Scanner module registry.

Modules register here by their ``name``; the orchestrator instantiates them in
the order requested by the config.
"""

from __future__ import annotations

from .base import ScanModule
from .host_scan import HostScanModule
from .shodan_enrich import ShodanModule
from .subdomains import SubdomainModule
from .vuln_scan import VulnScanModule
from .web_probe import WebProbeModule

REGISTRY: dict[str, type[ScanModule]] = {
    HostScanModule.name: HostScanModule,
    SubdomainModule.name: SubdomainModule,
    WebProbeModule.name: WebProbeModule,
    VulnScanModule.name: VulnScanModule,
    ShodanModule.name: ShodanModule,
}

__all__ = ["REGISTRY", "ScanModule"]
