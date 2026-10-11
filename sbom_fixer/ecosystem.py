"""Which language ecosystem an SBOM describes (dotnet, java, node, ...), and the generator tool name for it.

Used by the canonical form (CXN-011) when the profile sets `tool_per_ecosystem`: a .NET SBOM is labelled
cyclonedx-dotnet, a Java one cyclonedx-java, and so on.

Evidence, strongest first:
1. the purl types of the components (majority wins; OS packages, generic, docker, github, ... do not count);
2. the purl type of the root component (metadata.component), which also breaks a tie;
3. the generator named in metadata.tools / SPDX creators (cyclonedx-gradle-plugin -> java, ...).
Without evidence there is no ecosystem and the caller keeps its default tool.
"""

from __future__ import annotations

import re
from collections import Counter
from dataclasses import dataclass, field
from typing import Any

from .purlmap import try_purl

# purl type (lower case) -> ecosystem
PURL_TYPE_ECOSYSTEM: dict[str, str] = {
    "nuget": "dotnet",
    "maven": "java", "gradle": "java", "sbt": "java", "ivy": "java",
    "npm": "node", "yarn": "node", "bower": "node", "pnpm": "node",
    "pypi": "python", "pip": "python", "python": "python", "poetry": "python",
    "golang": "go", "go": "go", "gomodules": "go",
    "gem": "ruby", "ruby": "ruby", "rubygems": "ruby",
    "composer": "php", "php": "php",
    "cargo": "rust",
    "hex": "erlang",
    "pub": "dart", "dart": "dart",
    "swift": "swift", "swiftpm": "swift", "cocoapods": "swift", "carthage": "swift", "ios": "swift",
    "conan": "cpp", "cpp": "cpp",
    "cpan": "perl", "perl": "perl",
}

# ecosystem -> tool name written to metadata.tools
DEFAULT_ECOSYSTEM_TOOLS: dict[str, str] = {
    "dotnet": "cyclonedx-dotnet",
    "java": "cyclonedx-java",
    "node": "cyclonedx-node",
    "python": "cyclonedx-python",
    "go": "cyclonedx-go",
    "ruby": "cyclonedx-ruby",
    "php": "cyclonedx-php",
    "rust": "cyclonedx-rust",
    "erlang": "cyclonedx-erlang",
    "dart": "cyclonedx-dart",
    "swift": "cyclonedx-swift",
    "cpp": "cyclonedx-cpp",
    "perl": "cyclonedx-perl",
}

# words in a generator name -> ecosystem (matched as whole words: "go" must not match "google" or "cargo")
_GENERATOR_WORDS: dict[str, str] = {
    "dotnet": "dotnet", "nuget": "dotnet", "net": "dotnet", "csharp": "dotnet",
    "maven": "java", "gradle": "java", "java": "java", "sbt": "java", "jar": "java",
    "npm": "node", "node": "node", "yarn": "node", "pnpm": "node", "js": "node", "javascript": "node",
    "python": "python", "pip": "python", "poetry": "python", "pipenv": "python", "py": "python",
    "gomod": "go", "go": "go", "golang": "go",
    "ruby": "ruby", "bundler": "ruby", "gem": "ruby", "gems": "ruby",
    "composer": "php", "php": "php",
    "cargo": "rust", "rust": "rust",
    "mix": "erlang", "hex": "erlang", "erlang": "erlang", "elixir": "erlang", "rebar": "erlang", "rebar3": "erlang",
    "dart": "dart", "flutter": "dart", "pub": "dart",
    "swift": "swift", "cocoapods": "swift", "carthage": "swift",
    "conan": "cpp", "cpp": "cpp",
    "perl": "perl", "cpan": "perl",
}

ECOSYSTEMS = tuple(DEFAULT_ECOSYSTEM_TOOLS)


@dataclass
class EcosystemResult:
    ecosystem: str | None
    source: str  # forced | components | root-component | generator | none
    counts: dict[str, int] = field(default_factory=dict)  # ecosystem -> components
    total: int = 0  # components looked at

    def describe(self) -> str:
        if self.ecosystem is None:
            return "no ecosystem detected"
        if self.source == "components":
            n = self.counts.get(self.ecosystem, 0)
            others = ", ".join(f"{e} {c}" for e, c in sorted(self.counts.items(), key=lambda x: -x[1]) if e != self.ecosystem)
            text = f"ecosystem {self.ecosystem}: {n} of {self.total} components"
            return f"{text} (also {others})" if others else text
        return f"ecosystem {self.ecosystem} (from the {self.source.replace('-', ' ')})"


def _dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def ecosystem_of_purl(purl: Any) -> str | None:
    p = try_purl(purl) if isinstance(purl, str) else None
    return PURL_TYPE_ECOSYSTEM.get(p.type.lower()) if p is not None else None


def ecosystem_of_generator(names: list[str]) -> str | None:
    votes: Counter[str] = Counter()
    for name in names:
        for word in re.split(r"[^a-z0-9]+", name.lower()):
            eco = _GENERATOR_WORDS.get(word)
            if eco:
                votes[eco] += 1
    return votes.most_common(1)[0][0] if votes else None


def generator_names(doc: dict[str, Any]) -> list[str]:
    """Tool names of a CycloneDX (metadata.tools, both forms) or SPDX (creators 'Tool:') document."""
    names: list[str] = []
    tools: Any = (doc.get("metadata") or {}).get("tools") if isinstance(doc.get("metadata"), dict) else None
    if isinstance(tools, dict):
        tools = list(tools.get("components") or []) + list(tools.get("services") or [])
    for t in tools or []:
        if isinstance(t, dict):
            names.append(" ".join(str(t.get(k, "")) for k in ("vendor", "group", "name") if t.get(k)))
    creators = (doc.get("creationInfo") or {}).get("creators") if isinstance(doc.get("creationInfo"), dict) else None
    for c in creators or []:
        if isinstance(c, str) and c.startswith("Tool:"):
            names.append(c.removeprefix("Tool:").strip())
    return [n for n in names if n]


def detect_ecosystem(doc: dict[str, Any], generators: list[str] | None = None, force: str | None = None) -> EcosystemResult:
    """Ecosystem of a CycloneDX document; `generators` overrides the tool names read from the document."""
    if force:
        return EcosystemResult(force, "forced")
    counts: Counter[str] = Counter()
    total = 0
    for c in doc.get("components") or []:
        if not isinstance(c, dict):
            continue
        total += 1
        eco = ecosystem_of_purl(c.get("purl"))
        if eco is None and isinstance(c.get("bom-ref"), str):
            eco = ecosystem_of_purl(c["bom-ref"])
        if eco:
            counts[eco] += 1
    meta: dict[str, Any] = _dict(doc.get("metadata"))
    root: dict[str, Any] = _dict(meta.get("component"))
    root_eco = ecosystem_of_purl(root.get("purl")) or ecosystem_of_purl(root.get("bom-ref"))
    gen_eco = ecosystem_of_generator(generators if generators is not None else generator_names(doc))
    if counts:
        top = max(counts.values())
        leaders = sorted(e for e, n in counts.items() if n == top)
        if len(leaders) > 1:  # tie: the root component, then the generator, then a fixed order
            pick = next((e for e in (root_eco, gen_eco) if e in leaders), leaders[0])
        else:
            pick = leaders[0]
        return EcosystemResult(pick, "components", dict(counts), total)
    if root_eco:
        return EcosystemResult(root_eco, "root-component", {}, total)
    if gen_eco:
        return EcosystemResult(gen_eco, "generator", {}, total)
    return EcosystemResult(None, "none", {}, total)
