"""Locate and load the data files under ``rules/``.

Rules are data, not code: brands, keywords, and scoring weights all live in
plain files that an analyst can edit without touching Python.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path

# Second-level public suffixes where the organisational domain is three labels.
# This is a deliberately small hand-rolled list; see DECISIONS.md.
_SECOND_LEVEL_SUFFIXES = frozenset(
    {
        "co.uk",
        "org.uk",
        "ac.uk",
        "gov.uk",
        "co.jp",
        "ne.jp",
        "or.jp",
        "com.au",
        "net.au",
        "org.au",
        "co.nz",
        "com.br",
        "com.mx",
        "co.za",
        "com.sg",
        "com.hk",
        "co.in",
        "co.kr",
        "com.tr",
        "com.ar",
        "com.cn",
    }
)


def rules_dir() -> Path:
    """Directory holding ``scoring.yaml``, ``brands.txt``, ``keywords.txt``.

    Resolution order: ``PHISHTRIAGE_RULES_DIR`` env var, the repo's ``rules/``
    next to ``src/``, then ``./rules`` in the current working directory.
    """
    override = os.environ.get("PHISHTRIAGE_RULES_DIR")
    if override:
        return Path(override)
    repo_rules = Path(__file__).resolve().parents[2] / "rules"
    if repo_rules.is_dir():
        return repo_rules
    return Path.cwd() / "rules"


def organizational_domain(domain: str) -> str:
    """Collapse ``mail.eu.example.co.uk`` to ``example.co.uk``.

    Good enough for alignment checks without shipping the public suffix list.
    """
    domain = domain.strip().lower().rstrip(".")
    labels = [label for label in domain.split(".") if label]
    if len(labels) <= 2:
        return ".".join(labels)
    if ".".join(labels[-2:]) in _SECOND_LEVEL_SUFFIXES and len(labels) >= 3:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def same_org(a: str, b: str) -> bool:
    """Relaxed alignment: same organisational domain."""
    if not a or not b:
        return False
    return organizational_domain(a) == organizational_domain(b)


@dataclass(frozen=True)
class Brand:
    name: str
    domains: tuple[str, ...] = field(default_factory=tuple)

    def is_legitimate_domain(self, domain: str) -> bool:
        """True if ``domain`` is one this brand actually sends from."""
        domain = domain.lower()
        if self.domains:
            return any(same_org(domain, legit) for legit in self.domains)
        return self.name.replace(" ", "") in organizational_domain(domain)


def _read_lines(path: Path) -> list[str]:
    if not path.is_file():
        return []
    lines: list[str] = []
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.split("#", 1)[0].strip()
        if line:
            lines.append(line)
    return lines


@lru_cache(maxsize=8)
def load_brands(path: Path | None = None) -> tuple[Brand, ...]:
    """Parse ``rules/brands.txt``; result is cached per path."""
    path = path or rules_dir() / "brands.txt"
    brands: list[Brand] = []
    for line in _read_lines(path):
        if ":" in line:
            name, _, rest = line.partition(":")
            domains = tuple(d.strip().lower() for d in rest.split() if d.strip())
        else:
            name, domains = line, ()
        brands.append(Brand(name=name.strip().lower(), domains=domains))
    return tuple(brands)


@lru_cache(maxsize=8)
def load_keywords(path: Path | None = None) -> dict[str, tuple[str, ...]]:
    """Parse ``rules/keywords.txt`` into ``{category: (phrase, ...)}``.

    Format: ``[category]`` section headers, one phrase per line, ``#`` comments.
    """
    path = path or rules_dir() / "keywords.txt"
    out: dict[str, list[str]] = {}
    category = "general"
    for line in _read_lines(path):
        if line.startswith("[") and line.endswith("]"):
            category = line[1:-1].strip().lower() or "general"
            out.setdefault(category, [])
            continue
        out.setdefault(category, []).append(line.lower())
    return {k: tuple(v) for k, v in out.items()}


def load_list(name: str) -> tuple[str, ...]:
    """Load a simple one-item-per-line list such as ``shorteners.txt``."""
    return tuple(line.lower() for line in _read_lines(rules_dir() / name))
