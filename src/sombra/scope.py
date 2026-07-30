"""Target-scope enforcement.

This module replaces the original denylist (``OUT_OF_SCOPE_IPS``) with an
allowlist-first, default-deny model, which is the change the security review
asked for.

Why the change matters
----------------------
The old model was *default-allow*: the agent could touch anything, and a small
hardcoded set of gateway addresses was subtracted out. For a harness that hands
an LLM a raw shell, that is backwards — an address nobody thought to blacklist
(a colleague's laptop on the same /24, an arbitrary public host reached with
``curl``) sailed straight through. Here the default is *deny*: a target is
in-scope only if it is explicitly inside a declared target subnet and is not on
the hard never-touch list.

Two independent layers, checked in this order:

1. ``deny`` — hard never-touch addresses (e.g. the VirtualBox host-only gateways
   that are really ``earthquake`` itself). Refused even if they fall inside a
   target subnet. Defence in depth.
2. ``target_subnets`` — the only networks the agent may scan or attack.

Address extraction from free-form command strings is done with a
digit-boundary-aware regex and then compared using :mod:`ipaddress` objects,
never substring containment. This is what stops the classic false-positive the
original code called out: ``192.168.56.1`` is a textual substring of the real
target ``192.168.56.178``, but they are different addresses and only exact /
network-membership comparison gets that right.
"""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Iterable
from dataclasses import dataclass, field

# Full dotted-quad, not flanked by another digit *or dot* on either side.
# Excluding a flanking dot as well as a flanking digit is what stops a valid
# quad (1.2.3.4) being pulled out of a longer dotted run (1.2.3.4.5, a version
# string) and mistaken for an address. Extracting whole addresses this way —
# rather than substring-scanning for a fixed prefix — is what makes the
# ipaddress comparison below safe.
_IPV4_RE = re.compile(r"(?<![\d.])(\d{1,3}(?:\.\d{1,3}){3})(?![\d.])")


def _parse(ip: str) -> ipaddress.IPv4Address | None:
    try:
        return ipaddress.IPv4Address(ip)
    except ValueError:
        return None


@dataclass(frozen=True)
class Scope:
    """An immutable in-scope target policy.

    Parameters
    ----------
    target_subnets:
        CIDR strings the agent is permitted to scan and attack, e.g.
        ``["192.168.56.0/24"]``.
    deny:
        Individual addresses that are *never* in scope, even inside a target
        subnet (the ``earthquake`` host-only gateways).
    infra_allow:
        Addresses that may legitimately appear in a command without being a
        target — loopback, the attacker's own box, public DNS resolvers used by
        the toolkit installer, ``0.0.0.0``. These are references, not targets:
        they are allowed to appear but are never reported as discoverable hosts.
    """

    target_subnets: tuple[str, ...] = ("192.168.56.0/24",)
    deny: frozenset[str] = frozenset({"192.168.56.1", "192.168.57.1"})
    infra_allow: frozenset[str] = frozenset(
        {"127.0.0.1", "0.0.0.0", "8.8.8.8", "1.1.1.1"}
    )

    _nets: tuple[ipaddress.IPv4Network, ...] = field(
        default=(), init=False, repr=False, compare=False
    )
    _deny: frozenset[ipaddress.IPv4Address] = field(
        default=frozenset(), init=False, repr=False, compare=False
    )
    _infra: frozenset[ipaddress.IPv4Address] = field(
        default=frozenset(), init=False, repr=False, compare=False
    )

    def __post_init__(self) -> None:
        nets = tuple(ipaddress.IPv4Network(s, strict=False) for s in self.target_subnets)
        deny = frozenset(a for a in (_parse(x) for x in self.deny) if a is not None)
        infra = frozenset(a for a in (_parse(x) for x in self.infra_allow) if a is not None)
        # frozen dataclass: bypass the immutability guard to cache parsed forms.
        object.__setattr__(self, "_nets", nets)
        object.__setattr__(self, "_deny", deny)
        object.__setattr__(self, "_infra", infra)

    # -- target classification -------------------------------------------------

    def is_target_allowed(self, ip: str) -> bool:
        """True iff *ip* is a legitimate attack target under this policy.

        In-scope means: a valid address, inside a declared target subnet, and
        not on the hard deny list. Infrastructure references (loopback, DNS, the
        attacker box) are deliberately *not* targets and return False here.
        """
        addr = _parse(ip)
        if addr is None or addr in self._deny:
            return False
        return any(addr in net for net in self._nets)

    def is_referenceable(self, ip: str) -> bool:
        """True iff *ip* may appear in a command at all (target or known infra)."""
        addr = _parse(ip)
        if addr is None or addr in self._deny:
            return False
        if addr in self._infra:
            return True
        return any(addr in net for net in self._nets)

    # -- command gating --------------------------------------------------------

    def check_command(self, command: str) -> tuple[bool, str]:
        """Gate a free-form shell command before it runs.

        Returns ``(ok, reason)``. Every distinct IPv4 literal in the command
        must be referenceable; the first one that is not causes a refusal. An
        unrecognised public address is refused here — under the old denylist it
        would have been allowed, which was the whole problem.
        """
        for raw in dict.fromkeys(_IPV4_RE.findall(command)):  # de-dup, keep order
            addr = _parse(raw)
            if addr is None:
                continue  # not a real IPv4 (e.g. a version string) — ignore
            if addr in self._deny:
                return False, f"Refusing: {raw} is on the hard out-of-scope list."
            if not self.is_referenceable(raw):
                return (
                    False,
                    f"Refusing: {raw} is not within any in-scope target subnet "
                    f"({', '.join(self.target_subnets)}).",
                )
        return True, ""

    # -- helpers ---------------------------------------------------------------

    def nmap_exclude_arg(self) -> str:
        """Comma-joined deny list for ``nmap --exclude``."""
        return ",".join(sorted(str(a) for a in self._deny))

    def filter_discovered(self, ips: Iterable[str]) -> list[str]:
        """Keep only genuinely in-scope targets from a set of scanned IPs."""
        return [ip for ip in ips if self.is_target_allowed(ip)]
