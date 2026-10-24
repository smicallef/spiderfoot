# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         routing
# Purpose:      Pick the modules that are relevant to a detected target type.
# -------------------------------------------------------------------------------
"""Module routing for the single search box.

Given the engine type of a detected target (for example ``EMAILADDR``) this
walks the publisher/subscriber graph of the loaded modules: modules that
consume the target type run first, the event types they produce pull in the
modules that consume *those*, and so on until nothing new is added.
"""

from __future__ import annotations

import typing

# Labels that make a module heavier or noisier than a quick lookup.
HEAVY_LABELS = {"slow", "invasive", "tool"}

# Storage modules are always added by the caller, never routed.
_SKIP = {"sfp__stor_db", "sfp__stor_stdout"}

# Extra event types a target implicitly provides to the scan engine.
_TARGET_SEEDS: typing.Dict[str, typing.List[str]] = {
    "INTERNET_NAME": ["INTERNET_NAME", "DOMAIN_NAME"],
    "IP_ADDRESS": ["IP_ADDRESS"],
    "IPV6_ADDRESS": ["IPV6_ADDRESS"],
    "NETBLOCK_OWNER": ["NETBLOCK_OWNER"],
    "NETBLOCKV6_OWNER": ["NETBLOCKV6_OWNER"],
    "BGP_AS_OWNER": ["BGP_AS_OWNER"],
    "EMAILADDR": ["EMAILADDR", "INTERNET_NAME", "DOMAIN_NAME"],
    "PHONE_NUMBER": ["PHONE_NUMBER"],
    "HUMAN_NAME": ["HUMAN_NAME"],
    "USERNAME": ["USERNAME"],
    "BITCOIN_ADDRESS": ["BITCOIN_ADDRESS"],
}


def _needs_missing_key(mod: typing.Dict[str, typing.Any]) -> bool:
    """True if the module needs an API key and none is configured."""
    if "apikey" not in (mod.get("labels") or []):
        return False
    keyopts = [k for k in (mod.get("opts") or {}) if "api_key" in k]
    if not keyopts:
        return False
    return not any(str(mod["opts"][k]).strip() for k in keyopts)


def modules_for_target(modules: typing.Dict[str, typing.Dict[str, typing.Any]], target_type: str,
                       deep: bool = False, allow_unkeyed: bool = False,
                       max_hops: typing.Optional[int] = None) -> typing.List[str]:
    """Return the modules relevant to a target type.

    Args:
        modules: loaded module metadata (``config['__modules__']``)
        target_type: engine target type, e.g. ``IP_ADDRESS``
        deep: include slow, invasive and external tool modules
        allow_unkeyed: include modules that need an API key which has not been set
        max_hops: how many pivots to follow from the target. 1 means only modules that consume the
            target itself; 2 adds modules that consume what those produce, and so on. None follows
            the whole chain, which in practice reaches almost every module.

    Returns:
        sorted list of module names
    """
    seeds = set(_TARGET_SEEDS.get(target_type, [target_type]))
    selected: typing.Set[str] = set()
    seen_events: typing.Set[str] = set()
    frontier = set(seeds)
    hops = 0

    while frontier and (max_hops is None or hops < max_hops):
        hops += 1
        seen_events |= frontier
        produced: typing.Set[str] = set()
        for name, mod in modules.items():
            if name in selected or name in _SKIP:
                continue
            consumes = set(mod.get("consumes") or [])
            if not (consumes & frontier or "*" in consumes and selected):
                continue
            labels = set(mod.get("labels") or [])
            if not deep and labels & HEAVY_LABELS:
                continue
            if not allow_unkeyed and _needs_missing_key(mod):
                continue
            selected.add(name)
            produced |= set(mod.get("provides") or [])
        frontier = produced - seen_events

    return sorted(selected)
