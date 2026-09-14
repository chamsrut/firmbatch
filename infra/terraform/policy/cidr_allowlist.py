#!/usr/bin/env python3
"""The reviewer CIDR allow-list policy check (ADR 0011 decision 6).

An independent implementation of the rules the edge module's Terraform variable validation
enforces, over Python's ``ipaddress`` rather than Terraform's CIDR functions. The allow-list
is refused when it is:

* empty, or longer than 16 entries;
* holding an invalid or non-canonical CIDR -- host bits set, upper case, leading zeros, an
  IPv4-mapped IPv6 form, or anything ``ipaddress`` would print differently;
* holding an IPv4 range broader than /24 or an IPv6 range broader than /64;
* holding a range that is not globally routable -- unspecified, private, shared, loopback,
  link-local, documentation, benchmarking, multicast, reserved, or outside IPv6 global
  unicast;
* holding duplicate or overlapping entries;
* larger in total than the configured address-space allowance, which itself may not exceed
  4,096 IPv4 addresses or sixteen IPv6 /64 networks.

Findings name an entry by its position and never echo its value, because reviewer CIDRs are
personal network data and the pipeline runs this against the plan-time configuration.

    python3 infra/terraform/policy/cidr_allowlist.py --tfvars-json PATH
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import re
import sys

MAX_ENTRIES = 16
IPV4_BROADEST_PREFIX = 24
IPV6_BROADEST_PREFIX = 64
IPV4_ADDRESS_CEILING = 4096
IPV6_SLASH64_CEILING = 16

# Kept textually identical to the lists in infra/terraform/modules/edge/variables.tf; the
# policy tests assert that the two stay in step.
IPV4_NON_ROUTABLE = (
    "0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16",
    "172.16.0.0/12", "192.0.0.0/24", "192.0.2.0/24", "192.31.196.0/24", "192.52.193.0/24",
    "192.88.99.0/24", "192.168.0.0/16", "192.175.48.0/24", "198.18.0.0/15",
    "198.51.100.0/24", "203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4",
)
IPV6_GLOBAL_UNICAST = "2000::/3"
IPV6_NON_ROUTABLE = ("2001::/23", "2001:db8::/32", "2002::/16", "3fff::/20")

_SHAPE = re.compile(r"[0-9a-f.:]+/[0-9]{1,3}")


def validate(entries, ipv4_address_limit, ipv6_slash64_limit) -> list[str]:
    """Return every rule the allow-list breaks; an empty list means it is acceptable."""
    findings: list[str] = []

    if not isinstance(entries, list):
        return ["reviewer_cidrs must be a list"]
    if not entries:
        findings.append("reviewer_cidrs is empty; an empty allow-list is refused, never read as open")
    if len(entries) > MAX_ENTRIES:
        findings.append(f"reviewer_cidrs has {len(entries)} entries; at most {MAX_ENTRIES} are allowed")

    for name, value, ceiling in (
        ("ipv4_addresses", ipv4_address_limit, IPV4_ADDRESS_CEILING),
        ("ipv6_slash64_networks", ipv6_slash64_limit, IPV6_SLASH64_CEILING),
    ):
        low = 1 if name == "ipv4_addresses" else 0
        if isinstance(value, bool) or not isinstance(value, int) or not low <= value <= ceiling:
            findings.append(f"reviewer_address_space_limit.{name} must be a whole number from {low} to {ceiling}")

    networks: list[tuple[int, ipaddress.IPv4Network | ipaddress.IPv6Network]] = []
    for position, entry in enumerate(entries, start=1):
        label = f"entry {position}"
        if not isinstance(entry, str) or not _SHAPE.fullmatch(entry):
            findings.append(f"{label} is not a CIDR in lowercase address/prefix form")
            continue
        try:
            network = ipaddress.ip_network(entry, strict=True)
        except ValueError:
            findings.append(f"{label} is invalid or has host bits set")
            continue
        if str(network) != entry:
            findings.append(f"{label} is not canonical")
            continue

        if network.version == 4:
            if network.prefixlen < IPV4_BROADEST_PREFIX:
                findings.append(f"{label} is an IPv4 range broader than /{IPV4_BROADEST_PREFIX}")
            if (
                not network.is_global
                or any(network.overlaps(ipaddress.ip_network(s)) for s in IPV4_NON_ROUTABLE)
            ):
                findings.append(f"{label} is not a globally routable IPv4 range")
        else:
            if network.network_address.ipv4_mapped is not None:
                findings.append(f"{label} is an IPv4-mapped IPv6 form")
            if network.prefixlen < IPV6_BROADEST_PREFIX:
                findings.append(f"{label} is an IPv6 range broader than /{IPV6_BROADEST_PREFIX}")
            if (
                not network.subnet_of(ipaddress.ip_network(IPV6_GLOBAL_UNICAST))
                or not network.is_global
                or any(network.overlaps(ipaddress.ip_network(s)) for s in IPV6_NON_ROUTABLE)
            ):
                findings.append(f"{label} is not a globally routable IPv6 range")
        networks.append((position, network))

    for index, (first_position, first) in enumerate(networks):
        for second_position, second in networks[index + 1:]:
            if first.version == second.version and first.overlaps(second):
                kind = "duplicates" if first == second else "overlaps"
                findings.append(f"entry {second_position} {kind} entry {first_position}")

    ipv4_total = sum(n.num_addresses for _, n in networks if n.version == 4)
    ipv6_total = sum(n.num_addresses / 2**64 for _, n in networks if n.version == 6)
    if isinstance(ipv4_address_limit, int) and ipv4_total > ipv4_address_limit:
        findings.append("the IPv4 entries together exceed reviewer_address_space_limit.ipv4_addresses")
    if isinstance(ipv6_slash64_limit, int) and ipv6_total > ipv6_slash64_limit:
        findings.append("the IPv6 entries together exceed reviewer_address_space_limit.ipv6_slash64_networks")

    return findings


def validate_tfvars(document) -> list[str]:
    if not isinstance(document, dict):
        return ["the variables document must be a JSON object"]
    limit = document.get("reviewer_address_space_limit")
    if not isinstance(limit, dict):
        return ["reviewer_address_space_limit must be an object"]
    return validate(
        document.get("reviewer_cidrs"),
        limit.get("ipv4_addresses"),
        limit.get("ipv6_slash64_networks"),
    )


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--tfvars-json", required=True, help="JSON variables file holding reviewer_cidrs")
    args = parser.parse_args(argv)
    try:
        with open(args.tfvars_json, encoding="utf-8") as handle:
            document = json.load(handle)
    except (OSError, ValueError) as exc:
        print(f"cidr allow-list: could not read the variables file ({type(exc).__name__})", file=sys.stderr)
        return 2
    findings = validate_tfvars(document)
    for finding in findings:
        print(f"cidr allow-list: {finding}", file=sys.stderr)
    if findings:
        return 1
    print("cidr allow-list: accepted")
    return 0


if __name__ == "__main__":
    sys.exit(main())
