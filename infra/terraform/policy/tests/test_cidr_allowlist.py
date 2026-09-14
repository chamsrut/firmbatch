"""The independent reviewer allow-list check refuses every case the Terraform validation
refuses (infra/terraform/environments/staging/tests/reviewer_allowlist.tftest.hcl), and the
two implementations' non-routable range lists stay textually identical.

All ranges are synthetic test values; none is a reviewer's network.
"""

import json
import pathlib
import re
import subprocess
import sys
import tempfile
import unittest

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parents[1]))

from policy import cidr_allowlist  # noqa: E402

EDGE_VARIABLES = HERE.parents[1] / "modules" / "edge" / "variables.tf"
ACCEPTED = ["11.22.33.0/24", "11.22.34.128/25", "2a0f:ffff:1::/64"]


def refused(entries, ipv4=512, ipv6=1):
    return cidr_allowlist.validate(entries, ipv4, ipv6)


class AcceptedList(unittest.TestCase):
    def test_a_reviewed_list_within_every_bound_is_accepted(self):
        self.assertEqual(refused(ACCEPTED), [])

    def test_single_hosts_are_accepted(self):
        self.assertEqual(refused(["11.22.33.10/32", "2a0f:ffff:1::10/128"], 2, 1), [])


class Refusals(unittest.TestCase):
    cases = {
        "empty": [],
        "not a CIDR": ["11.22.33.0"],
        "host bits set": ["11.22.33.7/24"],
        "upper-case IPv6": ["2A0F:FFFF:1::/64"],
        "expanded IPv6": ["2a0f:ffff:0001:0000::/64"],
        "leading zeros": ["011.22.33.0/24"],
        "IPv4-mapped IPv6": ["::ffff:11.22.33.0/120"],
        "IPv4 broader than /24": ["11.22.32.0/23"],
        "IPv6 broader than /64": ["2a0f:ffff::/63"],
        "the whole IPv4 internet": ["0.0.0.0/0"],
        "the whole IPv6 internet": ["::/0"],
        "private": ["10.1.2.0/24"],
        "shared address space": ["100.64.1.0/24"],
        "loopback": ["127.0.0.0/24"],
        "link-local": ["169.254.10.0/24"],
        "multicast": ["224.0.1.0/24"],
        "reserved": ["240.0.1.0/24"],
        "documentation": ["203.0.113.0/24"],
        "benchmarking": ["198.18.1.0/24"],
        "unspecified": ["0.0.0.0/32"],
        "IPv6 unique-local": ["fd00:1::/64"],
        "IPv6 link-local": ["fe80::/64"],
        "IPv6 documentation": ["2001:db8:1::/64"],
        "IPv6 unspecified": ["::/128"],
        "IPv6 loopback": ["::1/128"],
        "IPv6 multicast": ["ff02::/64"],
        "duplicate": ["11.22.33.0/24", "11.22.33.0/24"],
        "overlap": ["11.22.33.0/24", "11.22.33.128/25"],
        "IPv6 overlap": ["2a0f:ffff:1::/64", "2a0f:ffff:1::/80"],
        "seventeen entries": [f"11.22.33.{n}/32" for n in range(1, 18)],
        "not a string": [42],
    }

    def test_each_rule_refuses(self):
        for name, entries in self.cases.items():
            with self.subTest(case=name):
                self.assertNotEqual(refused(entries), [], f"{name} was accepted")

    def test_a_list_over_the_address_space_allowance_is_refused(self):
        self.assertNotEqual(refused(["11.22.33.0/24", "11.22.35.0/24"], ipv4=256, ipv6=0), [])

    def test_ipv6_over_its_allowance_is_refused(self):
        self.assertNotEqual(refused(["2a0f:ffff:1::/64", "2a0f:ffff:2::/64"], ipv4=1, ipv6=1), [])

    def test_an_allowance_over_the_hard_ceiling_is_refused(self):
        self.assertNotEqual(refused(ACCEPTED, ipv4=8192, ipv6=1), [])
        self.assertNotEqual(refused(ACCEPTED, ipv4=512, ipv6=17), [])

    def test_findings_never_echo_an_entry(self):
        for finding in refused(["11.22.33.7/24", "10.1.2.0/24"]):
            self.assertNotIn("11.22.33", finding)
            self.assertNotIn("10.1.2", finding)


class AgreesWithTerraform(unittest.TestCase):
    def test_the_non_routable_lists_are_identical_to_the_edge_module(self):
        text = EDGE_VARIABLES.read_text()
        ipv4_block = re.search(r'for special in \[\s*("0\.0\.0\.0/8".*?)\]', text, re.S).group(1)
        ipv6_block = re.search(r'for special in \[("2001::/23".*?)\]', text, re.S).group(1)
        self.assertEqual(tuple(re.findall(r'"([^"]+)"', ipv4_block)), cidr_allowlist.IPV4_NON_ROUTABLE)
        self.assertEqual(tuple(re.findall(r'"([^"]+)"', ipv6_block)), cidr_allowlist.IPV6_NON_ROUTABLE)
        self.assertIn(f'"{cidr_allowlist.IPV6_GLOBAL_UNICAST}"', text)
        self.assertIn(f"<= {cidr_allowlist.MAX_ENTRIES}", text)
        self.assertIn(f"<= {cidr_allowlist.IPV4_ADDRESS_CEILING}", text)
        self.assertIn(f"<= {cidr_allowlist.IPV6_SLASH64_CEILING}", text)

    def test_every_terraform_refusal_case_is_refused_here(self):
        tftest = (HERE.parents[1] / "environments" / "staging" / "tests" / "reviewer_allowlist.tftest.hcl").read_text()
        cases = re.findall(r'reviewer_cidrs = (\[[^\]]*\])\s*\n\s*(?:reviewer_address_space_limit|\})', tftest)
        self.assertGreaterEqual(len(cases), 20)
        for literal in cases:
            entries = json.loads(re.sub(r",\s*\]", "]", literal))
            if entries == ["11.22.33.0/24", "11.22.35.0/24"]:
                continue  # the allowance case, covered above with its own limit
            with self.subTest(entries=entries):
                self.assertNotEqual(refused(entries), [])


class CommandLine(unittest.TestCase):
    def run_cli(self, document):
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as handle:
            json.dump(document, handle)
        try:
            return subprocess.run(
                [sys.executable, str(HERE.parents[0] / "cidr_allowlist.py"), "--tfvars-json", handle.name],
                capture_output=True, text=True, check=False,
            )
        finally:
            pathlib.Path(handle.name).unlink()

    def test_the_cli_accepts_and_refuses_without_echoing(self):
        limit = {"ipv4_addresses": 512, "ipv6_slash64_networks": 1}
        accepted = self.run_cli({"reviewer_cidrs": ACCEPTED, "reviewer_address_space_limit": limit})
        self.assertEqual(accepted.returncode, 0, accepted.stderr)
        refused_run = self.run_cli({"reviewer_cidrs": ["0.0.0.0/0"], "reviewer_address_space_limit": limit})
        self.assertEqual(refused_run.returncode, 1)
        self.assertNotIn("0.0.0.0", refused_run.stderr + refused_run.stdout)


if __name__ == "__main__":
    unittest.main()
