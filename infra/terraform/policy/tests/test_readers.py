"""The HCL and YAML readers read what the repository writes and refuse what they cannot read."""

import pathlib
import sys
import unittest

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parents[1]))

from policy import hcl, yaml_subset  # noqa: E402
from policy.hcl import Call, Raw, Template  # noqa: E402


class HclReader(unittest.TestCase):
    def test_blocks_attributes_and_literals(self):
        doc = hcl.parse(
            'resource "aws_x" "y" {\n'
            "  enabled = false\n"
            '  names   = ["a", "b"]\n'
            '  policy  = jsonencode({ Sid = "One", Action = ["s3:GetObject"] })\n'
            "  ref     = var.thing\n"
            '  tmpl    = "${var.a}-b"\n'
            "  nested {\n    port = 80\n  }\n"
            "}\n"
        )
        (block,) = doc.children("resource", "aws_x", "y")
        self.assertIs(block.attributes["enabled"], False)
        self.assertEqual(block.attributes["names"], ("a", "b"))
        self.assertIsInstance(block.attributes["policy"], Call)
        self.assertEqual(block.attributes["policy"].args[0]["Action"], ("s3:GetObject",))
        self.assertIsInstance(block.attributes["ref"], Raw)
        self.assertIsInstance(block.attributes["tmpl"], Template)
        self.assertEqual(block.children("nested")[0].attributes["port"], 80)

    def test_comments_heredocs_and_interpolated_braces(self):
        doc = hcl.parse(
            "# comment\n// another\n/* block\ncomment */\n"
            "locals {\n"
            '  a = "x${join(",", ["}", "{"])}y"\n'
            "  b = <<-EOT\n    text with { and }\n  EOT\n"
            "}\n"
        )
        self.assertEqual(set(doc.children("locals")[0].attributes), {"a", "b"})

    def test_unreadable_source_fails_closed(self):
        for source in ('a = "unterminated\n', "resource \"x\" {\n", "a = (1\n", "a = 1 }\n", "@@@\n"):
            with self.subTest(source=source):
                with self.assertRaises(hcl.HclError):
                    hcl.parse(source)

    def test_duplicate_attributes_are_refused(self):
        with self.assertRaises(hcl.HclError):
            hcl.parse("a = 1\na = 2\n")

    def test_every_repository_terraform_file_is_readable(self):
        root = HERE.parents[1]
        paths = [
            p for p in root.rglob("*")
            if p.suffix in (".tf", ".hcl") and ".terraform" not in p.parts and not p.name.endswith(".lock.hcl")
        ]
        self.assertGreater(len(paths), 20)
        for path in paths:
            with self.subTest(path=path.name):
                hcl.parse_file(path)


class YamlReader(unittest.TestCase):
    def test_the_workflow_subset(self):
        doc = yaml_subset.parse(
            "name: x\n"
            "on:\n  workflow_dispatch:\n    inputs:\n      a:\n        required: true\n"
            "permissions: {}\n"
            "jobs:\n  one:\n    needs: [two]\n    steps:\n"
            "      - uses: actions/checkout@abc  # pinned\n        with:\n          persist-credentials: false\n"
            "      - name: run\n        run: |\n          echo 'a # not a comment'\n          echo b\n"
        )
        self.assertEqual(list(doc["on"]), ["workflow_dispatch"])
        self.assertEqual(doc["permissions"], {})
        steps = doc["jobs"]["one"]["steps"]
        self.assertEqual(steps[0]["with"]["persist-credentials"], "false")
        self.assertEqual(steps[1]["run"], "echo 'a # not a comment'\necho b")
        self.assertEqual(doc["jobs"]["one"]["needs"], ["two"])

    def test_constructs_outside_the_subset_fail_closed(self):
        for source in (
            "a: &anchor 1\n", "a: *alias\n", "a: {b: 1}\n", "a: 1\na: 2\n", "a:\n\t- b\n",
            # Keys and scalars a real YAML parser could read differently from this one.
            '"on":\n  push:\n', "'on':\n  push:\n", '"o\\u006e":\n  push:\n', "<<: {}\n", "a b: 1\n",
            "jobs:\n  - 'x': 1\n", 'a: "tab\\tescape"\n', "a: 'it's'\n", "a: echo b: c\n",
            'a: ["x,y", z]\n', "a: [x, 'y]\n", "a: %directive\n", "a: |2\n  text\n",
        ):
            with self.subTest(source=source):
                with self.assertRaises(yaml_subset.YamlError):
                    yaml_subset.parse(source)

    def test_every_repository_workflow_is_readable(self):
        workflows = sorted((HERE.parents[3] / ".github" / "workflows").glob("*.yml"))
        self.assertTrue(workflows)
        for path in workflows:
            with self.subTest(path=path.name):
                self.assertIn("jobs", yaml_subset.parse(path.read_text()))


if __name__ == "__main__":
    unittest.main()
