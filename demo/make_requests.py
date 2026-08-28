#!/usr/bin/env python3
"""Generate a small classification workload: the boring kind of job where
equivalence between two stacks is two lines of code to measure."""
import json, random, sys

N = int(sys.argv[1]) if len(sys.argv) > 1 else 2000
OUT = sys.argv[2] if len(sys.argv) > 2 else "demo.jsonl"
random.seed(7)

SUBJECTS = ["the delivery", "support", "the invoice", "onboarding", "the dashboard",
            "billing", "the mobile app", "the migration", "the API", "documentation"]
VERDICTS = ["was excellent and arrived early", "was a complete disaster",
            "was fine, nothing special", "exceeded what we expected",
            "took three weeks longer than promised", "worked exactly as documented"]

with open(OUT, "w") as f:
    for i in range(N):
        text = f"{random.choice(SUBJECTS)} {random.choice(VERDICTS)}"
        f.write(json.dumps({
            "request_id": f"r{i:06d}",
            "prompt": ("Classify the sentiment as positive, negative or neutral. "
                       f"Answer with one word only.\n\nText: {text}\nSentiment:"),
        }) + "\n")
print(f"wrote {N} requests to {OUT}")
