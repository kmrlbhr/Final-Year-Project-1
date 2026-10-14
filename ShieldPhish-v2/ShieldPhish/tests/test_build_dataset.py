"""Tests for evaluation/build_dataset.py. Run with: python -m unittest discover -s tests"""

import csv
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
FIXTURES = ROOT / "tests" / "fixtures"
SCRIPT = ROOT / "evaluation" / "build_dataset.py"


def build(*args: str) -> list[dict]:
    with tempfile.TemporaryDirectory() as tmp:
        out = Path(tmp) / "urls.csv"
        subprocess.run([sys.executable, str(SCRIPT), *args, "--out", str(out)],
                       check=True, capture_output=True, text=True)
        with open(out, newline="", encoding="utf-8") as handle:
            return list(csv.DictReader(handle))


class BuildDatasetTest(unittest.TestCase):
    def test_kaggle_labels_and_missing_schemes(self):
        rows = build("--kaggle", str(FIXTURES / "kaggle_sample.csv"))
        by_url = {row["url"]: row for row in rows}
        self.assertEqual(by_url["http://youtube.com/"]["label"], "0")
        self.assertEqual(by_url["http://youtube.com/"]["scheme_known"], "0")
        self.assertEqual(by_url["http://192.168.10.5/maybank/login.php"]["label"], "1")
        self.assertEqual(by_url["http://192.168.10.5/maybank/login.php"]["scheme_known"], "1")
        self.assertEqual(by_url["https://www.unikl.edu.my/"]["scheme_known"], "1")
        # The duplicated phishing row is kept once.
        self.assertEqual(len(rows), 8)
        self.assertEqual({row["source"] for row in rows}, {"kaggle"})

    def test_opdb_rows_are_phishing_and_paired_with_top_sites(self):
        rows = build("--opdb", str(FIXTURES / "opdb-sample.db"),
                     "--tranco", str(FIXTURES / "tranco_sample.csv"))
        phishing = [row for row in rows if row["label"] == "1"]
        legitimate = [row for row in rows if row["label"] == "0"]
        self.assertEqual(len(phishing), 5)
        self.assertTrue(all(row["source"] == "openphish-db" for row in phishing))
        self.assertEqual(len(legitimate), 5)
        self.assertEqual(legitimate[0]["url"], "https://google.com/")

    def test_sources_combine_and_respect_the_limit(self):
        rows = build("--kaggle", str(FIXTURES / "kaggle_sample.csv"),
                     "--opdb", str(FIXTURES / "opdb-sample.db"),
                     "--openphish-feed", str(FIXTURES / "openphish_feed_sample.txt"),
                     "--tranco", str(FIXTURES / "tranco_sample.csv"),
                     "--limit", "2")
        counts = {}
        for row in rows:
            counts[(row["source"], row["label"])] = counts.get((row["source"], row["label"]), 0) + 1
        self.assertEqual(counts[("kaggle", "1")], 2)
        self.assertEqual(counts[("kaggle", "0")], 2)
        self.assertEqual(counts[("openphish-db", "1")], 2)
        # moobiileleginds.xyz is in both OpenPhish sources; duplicates are dropped.
        self.assertLessEqual(counts[("openphish-feed", "1")], 2)

    def test_safe_browsing_test_pages_can_be_added(self):
        rows = build("--kaggle", str(FIXTURES / "kaggle_sample.csv"), "--safe-browsing-tests")
        tests = [row for row in rows if row["source"] == "gsb-test"]
        self.assertEqual(len(tests), 3)
        self.assertTrue(all(row["label"] == "1" for row in tests))
        self.assertIn("https://testsafebrowsing.appspot.com/s/phishing.html", {row["url"] for row in tests})


if __name__ == "__main__":
    unittest.main()
