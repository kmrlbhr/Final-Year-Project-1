"""Build a labelled URL list for evaluate.js from public phishing datasets.

Sources (use any combination):
  --kaggle     phishing_site_urls.csv from the Kaggle "Phishing Site URLs" dataset
               (taruntiwarihp/phishing-site-urls). Has both phishing ("bad") and
               legitimate ("good") rows.
  --opdb       The OpenPhish Database SQLite file (opdb.db) downloaded with pyopdb
               (github.com/openphish/pyopdb). Phishing rows only.
  --openphish-feed  The free OpenPhish community feed (feed.txt). Phishing rows only.
  --tranco     A Tranco (or Cisco Umbrella) top-sites CSV of "rank,domain" rows, used
               as the legitimate side for the OpenPhish sources.
  --safe-browsing-tests  Adds Google's three Safe Browsing test pages
               (testsafebrowsing.appspot.com) as a check that the baseline works.

Output: a CSV with url,label,source,scheme_known columns (label 1 = phishing).

Example:
  python evaluation/build_dataset.py --kaggle data/phishing_site_urls.csv \
      --opdb data/opdb.db --tranco data/top-1m.csv --limit 5000 --out evaluation/urls.csv
"""

from __future__ import annotations

import argparse
import csv
import io
import random
import sqlite3
import sys
import zipfile
from pathlib import Path

SAFE_BROWSING_TESTS = Path(__file__).with_name("safe_browsing_test_urls.csv")

KAGGLE_PHISHING_LABELS = {"bad", "phishing", "1"}
KAGGLE_LEGITIMATE_LABELS = {"good", "legitimate", "benign", "0"}


def normalise(url: str) -> tuple[str, bool] | None:
    """Return (url, scheme_known). Kaggle URLs often have no scheme, so http:// is added."""
    url = url.strip().strip('"')
    if not url or any(ch.isspace() for ch in url):
        return None
    if "://" in url.split("/", 1)[0] or url.lower().startswith(("http://", "https://")):
        return url, True
    return f"http://{url}", False


def open_text(path: Path) -> io.TextIOBase:
    """Open a CSV or TXT file, reading the first CSV/TXT inside it if it is a zip."""
    if zipfile.is_zipfile(path):
        archive = zipfile.ZipFile(path)
        name = next(n for n in archive.namelist() if n.lower().endswith((".csv", ".txt")))
        return io.TextIOWrapper(archive.open(name), encoding="utf-8", errors="replace", newline="")
    return open(path, encoding="utf-8", errors="replace", newline="")


def load_kaggle(path: Path) -> list[dict]:
    rows = []
    with open_text(path) as handle:
        reader = csv.DictReader(handle)
        fields = {name.strip().lower(): name for name in reader.fieldnames or []}
        if "url" not in fields or "label" not in fields:
            sys.exit(f"{path}: expected URL and Label columns, found {reader.fieldnames}")
        for record in reader:
            label = (record[fields["label"]] or "").strip().lower()
            if label in KAGGLE_PHISHING_LABELS:
                phishing = True
            elif label in KAGGLE_LEGITIMATE_LABELS:
                phishing = False
            else:
                continue
            normalised = normalise(record[fields["url"]] or "")
            if normalised:
                rows.append(make_row(normalised, phishing, "kaggle"))
    return rows


def load_opdb(path: Path) -> list[dict]:
    connection = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
    try:
        urls = [row[0] for row in connection.execute(
            "SELECT DISTINCT url FROM phishing_urls WHERE url IS NOT NULL AND url != ''"
        )]
    except sqlite3.DatabaseError as error:
        sys.exit(f"{path}: not an OpenPhish database ({error})")
    finally:
        connection.close()
    return [make_row(n, True, "openphish-db") for n in map(normalise, urls) if n]


def load_openphish_feed(path: Path) -> list[dict]:
    with open_text(path) as handle:
        return [make_row(n, True, "openphish-feed") for n in map(normalise, handle) if n]


def load_tranco(path: Path, count: int) -> list[dict]:
    rows = []
    with open_text(path) as handle:
        for record in csv.reader(handle):
            if len(rows) >= count:
                break
            if len(record) < 2 or not record[0].strip().isdigit():
                continue
            rows.append(make_row((f"https://{record[1].strip()}/", True), False, "tranco"))
    return rows


def make_row(normalised: tuple[str, bool], phishing: bool, source: str) -> dict:
    url, scheme_known = normalised
    return {"url": url, "label": 1 if phishing else 0, "source": source,
            "scheme_known": 1 if scheme_known else 0}


def sample(rows: list[dict], limit: int | None, rng: random.Random) -> list[dict]:
    if limit is None or len(rows) <= limit:
        return rows
    return rng.sample(rows, limit)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--kaggle", type=Path)
    parser.add_argument("--opdb", type=Path)
    parser.add_argument("--openphish-feed", type=Path)
    parser.add_argument("--tranco", type=Path)
    parser.add_argument("--safe-browsing-tests", action="store_true")
    parser.add_argument("--limit", type=int, default=None,
                        help="maximum phishing and legitimate URLs taken from each source")
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--out", type=Path, default=Path("evaluation/urls.csv"))
    args = parser.parse_args()

    if not (args.kaggle or args.opdb or args.openphish_feed):
        parser.error("give at least one of --kaggle, --opdb or --openphish-feed")

    rng = random.Random(args.seed)
    rows: list[dict] = []

    if args.kaggle:
        kaggle = load_kaggle(args.kaggle)
        rows += sample([r for r in kaggle if r["label"] == 1], args.limit, rng)
        rows += sample([r for r in kaggle if r["label"] == 0], args.limit, rng)

    openphish: list[dict] = []
    if args.opdb:
        openphish += sample(load_opdb(args.opdb), args.limit, rng)
    if args.openphish_feed:
        openphish += sample(load_openphish_feed(args.openphish_feed), args.limit, rng)
    rows += openphish

    if openphish:
        if args.tranco:
            # Take the top sites, enough to match the OpenPhish phishing count.
            rows += load_tranco(args.tranco, len(openphish))
        else:
            print("Warning: no --tranco list given, so the OpenPhish URLs have no legitimate "
                  "counterpart and false-positive rates will come from Kaggle only.")

    if args.safe_browsing_tests:
        with open(SAFE_BROWSING_TESTS, encoding="utf-8", newline="") as handle:
            lines = [line for line in handle if not line.startswith("#")]
        rows += [dict(row, label=int(row["label"]), scheme_known=int(row["scheme_known"]))
                 for row in csv.DictReader(lines)]

    # Drop duplicates. If a URL appears with both labels, it is ambiguous and removed.
    labels_by_url: dict[str, set[int]] = {}
    for row in rows:
        labels_by_url.setdefault(row["url"], set()).add(row["label"])
    seen: set[str] = set()
    unique = []
    for row in rows:
        if len(labels_by_url[row["url"]]) == 1 and row["url"] not in seen:
            seen.add(row["url"])
            unique.append(row)

    args.out.parent.mkdir(parents=True, exist_ok=True)
    with open(args.out, "w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=["url", "label", "source", "scheme_known"])
        writer.writeheader()
        writer.writerows(unique)

    counts: dict[tuple[str, int], int] = {}
    for row in unique:
        counts[(row["source"], row["label"])] = counts.get((row["source"], row["label"]), 0) + 1
    print(f"Wrote {len(unique)} URLs to {args.out}")
    for (source, label), count in sorted(counts.items()):
        print(f"  {source:<15} {'phishing' if label else 'legitimate':<11} {count}")


if __name__ == "__main__":
    main()
