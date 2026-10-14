# ShieldPhish

ShieldPhish is a browser extension designed to detect suspicious phishing websites in real time. It analyzes a page for risky URL structure, fake login indicators, suspicious wording, and credential-collection patterns to warn users before they enter sensitive information.

## Tagline
Detect phishing websites before they steal your data.

## Features
- Checks URL patterns for phishing-style domains
- Flags pages that use insecure or suspicious URL structures
- Detects forms asking for passwords, emails, and account details
- Reviews page text and titles for scam keywords
- Adds a local Random Forest estimate based on URL structure
- Displays a risk score and explanation in a popup

## How It Works
ShieldPhish inspects the current page and combines lightweight page heuristics with an experimental local Random Forest URL estimate. The score is shown in the popup, along with the main reasons the page was flagged.

## Experimental Random Forest
The extension bundles a 64-tree Random Forest trained on seven URL features from the UCI Phishing Websites dataset: IP-address hosts, URL length, known URL shorteners, `@` characters, extra `//` sequences, hyphens in the hostname, and subdomain depth. Inference runs locally in the content script (feature extraction lives in `url_features.js`); page contents are not sent to a service.

The forest can add up to 20 points to the existing heuristic score and cannot lower it. The model is an experimental signal, not a verdict or a guarantee of safety. On a stratified random 20% holdout split (seed 42), the training script measured 73.2% accuracy, 83.4% phishing recall, 65.5% phishing precision, 73.4% F1-score, and a 34.9% false-positive rate. This is not independent, domain-grouped, or time-based validation. It can miss current phishing sites and flag legitimate ones. Do not use it as the only protection.

To retrain and export the bundled model, install the Python dependency and run the training script. The script downloads the dataset from UCI and overwrites `random_forest_model.js`.

```powershell
python -m pip install -r requirements.txt
python train_model.py
```

Dataset attribution: R. Mohammad and L. McCluskey, [Phishing Websites](https://doi.org/10.24432/C51W2X), UCI Machine Learning Repository, CC BY 4.0. The training script uses only the seven URL-derived features listed above; it does not use the dataset's reputation or page-content features.

## Testing
The tests need Node.js 18 or newer and Python 3.8 or newer. Install the test dependency once, then run the tests:

```powershell
npm install
npm test
python -m unittest discover -s tests
```

`tests/url_features.test.js` checks that each URL feature uses the same encoding as the UCI dataset the model was trained on. `tests/page_scoring.test.js` loads `content.js` into a simulated page to check that normal sign-in pages stay low risk and typical phishing pages are flagged. `tests/safe_browsing.test.js` checks the Safe Browsing client against a simulated API, so it needs no key. `tests/test_build_dataset.py` checks the dataset builder on small sample files in `tests/fixtures`.

## Evaluation
Evaluation has two steps: `evaluation/build_dataset.py` turns public phishing datasets into one labelled URL list, and `evaluation/evaluate.js` scores ShieldPhish on that list. The evaluation covers the URL signals only (the Random Forest and URL heuristics), because page-content signals need the page loaded in a browser.

### 1. Download the datasets
Put the files in a `data` folder next to `manifest.json` (it is ignored by git).

| Dataset | What it gives | How to get it |
| --- | --- | --- |
| [Kaggle Phishing Site URLs](https://www.kaggle.com/datasets/taruntiwarihp/phishing-site-urls) | About 549,000 URLs labelled `bad` (phishing) or `good` (legitimate) | Sign in to Kaggle, click **Download** on the dataset page, and save the zip (or the `phishing_site_urls.csv` inside it) as `data/phishing_site_urls.zip`. |
| [OpenPhish Database](https://openphish.com/phishing_database.html) via [pyopdb](https://github.com/openphish/pyopdb) | Recent, verified phishing URLs | Request a free trial or academic licence from OpenPhish. Clone pyopdb, put the keys and licence type in its `opdb.ini`, then run `python pyopdb.py update` (see the pyopdb wiki). Copy the resulting `opdb.db` to `data/opdb.db`. |
| [OpenPhish community feed](https://openphish.com/feed.txt) (optional, no licence) | The latest few hundred phishing URLs | Save `https://openphish.com/feed.txt` as `data/feed.txt`. |
| [Tranco top sites](https://tranco-list.eu/) | Legitimate sites to pair with OpenPhish, which only has phishing URLs | Download the latest list and save it as `data/tranco.zip`. |

Write down the date you downloaded each file, because phishing data goes stale quickly and your report should state it.

### 2. Build the URL list
```powershell
python evaluation/build_dataset.py --kaggle data/phishing_site_urls.zip --opdb data/opdb.db --tranco data/tranco.zip --limit 5000 --out evaluation/urls.csv
```

Use any combination of `--kaggle`, `--opdb` and `--openphish-feed`. `--limit` caps the phishing and legitimate URLs taken from each source, picked at random with a fixed seed so the list can be rebuilt. Duplicate URLs are dropped, and URLs that appear with both labels are removed. OpenPhish phishing URLs are paired with the same number of top Tranco sites.

Kaggle stores most URLs without `http://` or `https://`. The builder adds `http://` so they can be parsed, and marks them so the evaluation skips the HTTPS check for them.

### 3. Run the evaluation
```powershell
node evaluation/evaluate.js evaluation/urls.csv
```

It prints accuracy, precision, recall, F1-score and false-positive rate overall and for each source, and writes every URL's result to `evaluation/results.csv`. `evaluation/sample_urls.csv` is a small made-up list for checking the script runs; its numbers mean nothing.

### 4. Compare with Google Safe Browsing
Create a Safe Browsing API key in Google Cloud (enable the Safe Browsing API, then create an API key) and set it in PowerShell:

```powershell
$env:GOOGLE_SAFE_BROWSING_API_KEY = "your-key"
```

First check the key works using [Google's Safe Browsing test site](https://testsafebrowsing.appspot.com/). Its phishing, malware and unwanted-software test pages are always reported by the API:

```powershell
node evaluation/check_safe_browsing.js
```

Each test page should show PASS. The output also shows ShieldPhish's URL score for the same pages. Their URLs look ordinary, so ShieldPhish is not expected to flag them: a blocklist catches pages it already knows, while heuristics catch suspicious-looking pages, including new ones. That difference is worth explaining in the report.

Then run the evaluation again. With the key set, it adds Google Safe Browsing and "ShieldPhish OR Safe Browsing" rows to the results. Use `--limit` when building the list to stay within the API's daily quota. Add `--safe-browsing-tests` to `build_dataset.py` to include the three test pages in the list as a sanity check.

```powershell
node evaluation/evaluate.js evaluation/urls.csv
```

### Limitations to state in the report
- The Kaggle dataset was published around 2020 and is not updated, so it does not reflect current phishing techniques.
- Tranco entries are homepages (`https://domain/`), while phishing URLs usually have long paths, which makes the legitimate side easier than real browsing. Kaggle's `good` URLs include paths and are a fairer comparison.
- Google Safe Browsing may no longer list old phishing URLs that have been taken down, which lowers its recall on older data.

Dataset attribution: OpenPhish Database, OpenPhish (opdb-sample.db in `tests/fixtures` is from the MIT-licensed pyopdb repository); Phishing Site URLs, taruntiwarihp on Kaggle; Tranco, Le Pochat et al. (NDSS 2019).

## Installation
1. Open your browser and go to the extension management page.
2. Enable Developer mode.
3. Click Load unpacked.
4. Select the ShieldPhish folder.

## Example Risk Levels
- Low risk: page looks normal
- Medium risk: some suspicious indicators are present
- High risk: likely scam or phishing attempt

## Future Improvements
- Block dangerous pages automatically
- Add phishing URL blacklists
- Improve the model using recent, independently validated training data
- Add a dashboard and reporting system

## Project Identity
- Name: ShieldPhish
- Category: Cybersecurity / Browser Extension
- Goal: Help users avoid phishing scams and credential theft
