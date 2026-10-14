// Evaluates ShieldPhish's URL-based detection on a labelled list of URLs and, when an API key
// is available, compares it with Google Safe Browsing.
//
// Usage:
//   node evaluation/evaluate.js evaluation/urls.csv [--out evaluation/results.csv]
//   set GOOGLE_SAFE_BROWSING_API_KEY=...   (Windows)   to add the Safe Browsing baseline
//
// Input CSV columns: url,label[,source,scheme_known]  where label is 1 for phishing and 0 for
// legitimate. build_dataset.py makes this file from the Kaggle and OpenPhish datasets.
// scheme_known = 0 marks URLs stored without http:// or https://, so the HTTPS check is skipped.
//
// Only URL signals are evaluated (the Random Forest and the URL heuristics). Page-content
// signals need the page to be loaded in a browser, so they are not covered here.
const fs = require('node:fs');
const path = require('node:path');

const { extractUrlFeatures, predictPhishingProbability, scoreUrlHeuristics } = require('../url_features.js');
require('../random_forest_model.js');
const { lookupUrls } = require('./safe_browsing.js');
const model = globalThis.shieldPhishRandomForest;

const MODEL_THRESHOLD = 0.5;
// The URL-only score is the URL heuristics plus up to 20 model points. 20 or more means at
// least one clear URL warning sign.
const URL_SCORE_THRESHOLD = 20;

function parseArgs(argv) {
  const args = { input: null, out: null };
  for (let i = 0; i < argv.length; i += 1) {
    if (argv[i] === '--out') {
      args.out = argv[i += 1];
    } else {
      args.input = argv[i];
    }
  }
  if (!args.input) {
    console.error('Usage: node evaluation/evaluate.js <urls.csv> [--out results.csv]');
    process.exit(1);
  }
  args.out = args.out || path.join(path.dirname(args.input), 'results.csv');
  return args;
}

// Splits one CSV line, allowing quoted fields that contain commas or doubled quotes.
function splitCsvLine(line) {
  const fields = [];
  let field = '';
  let quoted = false;
  for (let i = 0; i < line.length; i += 1) {
    const ch = line[i];
    if (quoted) {
      if (ch === '"' && line[i + 1] === '"') { field += '"'; i += 1; }
      else if (ch === '"') quoted = false;
      else field += ch;
    } else if (ch === '"') quoted = true;
    else if (ch === ',') { fields.push(field); field = ''; }
    else field += ch;
  }
  fields.push(field);
  return fields;
}

function readLabelledUrls(file) {
  const rows = [];
  const lines = fs.readFileSync(file, 'utf8').split(/\r?\n/);
  lines.forEach((line, index) => {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('#')) {
      return;
    }
    const [url, rawLabel = '', source = 'unknown', schemeKnown = '1'] = splitCsvLine(trimmed);
    const label = rawLabel.trim();
    if (url.trim().toLowerCase() === 'url') {
      return;
    }
    if (label !== '0' && label !== '1') {
      console.warn(`Skipping line ${index + 1}: label must be 0 or 1`);
      return;
    }
    rows.push({
      url: url.trim(),
      phishing: label === '1',
      source: source.trim() || 'unknown',
      schemeKnown: schemeKnown.trim() !== '0'
    });
  });
  return rows;
}

function scoreWithShieldPhish(url, schemeKnown) {
  let parsed;
  try {
    parsed = new URL(url);
  } catch {
    return { probability: null, urlScore: null };
  }
  const probability = predictPhishingProbability(model, extractUrlFeatures(parsed));
  const heuristics = scoreUrlHeuristics(parsed, { ignoreScheme: !schemeKnown });
  const urlScore = Math.min(100, heuristics.score + Math.round(probability * 20));
  return { probability, urlScore };
}

function metrics(rows, predict) {
  let tp = 0; let fp = 0; let tn = 0; let fn = 0;
  rows.forEach((row) => {
    const predicted = predict(row);
    if (predicted && row.phishing) tp += 1;
    else if (predicted && !row.phishing) fp += 1;
    else if (!predicted && row.phishing) fn += 1;
    else tn += 1;
  });
  const ratio = (a, b) => (b === 0 ? 0 : a / b);
  const precision = ratio(tp, tp + fp);
  const recall = ratio(tp, tp + fn);
  return {
    tp, fp, tn, fn,
    accuracy: ratio(tp + tn, rows.length),
    precision,
    recall,
    f1: ratio(2 * precision * recall, precision + recall),
    falsePositiveRate: ratio(fp, fp + tn)
  };
}

function printTable(results) {
  const pct = (value) => `${(value * 100).toFixed(1)}%`;
  console.log('\nDetector                     Accuracy  Precision  Recall   F1      FPR     TP/FP/TN/FN');
  results.forEach(({ name, m }) => {
    console.log(
      `${name.padEnd(28)} ${pct(m.accuracy).padStart(8)} ${pct(m.precision).padStart(10)} `
      + `${pct(m.recall).padStart(7)} ${pct(m.f1).padStart(7)} ${pct(m.falsePositiveRate).padStart(7)}   `
      + `${m.tp}/${m.fp}/${m.tn}/${m.fn}`
    );
  });
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  const rows = readLabelledUrls(args.input);
  if (!rows.length) {
    console.error('No labelled URLs found.');
    process.exit(1);
  }
  rows.forEach((row) => Object.assign(row, scoreWithShieldPhish(row.url, row.schemeKnown)));

  const phishingCount = rows.filter((row) => row.phishing).length;
  console.log(`Evaluated ${rows.length} URLs (${phishingCount} phishing, ${rows.length - phishingCount} legitimate)`);

  const results = [
    { name: 'Random Forest (p >= 0.5)', m: metrics(rows, (r) => (r.probability ?? 0) >= MODEL_THRESHOLD) },
    { name: `URL score (>= ${URL_SCORE_THRESHOLD})`, m: metrics(rows, (r) => (r.urlScore ?? 0) >= URL_SCORE_THRESHOLD) }
  ];

  const apiKey = process.env.GOOGLE_SAFE_BROWSING_API_KEY;
  if (apiKey) {
    const flagged = await lookupUrls(rows.map((row) => row.url), apiKey);
    rows.forEach((row) => { row.safeBrowsing = flagged.has(row.url); });
    results.push({ name: 'Google Safe Browsing', m: metrics(rows, (r) => r.safeBrowsing) });
    results.push({
      name: 'ShieldPhish OR Safe Browsing',
      m: metrics(rows, (r) => r.safeBrowsing || (r.urlScore ?? 0) >= URL_SCORE_THRESHOLD)
    });
  } else {
    console.log('GOOGLE_SAFE_BROWSING_API_KEY is not set, so the Safe Browsing baseline is skipped.');
  }

  printTable(results);

  const sources = [...new Set(rows.map((row) => row.source))];
  if (sources.length > 1) {
    sources.forEach((source) => {
      const subset = rows.filter((row) => row.source === source);
      const phishing = subset.filter((row) => row.phishing).length;
      console.log(`\nSource: ${source} (${phishing} phishing, ${subset.length - phishing} legitimate)`);
      console.log('  Accuracy and precision are only meaningful for sources with both classes.');
      printTable([
        { name: 'URL score', m: metrics(subset, (r) => (r.urlScore ?? 0) >= URL_SCORE_THRESHOLD) },
        ...(apiKey ? [{ name: 'Google Safe Browsing', m: metrics(subset, (r) => r.safeBrowsing) }] : [])
      ]);
    });
  }

  const header = 'url,label,source,model_probability,url_score,safe_browsing';
  const lines = rows.map((row) => [
    `"${row.url.replace(/"/g, '""')}"`,
    row.phishing ? 1 : 0,
    row.source,
    row.probability === null ? '' : row.probability.toFixed(4),
    row.urlScore ?? '',
    row.safeBrowsing === undefined ? '' : (row.safeBrowsing ? 1 : 0)
  ].join(','));
  fs.writeFileSync(args.out, `${header}\n${lines.join('\n')}\n`);
  console.log(`\nPer-URL results written to ${args.out}`);
}

main().catch((error) => {
  console.error(error.message);
  process.exit(1);
});
