#!/usr/bin/env node
// Render every ```mermaid block in tracked markdown and fail on any parse error.
// One browser for all blocks — mmdc-per-block takes ~15s each, this takes seconds.
//
// Usage: node scripts/check-mermaid.mjs            (check tracked *.md)
//        node scripts/check-mermaid.mjs <file>...  (check specific files)
// Env:   PUPPETEER_EXECUTABLE_PATH to point at an existing Chromium
//
// Wired into .github/workflows/quality.yml so a broken diagram fails at review
// time instead of rendering as an error box on GitHub.

import { execFileSync } from 'node:child_process';
import { readFileSync, mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createServer } from 'node:http';

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const tmp = mkdtempSync(join(tmpdir(), 'mermaid-'));
process.on('exit', () => rmSync(tmp, { recursive: true, force: true }));

// ---- collect blocks ----
function mermaidBlocks(text) {
  const lines = text.split('\n');
  const blocks = [];
  let cur = null;
  for (let i = 0; i < lines.length; i++) {
    const t = lines[i].trim();
    if (t.startsWith('```mermaid')) {
      cur = { start: i + 2, body: [] };
      continue;
    }
    if (cur) {
      if (t.startsWith('```')) {
        blocks.push({ start: cur.start, end: i, body: cur.body.join('\n') });
        cur = null;
      } else {
        cur.body.push(lines[i]);
      }
    }
  }
  return blocks;
}

function trackedMarkdownFiles() {
  return execFileSync('git', ['ls-files', '*.md'], { cwd: repoRoot, encoding: 'utf8' })
    .split('\n')
    .filter(Boolean);
}

const args = process.argv.slice(2);
const files = args.length ? args : trackedMarkdownFiles();

const jobs = [];
for (const f of files) {
  const abs = resolve(repoRoot, f);
  let text;
  try {
    text = readFileSync(abs, 'utf8');
  } catch {
    console.error(`SKIP ${f} — not readable`);
    continue;
  }
  if (!text.includes('```mermaid')) continue;
  for (const b of mermaidBlocks(text)) jobs.push({ file: f, ...b });
}

if (!jobs.length) {
  console.log('OK — no mermaid blocks found');
  process.exit(0);
}

// ---- render all in one browser page ----
const { createRequire } = await import('node:module');
const require_ = createRequire(import.meta.url);
const puppeteerDir = execFileSync('bash', [
  '-c', 'ls -d "$HOME"/.npm/_npx/*/node_modules/puppeteer 2>/dev/null | head -1',
], { encoding: 'utf8' }).trim();
const puppeteer = process.env.MERMAID_PUPPETEER
  ? (await import(process.env.MERMAID_PUPPETEER)).default
  : require_(join(puppeteerDir, 'lib', 'puppeteer', 'puppeteer.js'));

const browser = await puppeteer.launch({
  headless: true,
  protocolTimeout: 180_000, // the mermaid bundle is multi-MB; first import is slow
  args: ['--no-sandbox', '--disable-setuid-sandbox', '--disable-dev-shm-usage'],
});

let failed = 0;
let serverRef = null;
try {
  const page = await browser.newPage();

  // mermaid.min.js is the UMD/iife build: loading it as a classic script puts
  // the API on window.mermaid with no module graph to resolve, so a plain
  // single-file http response is enough (the .esm build splits into chunks and
  // needs the whole dist/chunks tree served).
  const mermaidBundle = execFileSync('bash', [
    '-c', 'ls -d "$HOME"/.npm/_npx/*/node_modules/mermaid/dist/mermaid.min.js 2>/dev/null | head -1',
  ], { encoding: 'utf8' }).trim();
  if (!mermaidBundle) {
    console.error('mermaid not found in npx cache — run: npx -y @mermaid-js/mermaid-cli --version');
    process.exit(2);
  }
  const bundle = readFileSync(mermaidBundle);
  serverRef = createServer((req, res) => {
    if (req.url === '/mermaid.min.js') {
      res.writeHead(200, { 'content-type': 'text/javascript; charset=utf-8' });
      res.end(bundle);
    } else {
      res.writeHead(200, { 'content-type': 'text/html; charset=utf-8' });
      res.end('<!doctype html><meta charset="utf-8"><body><div id="c"></div></body>');
    }
  });
  await new Promise((r) => serverRef.listen(0, '127.0.0.1', r));
  const { port } = serverRef.address();
  await page.goto(`http://127.0.0.1:${port}/`);
  await page.addScriptTag({ url: `http://127.0.0.1:${port}/mermaid.min.js` });
  await page.evaluate(() => {
    window.__m = window.mermaid;
    window.__m.initialize({ startOnLoad: false, securityLevel: 'loose' });
  });

  for (const job of jobs) {
    try {
      const err = await page.evaluate(async (body) => {
        try {
          await window.__m.parse(body);
          return null;
        } catch (e) {
          return String(e && e.message ? e.message : e).split('\n').slice(0, 3).join(' ');
        }
      }, job.body);
      if (err) {
        failed++;
        console.error(`FAIL ${job.file}:${job.start}-${job.end} — ${err}`);
      }
    } catch (e) {
      failed++;
      console.error(`FAIL ${job.file}:${job.start}-${job.end} — ${String(e).split('\n')[0]}`);
    }
  }
} finally {
  await browser.close();
  serverRef?.close();
}

if (failed) {
  console.error(`\nFAILED — ${failed} of ${jobs.length} mermaid blocks do not parse`);
  process.exit(1);
}
console.log(`OK — ${jobs.length} mermaid blocks in ${files.length} files parse cleanly`);
