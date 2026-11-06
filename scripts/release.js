#!/usr/bin/env node
// Prepare a release on a feature branch, or rebuild the current one.
//
// Usage:
//   node release.js prepare patch   # commit the bump 0.1.0 → 0.1.1 to this branch
//   node release.js prepare minor   # commit the bump 0.1.0 → 0.2.0 to this branch
//   node release.js prepare major   # commit the bump 0.1.0 → 1.0.0 to this branch
//   node release.js rebuild         # move the current version's tag to main's HEAD
//
// Merging a prepared bump to main makes release.yml tag and build it.

import { execSync } from 'child_process';
import { existsSync, readFileSync, writeFileSync } from 'fs';
import { dirname, join } from 'path';
import { fileURLToPath } from 'url';
import { createInterface } from 'readline';

const rootDir = join(dirname(fileURLToPath(import.meta.url)), '..');
const changelogPath = join(rootDir, 'CHANGELOG.md');

const VERSION_FILES = [
  'Cargo.toml',
  'package.json',
  'frontend/package.json',
  'crates/opca-core/Cargo.toml',
  'crates/opca-cli/Cargo.toml',
  'crates/opca-tauri/Cargo.toml',
  'crates/opca-tauri/tauri.conf.json',
  'Cargo.lock',
  'CHANGELOG.md',
];

// iOS files, which exist only once the iOS project is generated.
const OPTIONAL_FILES = [
  'crates/opca-tauri/gen/apple/project.yml',
  'crates/opca-tauri/gen/apple/opca_iOS/Info.plist',
];

function usage() {
  console.error('Usage: node release.js prepare <patch|minor|major>');
  console.error('       node release.js rebuild');
  process.exit(1);
}

function fail(...lines) {
  lines.forEach(line => console.error(line));
  process.exit(1);
}

function run(cmd) {
  console.log(`$ ${cmd}`);
  try {
    execSync(cmd, { cwd: rootDir, stdio: 'inherit' });
  } catch {
    fail(`Command failed: ${cmd}`);
  }
}

function runSilent(cmd) {
  return execSync(cmd, { cwd: rootDir, encoding: 'utf8' }).trim();
}

function ask(question) {
  const rl = createInterface({ input: process.stdin, output: process.stdout });
  return new Promise(resolve => rl.question(question, answer => {
    rl.close();
    resolve(answer.toLowerCase().trim());
  }));
}

function uncommittedFiles() {
  return runSilent('git status --porcelain').split('\n').filter(line => line.trim());
}

function refuseDirtyTree(files) {
  if (files.length > 0) {
    fail('Error: Working directory has uncommitted changes:', ...files.map(line => `  ${line}`));
  }
}

function currentVersion() {
  return JSON.parse(readFileSync(join(rootDir, 'package.json'), 'utf8')).version;
}

function nextVersion(version, bumpType) {
  const [major, minor, patch] = version.split('.').map(Number);
  return {
    major: `${major + 1}.0.0`,
    minor: `${major}.${minor + 1}.0`,
    patch: `${major}.${minor}.${patch + 1}`,
  }[bumpType];
}

function sectionBody(prefix) {
  const section = readFileSync(changelogPath, 'utf8').split(/^## \[/m).find(s => s.startsWith(prefix));
  return section?.replace(/^[^\n]*\n/, '').trim();
}

function releaseChangelog(version) {
  const versionHeader = new RegExp(`^## \\[${version.replace(/\./g, '\\.')}\\]`, 'm');
  const unreleasedHeader = /^## \[Unreleased\]/m;
  const changelog = readFileSync(changelogPath, 'utf8');

  if (versionHeader.test(changelog)) {
    console.log(`✓ Found changelog section for version ${version}`);
    return;
  }
  if (!unreleasedHeader.test(changelog)) {
    fail(
      `Error: CHANGELOG.md has no section for version ${version} and no [Unreleased] section.`,
      'Please add release notes before releasing.',
    );
  }
  const hasNotes = sectionBody('Unreleased]')
    .split('\n')
    .some(line => line.trim() && !line.startsWith('###'));
  if (!hasNotes) {
    fail('Error: [Unreleased] section exists but has no content.', 'Please add release notes before releasing.');
  }

  const today = new Date().toLocaleDateString('sv');
  writeFileSync(changelogPath, changelog.replace(unreleasedHeader, `## [${version}] - ${today}`), 'utf8');
  console.log(`✓ Updated [Unreleased] → [${version}] - ${today}`);
}

function printChangelog(version) {
  const notes = sectionBody(`${version}]`);
  if (notes) {
    console.log(`\n--- Changelog for ${version} ---\n${notes}\n--- End of changelog ---\n`);
  }
}

function prepare(bumpType) {
  if (!['major', 'minor', 'patch'].includes(bumpType)) usage();

  const branch = runSilent('git branch --show-current');
  if (branch === 'main' || !branch) {
    fail(`Error: Prepare a release on a feature branch, not '${branch || 'a detached HEAD'}'.`);
  }
  refuseDirtyTree(uncommittedFiles().filter(line => !line.endsWith('CHANGELOG.md')));

  const current = currentVersion();
  const version = nextVersion(current, bumpType);
  console.log(`\nPreparing ${bumpType} release: ${current} → ${version}\n`);
  releaseChangelog(version);
  printChangelog(version);

  run(`node scripts/bump-version.js ${bumpType}`);
  run('cargo check --manifest-path crates/opca-tauri/Cargo.toml');

  const optional = OPTIONAL_FILES.filter(file => existsSync(join(rootDir, file)));
  run(`git add ${[...VERSION_FILES, ...optional].join(' ')}`);
  run(`git commit -m "Bump version to ${version}"`);

  console.log(`
✅ Committed the bump to ${version} on '${branch}'.

Next: push the branch and open a PR. Merging it to main makes release.yml
tag v${version} and build a draft release at
https://github.com/Wired-Square/opca/releases to review and publish.
`);
}

async function rebuild() {
  const branch = runSilent('git branch --show-current');
  if (branch !== 'main') fail(`Error: Rebuild from 'main' (currently on '${branch}').`);
  refuseDirtyTree(uncommittedFiles());

  const version = currentVersion();
  const tag = `v${version}`;
  if (!runSilent('git tag --list').split('\n').includes(tag)) {
    fail(`Error: Tag ${tag} does not exist. Prepare a release for a new version.`);
  }
  printChangelog(version);

  const answer = await ask(`Move ${tag} to main's HEAD and push it to rebuild? [y/N] `);
  if (answer !== 'y' && answer !== 'yes') {
    console.log('Rebuild cancelled.');
    return;
  }

  run(`git tag -f ${tag}`);
  run(`git push origin :refs/tags/${tag}`);
  run(`git push origin ${tag}`);

  console.log(`
✅ Pushed ${tag} at main's HEAD; build.yml rebuilds the draft release at
https://github.com/Wired-Square/opca/releases
`);
}

const [mode, bumpType] = process.argv.slice(2);
if (mode === 'prepare') prepare(bumpType);
else if (mode === 'rebuild') await rebuild();
else usage();
