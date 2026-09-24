#!/usr/bin/env node
// Bump version across all config files
//
// The single source of truth is [workspace.package] version in Cargo.toml.
// Crate Cargo.toml files inherit via `version.workspace = true`, and
// tauri.conf.json falls back to the Cargo.toml package version, so neither
// needs updating here. The Sidebar reads the version at runtime via the
// Tauri app API.
//
// Usage:
//   node bump-version.js         # patch: 0.1.0 → 0.1.1
//   node bump-version.js patch   # patch: 0.1.0 → 0.1.1
//   node bump-version.js minor   # minor: 0.1.0 → 0.2.0
//   node bump-version.js major   # major: 0.1.0 → 1.0.0

import { readFileSync, writeFileSync } from 'fs';
import { dirname, join } from 'path';
import { fileURLToPath } from 'url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const rootDir = join(__dirname, '..');
const tauriDir = join(rootDir, 'crates', 'opca-tauri');

// Parse bump type from args (default: patch)
const bumpType = process.argv[2] || 'patch';
if (!['major', 'minor', 'patch'].includes(bumpType)) {
  console.error(`Invalid bump type: ${bumpType}`);
  console.error('Usage: node bump-version.js [major|minor|patch]');
  process.exit(1);
}

// Read current version from workspace Cargo.toml (source of truth)
const workspaceCargoPath = join(rootDir, 'Cargo.toml');
const workspaceCargo = readFileSync(workspaceCargoPath, 'utf8');
const versionMatch = workspaceCargo.match(/\[workspace\.package\]\s*\nversion\s*=\s*"([^"]+)"/);
if (!versionMatch) {
  console.error('Could not find [workspace.package] version in Cargo.toml');
  process.exit(1);
}
const currentVersion = versionMatch[1];

// Parse and increment version
const parts = currentVersion.split('.').map(n => parseInt(n, 10));
if (bumpType === 'major') {
  parts[0] += 1;
  parts[1] = 0;
  parts[2] = 0;
} else if (bumpType === 'minor') {
  parts[1] += 1;
  parts[2] = 0;
} else {
  parts[2] += 1;
}
const newVersion = parts.join('.');

console.log(`Bumping version: ${currentVersion} → ${newVersion}`);

// Update workspace Cargo.toml
const updatedCargo = workspaceCargo.replace(
  /(\[workspace\.package\]\s*\nversion\s*=\s*")[^"]+"/,
  `$1${newVersion}"`
);
writeFileSync(workspaceCargoPath, updatedCargo);
console.log(`  ✓ Cargo.toml [workspace.package]`);

// Update root package.json
const packageJsonPath = join(rootDir, 'package.json');
const packageJson = JSON.parse(readFileSync(packageJsonPath, 'utf8'));
packageJson.version = newVersion;
writeFileSync(packageJsonPath, JSON.stringify(packageJson, null, 2) + '\n');
console.log(`  ✓ package.json`);

// Update frontend/package.json
const frontendPackageJsonPath = join(rootDir, 'frontend', 'package.json');
const frontendPackageJson = JSON.parse(readFileSync(frontendPackageJsonPath, 'utf8'));
frontendPackageJson.version = newVersion;
writeFileSync(frontendPackageJsonPath, JSON.stringify(frontendPackageJson, null, 2) + '\n');
console.log(`  ✓ frontend/package.json`);

// Update iOS Info.plist (if it exists)
const iosPlistPath = join(tauriDir, 'gen', 'apple', 'opca_iOS', 'Info.plist');
try {
  let iosPlist = readFileSync(iosPlistPath, 'utf8');
  iosPlist = iosPlist.replace(
    /(<key>CFBundleShortVersionString<\/key>\s*<string>)[^<]*/,
    `$1${newVersion}`
  );
  iosPlist = iosPlist.replace(
    /(<key>CFBundleVersion<\/key>\s*<string>)[^<]*/,
    `$1${newVersion}`
  );
  if (!iosPlist.endsWith('\n')) iosPlist += '\n';
  writeFileSync(iosPlistPath, iosPlist);
  console.log(`  ✓ crates/opca-tauri/gen/apple/opca_iOS/Info.plist`);
} catch { /* iOS not initialised yet */ }

// Update iOS project.yml (if it exists)
const projectYmlPath = join(tauriDir, 'gen', 'apple', 'project.yml');
try {
  let projectYml = readFileSync(projectYmlPath, 'utf8');
  projectYml = projectYml.replace(
    /CFBundleShortVersionString: .+/,
    `CFBundleShortVersionString: ${newVersion}`
  );
  projectYml = projectYml.replace(
    /CFBundleVersion: .+/,
    `CFBundleVersion: "${newVersion}"`
  );
  writeFileSync(projectYmlPath, projectYml);
  console.log(`  ✓ crates/opca-tauri/gen/apple/project.yml`);
} catch { /* iOS not initialised yet */ }

console.log(`\nVersion bumped to ${newVersion}`);
