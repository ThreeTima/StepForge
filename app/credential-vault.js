'use strict';

const crypto = require('node:crypto');
const { execFile } = require('node:child_process');

/*
 * A second home for the Google sign-in, bound to the operating-system user
 * rather than to this installation. Electron's safeStorage key lives in the
 * app profile (Windows) or is looked up once at launch (Linux keyring), so a
 * reinstall, update or early launch can leave the primary file unreadable.
 * Secrets travel over stdin, never command-line arguments.
 *
 * On Windows, decrypting or encrypting with DPAPI from PowerShell looks like
 * credential theft to endpoint security (Defender for Endpoint reports
 * "Suspicious DPAPI Activity"), so it only happens when there is something
 * to do: a saved backup to recover, or a sign-in that isn't backed up yet.
 * Checking for those reads the registry with reg.exe and decrypts nothing.
 */

const SERVICE = 'stepforge-google-drive';
const ENTROPY = 'StepForge Google Drive';
// Each cloud service, and Wiki.js, has its own slot. Google keeps the
// original names so existing backups are still found.
const LABELS = { google: 'Google Drive', onedrive: 'OneDrive', dropbox: 'Dropbox', webdav: 'Nextcloud', wikijs: 'Wiki.js' };
const WEEK_MS = 7 * 24 * 60 * 60 * 1000;

/*
 * What decides whether a backup needs writing again, for a sign-in with a
 * part that changes all the time (a refresh token replaced on every refresh,
 * a session renewed every half hour): the parts that don't change, plus the
 * current week. The backup is then rewritten at most once a week instead of
 * every time that part changes.
 */
function weeklyCheck(fields, now = Date.now()) {
  return JSON.stringify({ ...fields, week: Math.floor(now / WEEK_MS) });
}

function run(file, args, input, timeout = 15000) {
  return new Promise((resolve, reject) => {
    const child = execFile(file, args, { timeout, windowsHide: true, maxBuffer: 1024 * 1024 }, (err, stdout) => {
      if (err) reject(err); else resolve(stdout);
    });
    // A missing tool fails in the callback; ignore the resulting stdin EPIPE.
    child.stdin.on('error', () => {});
    child.stdin.end(input);
  });
}

// GNOME Keyring / KWallet through the Secret Service CLI (libsecret-tools).
function secretServiceVault(slot, exec) {
  const service = slot === 'google' ? SERVICE : `stepforge-${slot}`;
  const attrs = (clientId) => ['service', service, 'client', clientId];
  return {
    async read(clientId) {
      const out = await exec('secret-tool', ['lookup', ...attrs(clientId)], '');
      return out.trim() || null;
    },
    async write(clientId, secret) {
      await exec('secret-tool', ['store', `--label=StepForge ${LABELS[slot] || slot} sign-in`, ...attrs(clientId)], secret);
    },
    async clear(clientId) {
      await exec('secret-tool', ['clear', ...attrs(clientId)], '').catch(() => {});
    },
  };
}

// DPAPI with the CurrentUser scope, kept in the per-user registry. Only this
// Windows account can decrypt it, and uninstallers leave it in place.
// SignInSha256 is a fingerprint of the saved sign-in (or of the `check` the
// caller passes for it), so a backup that is still current isn't encrypted
// again.
function dpapiVault(slot, exec) {
  const subkey = slot === 'google' ? 'Software\\StepForge\\GoogleDrive' : `Software\\StepForge\\Cloud-${slot}`;
  const key = `'HKCU:\\${subkey}'`;
  const regKey = `HKCU\\${subkey}`;
  const entropy = `[Text.Encoding]::UTF8.GetBytes('${ENTROPY}')`;
  const powershell = (lines, input = '') => exec('powershell.exe', ['-NoProfile', '-NonInteractive', '-Command',
    ['$ErrorActionPreference = "Stop"', 'Add-Type -AssemblyName System.Security', ...lines].join('; ')], input);
  const fingerprint = (secret) => crypto.createHash('sha256').update(`${ENTROPY}\0${slot}\0${secret}`).digest('hex');
  // The slot's saved values, read without decrypting anything. A missing key
  // (the service was never used) or a failed lookup reads as nothing saved.
  const saved = async () => {
    let out;
    try { out = await exec('reg.exe', ['query', regKey], ''); } catch { return {}; }
    return Object.fromEntries([...String(out).matchAll(/^\s+(SignIn|SignInSha256)\s+REG_SZ\s+(\S+)\s*$/gm)]
      .map(([, name, value]) => [name, value]));
  };
  return {
    async read() {
      if (!(await saved()).SignIn) return null;
      const out = await powershell([
        `$v = (Get-ItemProperty -Path ${key} -Name SignIn -ErrorAction SilentlyContinue).SignIn`,
        `if ($v) { [Convert]::ToBase64String([Security.Cryptography.ProtectedData]::Unprotect([Convert]::FromBase64String($v), ${entropy}, 'CurrentUser')) }`,
      ]);
      return out.trim() ? Buffer.from(out.trim(), 'base64').toString('utf8') : null;
    },
    async write(clientId, secret, check = secret) {
      const print = fingerprint(check);
      const current = await saved();
      if (current.SignIn && current.SignInSha256 === print) return;
      await powershell([
        '$d = [Convert]::FromBase64String([Console]::In.ReadToEnd().Trim())',
        `$p = [Convert]::ToBase64String([Security.Cryptography.ProtectedData]::Protect($d, ${entropy}, 'CurrentUser'))`,
        `if (-not (Test-Path ${key})) { New-Item -Path ${key} -Force | Out-Null }`,
        `Set-ItemProperty -Path ${key} -Name SignIn -Value $p`,
        `Set-ItemProperty -Path ${key} -Name SignInSha256 -Value '${print}'`,
      ], Buffer.from(secret, 'utf8').toString('base64'));
    },
    async clear() {
      for (const name of Object.keys(await saved())) {
        await exec('reg.exe', ['delete', regKey, '/v', name, '/f'], '').catch(() => {});
      }
    },
  };
}

// `exec` runs a command (file, args, stdin) and resolves its stdout; tests
// replace it.
function createCredentialVault({ platform = process.platform, slot = 'google', exec = run } = {}) {
  if (!/^[a-z]+$/.test(slot)) throw new Error('Invalid credential slot.');
  if (platform === 'linux') return secretServiceVault(slot, exec);
  if (platform === 'win32') return dpapiVault(slot, exec);
  return null;
}

module.exports = { createCredentialVault, weeklyCheck };
