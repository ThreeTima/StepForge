'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const { createCredentialVault, weeklyCheck } = require('../../app/credential-vault');
const { GoogleDrive } = require('../../app/google-drive');
const { makeTmpDir, rmrf } = require('./helpers');

/*
 * A stand-in for Windows: an HKCU registry that reg.exe and the vault's
 * PowerShell scripts work on, with a reversible "DPAPI". Every command is
 * recorded so a test can check what was started.
 */
function fakeWindows() {
  const registry = new Map(); // 'HKCU\\Software\\StepForge\\GoogleDrive' -> Map(name -> value)
  const calls = [];
  const fail = (message) => Object.assign(new Error(message), { code: 1 });
  const psKey = (script) => `HKCU\\${/'HKCU:\\([^']+)'/.exec(script)[1]}`;
  const exec = async (file, args, input) => {
    calls.push({ file, args, input });
    if (file === 'reg.exe') {
      const [verb, key, , name] = args;
      const values = registry.get(key);
      if (verb === 'query') {
        if (!values) throw fail('ERROR: The system was unable to find the specified registry key or value.');
        const lines = [...values].map(([n, v]) => `    ${n}    REG_SZ    ${v}`);
        return `\r\n${key.replace(/^HKCU/, 'HKEY_CURRENT_USER')}\r\n${lines.join('\r\n')}\r\n\r\n`;
      }
      if (verb === 'delete') {
        if (!values?.delete(name)) throw fail('ERROR: The system was unable to find the specified registry key or value.');
        return 'The operation completed successfully.\r\n';
      }
    }
    if (file === 'powershell.exe') {
      const script = args.at(-1);
      const key = psKey(script);
      if (script.includes('::Unprotect(')) {
        const saved = registry.get(key)?.get('SignIn');
        return saved ? `${saved.replace(/^dpapi:/, '')}\r\n` : '';
      }
      if (script.includes('::Protect(')) {
        if (!registry.has(key)) registry.set(key, new Map());
        registry.get(key).set('SignIn', `dpapi:${input}`);
        registry.get(key).set('SignInSha256', /-Name SignInSha256 -Value '([0-9a-f]{64})'/.exec(script)[1]);
        return '';
      }
    }
    throw fail(`unexpected command: ${file} ${args.join(' ')}`);
  };
  const started = (file) => calls.filter((call) => call.file === file);
  const decrypts = () => started('powershell.exe').filter((call) => call.args.at(-1).includes('::Unprotect('));
  const encrypts = () => started('powershell.exe').filter((call) => call.args.at(-1).includes('::Protect('));
  return { registry, calls, exec, started, decrypts, encrypts };
}

const vaultFor = (win, slot = 'google') => createCredentialVault({ platform: 'win32', slot, exec: win.exec });

test('Windows: nothing saved means nothing is decrypted and PowerShell is not started', async () => {
  const win = fakeWindows();
  for (const slot of ['google', 'onedrive', 'dropbox', 'webdav', 'wikijs']) {
    assert.equal(await vaultFor(win, slot).read('client'), null);
  }
  assert.equal(win.started('powershell.exe').length, 0);
  assert.deepEqual(win.started('reg.exe').map((call) => call.args), [
    ['query', 'HKCU\\Software\\StepForge\\GoogleDrive'],
    ['query', 'HKCU\\Software\\StepForge\\Cloud-onedrive'],
    ['query', 'HKCU\\Software\\StepForge\\Cloud-dropbox'],
    ['query', 'HKCU\\Software\\StepForge\\Cloud-webdav'],
    ['query', 'HKCU\\Software\\StepForge\\Cloud-wikijs'],
  ]);
});

test('Windows: a reg.exe that fails or is blocked is treated as nothing saved', async () => {
  const calls = [];
  const exec = async (file, args) => { calls.push(file); throw new Error('ERROR: Registry editing has been disabled by your administrator.'); };
  assert.equal(await createCredentialVault({ platform: 'win32', exec }).read('client'), null);
  assert.deepEqual(calls, ['reg.exe']);
});

test('Windows: a saved sign-in is written once, recovered, and not encrypted again on later launches', async () => {
  const win = fakeWindows();
  const secret = JSON.stringify({ clientId: 'client', refresh_token: 'refresh-secret' });
  await vaultFor(win).write('client', secret);
  assert.equal(win.encrypts().length, 1);
  // The secret goes over stdin, never on the command line.
  assert.ok(!win.calls.some((call) => call.args.join(' ').includes('refresh-secret')));
  assert.ok(!win.calls.some((call) => call.args.join(' ').includes(Buffer.from(secret).toString('base64'))));

  // Next launch: the backup is current, so it is only looked up.
  await vaultFor(win).write('client', secret);
  assert.equal(win.encrypts().length, 1);

  assert.equal(await vaultFor(win).read('client'), secret);
  assert.equal(win.decrypts().length, 1);

  // A new sign-in replaces the backup.
  await vaultFor(win).write('client', JSON.stringify({ clientId: 'client', refresh_token: 'other' }));
  assert.equal(win.encrypts().length, 2);
});

test('Windows: a backup whose check is unchanged is not encrypted again, even if the secret changed', async () => {
  const win = fakeWindows();
  await vaultFor(win, 'onedrive').write('client', '{"refresh_token":"one"}', 'same week');
  await vaultFor(win, 'onedrive').write('client', '{"refresh_token":"two"}', 'same week');
  assert.equal(win.encrypts().length, 1);
  await vaultFor(win, 'onedrive').write('client', '{"refresh_token":"three"}', 'next week');
  assert.equal(win.encrypts().length, 2);
});

test('weeklyCheck changes with the week, not with the time of day', () => {
  const monday = Date.parse('2026-11-16T09:00:00Z');
  assert.equal(weeklyCheck({ a: 1 }, monday), weeklyCheck({ a: 1 }, monday + 60 * 60 * 1000));
  assert.notEqual(weeklyCheck({ a: 1 }, monday), weeklyCheck({ a: 1 }, monday + 7 * 24 * 60 * 60 * 1000));
  assert.notEqual(weeklyCheck({ a: 1 }, monday), weeklyCheck({ a: 2 }, monday));
});

test('Windows: a backup from an earlier version, without a fingerprint, is rewritten once', async () => {
  const win = fakeWindows();
  const secret = JSON.stringify({ clientId: 'client', refresh_token: 'refresh-secret' });
  win.registry.set('HKCU\\Software\\StepForge\\GoogleDrive', new Map([['SignIn', `dpapi:${Buffer.from(secret).toString('base64')}`]]));
  assert.equal(await vaultFor(win).read('client'), secret);
  await vaultFor(win).write('client', secret);
  await vaultFor(win).write('client', secret);
  assert.equal(win.encrypts().length, 1);
  assert.match(win.registry.get('HKCU\\Software\\StepForge\\GoogleDrive').get('SignInSha256'), /^[0-9a-f]{64}$/);
});

test('Windows: clearing removes the saved values with reg.exe and starts no PowerShell', async () => {
  const win = fakeWindows();
  await vaultFor(win, 'wikijs').write('wikijs', '{"baseUrl":"https://wiki.example.com"}');
  const before = win.started('powershell.exe').length;
  await vaultFor(win, 'wikijs').clear('wikijs');
  assert.equal(win.started('powershell.exe').length, before);
  assert.equal(win.registry.get('HKCU\\Software\\StepForge\\Cloud-wikijs').size, 0);
  assert.equal(await vaultFor(win, 'wikijs').read('wikijs'), null);

  // Nothing saved: only the lookup runs.
  const empty = fakeWindows();
  await vaultFor(empty, 'dropbox').clear('dropbox');
  assert.deepEqual(empty.calls.map((call) => call.file), ['reg.exe']);
});

test('Windows: launching without ever signing in to Google Drive starts no PowerShell', async (t) => {
  const directory = makeTmpDir('credential-vault');
  t.after(() => rmrf(directory));
  const key = crypto.randomBytes(32);
  const safeStorage = {
    isEncryptionAvailable: () => true,
    getSelectedStorageBackend: () => 'dpapi',
    encryptString(text) { const iv = crypto.randomBytes(16); const cipher = crypto.createCipheriv('aes-256-cbc', key, iv); return Buffer.concat([iv, cipher.update(text), cipher.final()]); },
    decryptString(bytes) { const cipher = crypto.createDecipheriv('aes-256-cbc', key, bytes.subarray(0, 16)); return Buffer.concat([cipher.update(bytes.subarray(16)), cipher.final()]).toString(); },
  };
  const win = fakeWindows();
  const launch = () => new GoogleDrive({ directory, safeStorage, vault: vaultFor(win), clientId: 'test.apps.googleusercontent.com', clientSecret: 'test-client-secret' });
  const first = launch();
  assert.equal(await first.recover(), false);
  assert.equal(win.started('powershell.exe').length, 0);

  // After signing in, the backup is written once; later launches don't touch DPAPI.
  first.credentials = { clientId: 'test.apps.googleusercontent.com', refresh_token: 'refresh-secret' };
  first.save();
  await new Promise((resolve) => setTimeout(resolve, 20)); // save() backs up in the background
  assert.equal(win.encrypts().length, 1);
  for (let i = 0; i < 3; i += 1) assert.equal(await launch().recover(), false);
  assert.equal(win.started('powershell.exe').length, 1);
});
