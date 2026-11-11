// Expand test names portably: older Windows Node does not expand shell globs.
import { readdirSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
const directory = fileURLToPath(new URL('.', import.meta.url));
const tests = readdirSync(directory).filter(name => name.endsWith('.test.mjs')).sort();
if (!tests.length) throw new Error('No unit tests found');
const result = spawnSync(process.execPath, ['--test', ...tests], { cwd: directory, stdio: 'inherit' });
process.exitCode = result.status ?? 1;
