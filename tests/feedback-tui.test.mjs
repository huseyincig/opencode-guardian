import test from 'node:test';
import assert from 'node:assert/strict';
import {spawnSync} from 'node:child_process';
import {fileURLToPath} from 'node:url';
const probe=spawnSync(process.execPath,['--experimental-vm-modules',fileURLToPath(new URL('./helpers/feedback-tui-probe.mjs',import.meta.url))],{encoding:'utf8',timeout:10000});
assert.equal(probe.status,0,probe.stderr);
const rows=probe.stdout.trim().split('\n').map(line=>JSON.parse(line));
for(const id of [9,19,10,21])test(`F${id} TUI lifecycle/config regression`,()=>{
 assert.equal(rows.find(row=>row.id===id)?.status,'NOT_REPRODUCED',probe.stdout);
});
