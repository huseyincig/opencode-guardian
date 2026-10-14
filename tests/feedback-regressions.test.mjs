import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {collectTurnEvidence,extractMutatedFilePaths,VerificationSnapshotStore} from '../dist/evidence.js';
import {sanitizeString,sanitizeToolResult,sanitizeObject} from '../dist/secrets/sanitizer.js';
import {cacheAgentCapability,getCachedAgentCapability,cacheV2SessionPermissions,getCachedV2SessionPermissions,clearAllAgentCapabilities} from '../dist/agent-capability.js';
import Guardian,{extractCurrentTurn} from '../dist/index.js';
import {noCheatRule} from '../dist/rules/no-cheat.js';
import {noSecretsRule} from '../dist/rules/no-secrets.js';
import {noStubsRule} from '../dist/rules/no-stubs.js';
import {noShortcutsRule} from '../dist/rules/no-shortcuts.js';
import {isSourceReviewEvidence} from '../dist/task-contract.js';
import {evaluatePreflight} from '../dist/preflight.js';
import {extractToolCommand} from '../dist/tool-input.js';
import {readGuardianStatus,readGuardianActivity} from '../dist/telemetry.js';
const part=(input,tool='apply_patch')=>({type:'tool',tool,state:{status:'completed',input,metadata:{exitCode:0},output:'ok'}});
const msg=(role,parts,id='m')=>({info:{id,role},parts});
const patch=(file,before,after)=>`--- a/${file}\n+++ b/${file}\n@@ -1 +1 @@\n-${before}\n+${after}\n`;
const first=patch('src/first.js','let x=1;','let x=2;');
const context=patchText=>({sessionID:'feedback',directory:process.cwd(),messages:[],currentTurn:[msg('assistant',[part({patchText})])],isSubagent:false,ruleConfig:{blockStructuralTestChanges:true}});
function tmp(t){const p=fs.mkdtempSync(path.join(os.tmpdir(),'guardian-feedback-'));t.after(()=>fs.rmSync(p,{recursive:true,force:true}));return p;}
test('F01 user and system tool parts never create verification or mutation evidence',()=>{
 for(const role of ['user','system']){
  const ev=collectTurnEvidence([msg(role,[part({command:'npm test'},'bash'),part({patchText:first})])]);
  assert.deepEqual(ev.records,[]);assert.equal(ev.mutatedFiles.size,0);
 }
 assert.equal(collectTurnEvidence([msg('assistant',[part({command:'npm test'},'bash')])]).successfulVerifications.length,1);
});
test('F02 every updated and deleted patch file contributes mutation evidence',()=>{
 const patchText=first+patch('src/second.js','let y=1;','let y=2;')+'--- a/obsolete.js\n+++ /dev/null\n@@ -1 +0,0 @@\n-old\n';
 const p=part({patchText});assert.deepEqual(extractMutatedFilePaths(p),['src/first.js','src/second.js','obsolete.js']);
 assert.deepEqual(collectTurnEvidence([msg('assistant',[p])]).fileMutations.map(r=>r.filePath),['src/first.js','src/second.js','obsolete.js']);
});
test('F02 live verification snapshots include every patch file',t=>{
 const directory=tmp(t);fs.mkdirSync(path.join(directory,'src'));for(const f of ['first','second'])fs.writeFileSync(path.join(directory,'src',f+'.js'),'content');
 const store=new VerificationSnapshotStore();store.observe('s','p','apply_patch',{patchText:first+patch('src/second.js','a','b')},'ok',{},directory);
 store.observe('s','test','bash',{command:'npm test'},'passed',{exitCode:0},directory);
 assert.deepEqual(store.snapshots('s').get('test').files,['src/first.js','src/second.js']);
});
test('F03 Error.name is sanitized in direct and nested results',()=>{
 const secret='feedbackCanaryErrorName7654321';const options={includeRuntimeEnv:false,customSecretValues:[secret]};const e=new Error('benign');e.name=secret;
 assert.equal(sanitizeToolResult(e,options).name,'[REDACTED]');assert.equal(sanitizeObject({error:e},options).sanitized.error.name,'[REDACTED]');
});
for(const key of ['api_key','access_token','auth_token'])test(`F04 URL ${key} credential is contextually redacted`,()=>{
 const secret='feedbackUnknownCredential7654321';const input=`https://example.test/path?ok=1&${key}=${secret}#part`;
 const output=sanitizeString(input,{includeRuntimeEnv:false}).sanitized;assert.equal(output.includes(secret),false);assert.match(output,/ok=1/);assert.match(output,/#part$/);
});
for(const key of ['Authorization','Proxy-Authorization','Cookie','Set-Cookie'])test(`F05 ${key} header values are redacted`,()=>{
 const secret='feedbackHeaderCredential7654321';assert.equal(sanitizeString(`${key}: Basic ${secret}`,{includeRuntimeEnv:false}).sanitized.includes(secret),false);
 assert.equal(JSON.stringify(sanitizeObject({[key]:secret},{includeRuntimeEnv:false}).sanitized).includes(secret),false);
});
test('F06 cache boundaries copy profiles and permission rules',()=>{
 clearAllAgentCapabilities();const profile={capability:'read-only',evidence:{reasons:['original'],mutatingTools:[]}};cacheAgentCapability('s',profile);profile.capability='write-allowed';
 assert.equal(getCachedAgentCapability('s').capability,'read-only');const read=getCachedAgentCapability('s');read.capability='write-allowed';read.evidence.reasons.push('forged');assert.deepEqual(getCachedAgentCapability('s').evidence.reasons,['original']);
 cacheV2SessionPermissions('p',[{action:'edit',effect:'deny'}]);getCachedV2SessionPermissions('p')[0].effect='allow';assert.equal(getCachedV2SessionPermissions('p')[0].effect,'deny');clearAllAgentCapabilities();
});
test('F07 mixed real and synthetic user parts retain the latest human turn',()=>{
 const messages=[msg('user',[{type:'text',text:'Earlier instruction.'}],'old'),msg('user',[{type:'text',text:'Run tests now.'},{type:'text',text:'synthetic notice',synthetic:true}],'new')];
 assert.equal(extractCurrentTurn(messages).turnKey,'new');
 messages[1].parts[1].text='[opencode-guardian remediation]\nFollowup';assert.equal(extractCurrentTurn(messages).isRemediationResponse,false);
});
for(const [name,second,pattern] of [
 ['assertion',patch('tests/example.test.js','assert.strictEqual(result, 42);','assert.ok(result);'),'assertion weakened'],
 ['CI',patch('.github/workflows/ci.yml','      - run: npm test','      - run: echo done'),'CI test step removed'],
 ['deletion','--- a/tests/example.test.js\n+++ /dev/null\n@@ -1 +0,0 @@\n-assert.strictEqual(result, 42);\n','test file deleted'],
])test(`F11/F12 later patch ${name} is detected with its own path`,async()=>{
 const result=await noCheatRule.inspect(context(first+second));const finding=result.findings.find(f=>f.pattern===pattern);assert.ok(finding);assert.notEqual(finding.filePath,'src/first.js');assert.equal(result.decision,'block');
});
test('F13 secret in second patch file is attributed to the second path',async()=>{
 const result=await noSecretsRule.inspect(context(first+patch('src/second.js','a',`const token='sk-${'a'.repeat(40)}';`)));assert.equal(result.findings[0]?.filePath,'src/second.js');
});
test('F15 insecure audit-log modes are excluded from counters as well as activity',t=>{
 const directory=tmp(t);fs.mkdirSync(path.join(directory,'.opencode'));const file=path.join(directory,'.opencode','guardian-events.jsonl');fs.writeFileSync(file,JSON.stringify({kind:'preflight-blocked',at:'2026-10-14T12:00:00.000Z'})+'\n');fs.chmodSync(file,0o644);
 if(process.platform!=='win32'){assert.equal(readGuardianStatus(directory).blocked,0);assert.deepEqual(readGuardianActivity(directory),[]);}
 fs.chmodSync(file,0o600);assert.equal(readGuardianStatus(directory).blocked,1);
});
for(const output of ['ENOENT: no such file or directory','Not found','Permission denied'])test(`F16 read failure ${output} is not source review`,()=>{
 assert.equal(isSourceReviewEvidence({status:'success',kind:'generic',toolName:'read_file',output,sequence:1,signature:'s'}),false);
});
test('F17 POSIX shell positional argv is not executed as script source',()=>{
 assert.equal(evaluatePreflight('process_start',{executable:'bash',args:['-c','true','unused-argv0','; rm -rf /']}),undefined);
 assert.equal(evaluatePreflight('process_start',{executable:'bash',args:['-c','rm -rf /']}),'destructive-command');
});
test('F18 non-shell argv metacharacters remain literal',()=>{
 assert.equal(evaluatePreflight('process_start',{executable:'printf',args:['%s','safe && rm -rf /']}),undefined);
 assert.equal(collectTurnEvidence([msg('assistant',[part({executable:'printf',args:['%s','safe && npm test']},'process_start')])]).records.some(r=>r.kind==='test'),false);
 assert.equal(evaluatePreflight('process_start',{executable:'rm',args:['-rf','/']}),'destructive-command');
 assert.match(extractToolCommand({executable:'printf',args:['a; b']}),/'a; b'/);
});
test('F20 second-patch TODO and stub findings use the actual file',async()=>{
 const ctx=context(first+patch('src/second.js','let y=1;','// TODO: implement handler'));
 for(const rule of [noStubsRule,noShortcutsRule]){const result=await rule.inspect(ctx);assert.equal(result.findings[0]?.filePath,'src/second.js');}
});
test('F14 repeated idle bursts are coalesced and remain cancellable',async t=>{
 const directory=tmp(t);fs.writeFileSync(path.join(directory,'opencode-guardian.json'),JSON.stringify({enabled:true,secrets:{enabled:false},updateNotice:{enabled:false}}));
 let calls=0,done;const drained=new Promise(r=>{done=r;});
 const cleanup=await Guardian.setup({location:{directory},event:{subscribe({signal}){return(async function*(){for(let i=0;i<251;i++)yield{type:'session.idle',data:{sessionID:'same'}};done();await new Promise(r=>signal.aborted?r():signal.addEventListener('abort',r,{once:true}));})();}},session:{async context(){calls++;return[];},async synthetic(){}}});
 try{await drained;await new Promise(r=>setTimeout(r,40));assert.ok(calls>0&&calls<=2,`burst caused ${calls} inspections`);}finally{await cleanup();}
});

test('file patch boundaries preserve native add/update/delete paths',async()=>{
 const patchText='*** Begin Patch\n*** Update File: src/first.js\n@@\n-a\n+b\n*** Add File: tests/new.test.js\n+test.skip("case",()=>{});\n*** Delete File: tests/old.test.js\n*** End Patch';
 assert.deepEqual(extractMutatedFilePaths(part({patchText})),['src/first.js','tests/new.test.js','tests/old.test.js']);
 const result=await noCheatRule.inspect(context(patchText));assert.ok(result.findings.some(f=>f.filePath==='tests/old.test.js'&&f.pattern==='test file deleted'));
});

test('idle queue does not starve a continuous burst and cancels pending work',async()=>{
 const {createIdleQueue}=await import('../dist/idle-queue.js');const controller=new AbortController();const queue=createIdleQueue(controller.signal,()=>assert.fail('unexpected queue error'));let calls=0;
 for(let i=0;i<8;i++){queue.enqueue('s',async()=>{calls++;});await new Promise(r=>setTimeout(r,5));}
 assert.ok(calls>0,'continuous notifications must still inspect');
 const before=calls;queue.enqueue('cancelled',async()=>{calls++;});queue.forget('cancelled');controller.abort();await new Promise(r=>setTimeout(r,20));assert.equal(calls,before);
});

test('idle queue serializes same-session work and coalesces one follow-up',async()=>{
 const {createIdleQueue}=await import('../dist/idle-queue.js');const controller=new AbortController();const queue=createIdleQueue(controller.signal,()=>assert.fail('unexpected queue error'));let release,started;const entered=new Promise(r=>{started=r;});const held=new Promise(r=>{release=r;});let calls=0;
 queue.enqueue('s',async()=>{calls++;started();await held;});await entered;
 for(let i=0;i<250;i++)queue.enqueue('s',async()=>{calls++;});assert.equal(calls,1);release();await new Promise(r=>setTimeout(r,30));assert.equal(calls,2);controller.abort();
});

test('unified hunk content cannot forge a new file boundary',async()=>{
 const patchText='--- a/tests/example.test.js\n+++ b/tests/example.test.js\n@@ -1,3 +1,4 @@\n const marker = `\n--- a/src/decoy.js\n+++ b/src/decoy.js\n `;\n+test.skip("case", () => {});\n';
 assert.deepEqual(extractMutatedFilePaths(part({patchText})),['tests/example.test.js']);
 const result=await noCheatRule.inspect(context(patchText));assert.ok(result.findings.some(f=>f.filePath==='tests/example.test.js'));
});

test('native move tracks old and new paths and inspects the new test target',async()=>{
 const patchText='*** Begin Patch\n*** Update File: src/old.js\n*** Move to: tests/new.test.js\n@@\n-a\n+test.skip("case", () => {});\n*** End Patch';
 assert.deepEqual(extractMutatedFilePaths(part({patchText})),['src/old.js','tests/new.test.js']);
 const result=await noCheatRule.inspect(context(patchText));assert.ok(result.findings.some(f=>f.filePath==='tests/new.test.js'));
});
