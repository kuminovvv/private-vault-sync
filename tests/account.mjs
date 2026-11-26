import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { mkdtemp, rm } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { setTimeout as sleep } from 'node:timers/promises';
import { createRequire } from 'node:module';
import { fileURLToPath } from 'node:url';
const require=createRequire(new URL('../plugin/package.json',import.meta.url));
const {buildSync}=require('esbuild');
const bundle=buildSync({entryPoints:[fileURLToPath(new URL('../plugin/src/account-client.ts',import.meta.url))],bundle:true,write:false,platform:'node',format:'cjs',external:['obsidian']}).outputFiles[0].text;
const moduleStub={exports:{}};
const obsidianStub={async requestUrl(options){const response=await fetch(options.url,{method:options.method??'GET',headers:options.headers,body:options.body});const body=await response.text();return {status:response.status,text:body,get json(){return JSON.parse(body);}};}};
new Function('require','module','exports',bundle)(name=>name==='obsidian'?obsidianStub:require(name),moduleStub,moduleStub.exports);
const {createOwner,signIn}=moduleStub.exports;
const executable=process.argv[2];
assert.ok(executable);
const data=await mkdtemp(join(tmpdir(),'private-sync-account-test-'));
const port=18881;
const base='http://127.0.0.1:'+port+'/v1';
const env={...process.env,SYNC_DATA:data,SYNC_BIND:'127.0.0.1:'+port,SYNC_ENCRYPTED_ONLY:'1'};
let server;
async function start(enabled){
 server=spawn(executable,[],{env:{...env,SYNC_ENABLE_OWNER_SETUP:enabled?'1':'0',SYNC_OWNER_SETUP_BIND:'127.0.0.1:18882'},stdio:'ignore'});
 for(let i=0;i<50;i++){try{if((await fetch(base+'/health')).ok)return;}catch{}await sleep(100);}
 throw Error('Test server failed to start');
}
async function stop(){
 if(server&&server.exitCode===null){const done=new Promise(r=>server.once('exit',r));server.kill();await done;}
}
async function api(path,body,expected,session,admin=false){
 const headers={'X-Private-Sync-Protocol':'e2ee-v1'};
 if(body!==undefined)headers['Content-Type']='application/json';
 if(session)headers.Authorization='Bearer '+session;
 const response=await fetch((admin?'http://127.0.0.1:18882/v1':base)+path,{method:body===undefined?'GET':'POST',headers,body:body===undefined?undefined:JSON.stringify(body)});
 assert.equal(response.status,expected,path);
 if(response.headers.get('content-type')?.includes('application/json'))return response.json();
}
const fixture={username:'test-owner',salt:'a'.repeat(64),auth:'b'.repeat(64),envelope:'c'.repeat(120)};
const credentials={username:'test-owner',password:'synthetic test passphrase only',device:'test desktop'};
try{
 await start(false);
 assert.equal((await api('/account/status',undefined,200)).initialized,false);
 await api('/account/setup',fixture,404);
 await stop();
 await start(true);
 await api('/account/setup',fixture,404);
 await createOwner('http://127.0.0.1:18882',credentials);
 await api('/account/setup',fixture,409,undefined,true);
 assert.equal((await api('/account/status',undefined,200)).initialized,true);
 await api('/account/login',{username:'test-owner',auth:'d'.repeat(64),name:'test device'},401);
 await assert.rejects(()=>signIn(base.slice(0,-3),{...credentials,password:'incorrect password'}),/Неверный логин или пароль/);
 const session=await signIn(base.slice(0,-3),credentials);
 assert.match(session.vaultKey,/^[0-9a-f]{64}$/);
 await api('/index',undefined,401);
 assert.deepEqual(await api('/index',undefined,200,session.sessionId),[]);
 await stop();
 await start(false);
 await api('/account/setup',fixture,404);
 const second=await signIn(base.slice(0,-3),{...credentials,device:'second test device'});
 assert.equal(second.vaultKey,session.vaultKey);
 assert.notEqual(second.sessionId,session.sessionId);
 console.log('PASS: separate admin bootstrap, single owner, wrong password rejected, two clients recover identical encryption key after restart');
}finally{await stop();await rm(data,{recursive:true,force:true});}
