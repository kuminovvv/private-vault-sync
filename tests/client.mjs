import assert from 'node:assert/strict';
import { spawn, spawnSync } from 'node:child_process';
import { randomBytes,createHash } from 'node:crypto';
import { mkdtempSync,readFileSync } from 'node:fs';
import fs from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join,dirname } from 'node:path';
import { setTimeout as sleep } from 'node:timers/promises';
const exe=process.argv[2];
if(!exe)throw Error('Pass server executable');
const root=mkdtempSync(join(tmpdir(),'private-sync-client-'));
const encrypted=process.env.SYNC_TEST_ENCRYPTED==='1';
const env={...process.env,SYNC_DATA:join(root,'server'),SYNC_BIND:'127.0.0.1:18878',SYNC_ENCRYPTED_ONLY:encrypted?'1':'0'};
const code=spawnSync(exe,['pair'],{env,encoding:'utf8'});
assert.equal(code.status,0,code.stderr);
const server=spawn(exe,[],{env,stdio:'ignore'});
const base='http://127.0.0.1:18878';
const digest=b=>createHash('sha256').update(b).digest('hex');
const arr=b=>b.buffer.slice(b.byteOffset,b.byteOffset+b.byteLength);
globalThis.window=globalThis;
class TFile{constructor(path,stat){this.path=path;this.stat=stat;}}
class Plugin{constructor(app){this.app=app;this.manifest={id:'private-vault-sync'};this.saved={};}async saveData(c){this.saved=structuredClone(c);} }
class Empty{}
let failChunk=null,failed=0,networkChunks=[];
const obsidian={
 App:Empty,Modal:Empty,Notice:Empty,Plugin,PluginSettingTab:Empty,Setting:Empty,TFile,Platform:{isMobile:false},normalizePath:x=>x,
 async requestUrl(req){
  if(req.method==='GET'&&req.url.includes('/chunks/')){
   const h=req.url.split('/').at(-1);networkChunks.push(h);
   if(h===failChunk){failed++;throw Error('simulated network disconnect');}
  }
  const r=await fetch(req.url,{method:req.method,headers:req.headers,body:req.body,signal:AbortSignal.timeout(10000)});
  const b=await r.arrayBuffer();return {status:r.status,arrayBuffer:b,text:new TextDecoder().decode(b)};
 }
};
const module={exports:{}};
new Function('require','module','exports',readFileSync(new URL('../plugin/main.js',import.meta.url),'utf8'))(n=>{if(n==='obsidian')return obsidian;throw Error(n)},module,module.exports);
const Client=module.exports.default;
async function vault(name){
 const dir=join(root,name);await fs.mkdir(join(dir,'.obsidian','plugins','private-vault-sync'),{recursive:true});
 const files=new Map();
 const p=x=>join(dir,...x.split('/'));
 const adapter={
  async exists(x){try{await fs.stat(p(x));return true;}catch{return false;}},
  async stat(x){try{const s=await fs.stat(p(x));return {type:s.isDirectory()?'folder':'file',size:s.size,mtime:s.mtimeMs,ctime:s.ctimeMs};}catch(e){if(e.code==='ENOENT')return null;throw e;}},
  async list(x){const entries=await fs.readdir(p(x),{withFileTypes:true});const files=[],folders=[];for(const e of entries){const name=x?x+'/'+e.name:e.name;if(e.isFile())files.push(name);else if(e.isDirectory())folders.push(name);}return {files,folders};},
  mkdir:x=>fs.mkdir(p(x),{recursive:true}),
  readBinary:async x=>arr(await fs.readFile(p(x))),
  writeBinary:async(x,b)=>{if(x.startsWith('.obsidian/'))await fs.writeFile(p(x),Buffer.from(b));else await write(x,Buffer.from(b));},
  async trashLocal(x){await fs.mkdir(join(dir,'.trash'),{recursive:true});await fs.rename(p(x),join(dir,'.trash',x.replaceAll('/','_')));files.delete(x);},
  rmdir:(x,recursive)=>fs.rm(p(x),{recursive,force:true})
 };
 const v={adapter,configDir:'.obsidian',getFiles:()=>[...files.values()],
  getAbstractFileByPath:x=>x.endsWith('.zst')?null:files.get(x)??null,
  async readBinary(f){return arr(await fs.readFile(p(f.path)));},
  async createFolder(x){await fs.mkdir(p(x),{recursive:true});},
  async createBinary(x,b){if(files.has(x))throw Error('already exists');await write(x,Buffer.from(b));},
  async modifyBinary(f,b){await write(f.path,Buffer.from(b));}
 };
 async function write(x,b){await fs.mkdir(dirname(p(x)),{recursive:true});await fs.writeFile(p(x),b);const st=await fs.stat(p(x));files.set(x,new TFile(x,{mtime:st.mtimeMs,size:st.size}));}
 async function remove(x){await fs.rm(p(x));files.delete(x);}
 const app={vault:v,fileManager:{trashFile:async f=>{await fs.mkdir(join(dir,'.trash'),{recursive:true});await fs.rename(p(f.path),join(dir,'.trash',f.path.replaceAll('/','_')));files.delete(f.path);}}};
 const client=new Client(app);client.cfg.server=base;client.cfg.device=name;
 return {client,write,remove,read:x=>fs.readFile(p(x)),exists:x=>files.has(x),dir};
}
async function ready(){for(let i=0;i<50;i++){try{if((await fetch(base+'/v1/health')).ok)return;}catch{}await sleep(100);}throw Error('not ready');}
async function sync(c){await c.sync();assert.equal(c.progress,'Синхронизировано',JSON.stringify(c.errorsByPath));}
try{
 await ready();
 const a=await vault('device-a'),b=await vault('device-b');
 if(encrypted){
   const key=randomBytes(32).toString('hex');a.client.cfg.encryptionKey=key;b.client.cfg.encryptionKey=key;
   assert.equal((await fetch(base+'/v1/index')).status,426);
 }
 const redeem=await a.client.req('POST','/redeem',{code:code.stdout.trim(),name:'a'},false,false);a.client.cfg.token=redeem.token;
 const next=await a.client.pair();b.client.cfg.token=(await b.client.req('POST','/redeem',{code:next.code,name:'b'},false,false)).token;
 if(encrypted){
   const c=a.client.cipher();
   const original=randomBytes(1024*1024+100);const wire=c.encode('test.bin',original);
   assert.deepEqual(Buffer.from(c.decode('test.bin',wire)),original);
   assert.deepEqual(c.encode('test.bin',original),wire);
   assert.deepEqual(Buffer.from(c.decode('empty',c.encode('empty',Buffer.alloc(0)))),Buffer.alloc(0));
   assert.throws(()=>c.decode('other.bin',wire));
   const tampered=wire.slice();tampered[100]^=1;assert.throws(()=>c.decode('test.bin',tampered));
   const changed=original.slice();changed[changed.length-1]^=1;
   const mixed=wire.slice();mixed.set(c.encode('test.bin',changed).subarray(1048576),1048576);assert.throws(()=>c.decode('test.bin',mixed));
   assert.equal(c.unpath(c.path('notes/тест.md')),'notes/тест.md');
   await assert.rejects(()=>a.client.req('POST','/commit',{path:'plaintext.md',base_rev:0,hash:digest(Buffer.alloc(0)),size:0,chunks:[]}),/HTTP 400/);
   console.log('PASS: encrypted block roundtrip, empty files, deterministic retries, tamper/path/mixed-revision rejection');
 }
 const payload=randomBytes(3*1024*1024+137);
 await a.write('notes/big.bin',payload);await a.write('notes/тест.md',Buffer.from('Привет'));
 await a.write('notes/session.jsonl.zst',Buffer.from('synthetic unindexed file'));
 await fs.writeFile(join(a.dir,'.obsidian','private-test.txt'),'must not sync');
 await sync(a.client);
 const remote=(await a.client.remoteIndex()).find(x=>x.path==='notes/big.bin');
 if(encrypted){
   const raw=await a.client.req('GET','/index');assert.ok(raw.every(x=>x.path.startsWith('e2ee-v1/')));
   assert.ok(!JSON.stringify(raw).includes('notes/big.bin'));
   const note=(await a.client.remoteIndex()).find(x=>x.path==='notes/тест.md');
   const stored=Buffer.from(await a.client.req('GET','/chunks/'+note.chunks[0]));
   assert.ok(!stored.includes(Buffer.from('Привет')));
   const key=b.client.cfg.encryptionKey;b.client.cfg.encryptionKey=randomBytes(32).toString('hex');
   await assert.rejects(()=>b.client.remoteIndex(),/Wrong recovery key/);b.client.cfg.encryptionKey=key;
   console.log('PASS: remote filenames and content encrypted; wrong recovery key rejected');
 }
 failChunk=remote.chunks[1];await b.client.sync();
 assert.ok(failed>=4);assert.ok(!b.exists('notes/big.bin'));
 assert.match(b.client.progress,/Ошибки: 1/);
 failChunk=null;networkChunks=[];await sync(b.client);
 assert.ok(!networkChunks.includes(remote.chunks[0]),'downloaded block must be reused');
 assert.deepEqual(await b.read('notes/big.bin'),payload);
 assert.equal((await b.read('notes/тест.md')).toString(),'Привет');
 assert.equal((await b.read('notes/session.jsonl.zst')).toString(),'synthetic unindexed file');
 assert.equal(await b.client.app.vault.adapter.exists('.obsidian/private-test.txt'),false);
 console.log('PASS: bundled plugin, interrupted download, cached chunk reuse, UTF-8 paths');
 await b.write('notes/тест.md',Buffer.from('изменено'));await sync(b.client);await sync(a.client);
 assert.equal((await a.read('notes/тест.md')).toString(),'изменено');
 a.client.cfg.deleteEnabled=true;b.client.cfg.deleteEnabled=true;
 const deletedHash=a.client.cfg.base['notes/тест.md'];a.client.cfg.pendingDeletes['notes/тест.md']=deletedHash;await a.remove('notes/тест.md');await sync(a.client);await sync(b.client);
 assert.ok(!b.exists('notes/тест.md'));assert.equal((await fs.readFile(join(b.dir,'.trash','notes_тест.md'))).toString(),'изменено');
 const versions=await a.client.history('notes/тест.md');assert.ok(versions.length>=2);
 await a.client.restoreVersion(versions[0]);await sync(b.client);
 assert.equal((await b.read('notes/тест.md')).toString(),'изменено');
 console.log('PASS: actual plugin algorithm, edit, deletion to trash, restore');
 await a.write('notes/тест.md',Buffer.from('версия A'));await b.write('notes/тест.md',Buffer.from('версия B'));
 await sync(a.client);await b.client.sync();
 assert.match(b.client.progress,/Конфликты: 1/);assert.equal((await b.read('notes/тест.md')).toString(),'версия B');
 console.log('PASS: concurrent edit preserved as conflict');
 const count=Number(process.env.SYNC_TEST_FILES||'100');
 const size=Number(process.env.SYNC_TEST_MIB||'1')*1024*1024;
 const start=Date.now();
 for(let i=0;i<count;i++)await a.write('load/'+i+'.bin',randomBytes(size));
 await sync(a.client);
 // conflict remains intentionally; resolve local conflict using known remote content for load-test
 await b.write('notes/тест.md',Buffer.from('версия A'));
 await sync(b.client);
 for(let i=0;i<count;i++){assert.equal(digest(await a.read('load/'+i+'.bin')),digest(await b.read('load/'+i+'.bin')));}
 console.log('PASS: '+count+' files / '+(count*size/1048576)+' MiB uploaded and downloaded in '+((Date.now()-start)/1000).toFixed(1)+'s on loopback');
 console.log('All bundled-client integration checks passed.');
}finally{const done=new Promise(resolve=>server.once('exit',resolve));server.kill();await done;await fs.rm(root,{recursive:true,force:true});}
