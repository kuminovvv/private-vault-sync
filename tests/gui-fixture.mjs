import fs from 'node:fs/promises';
import { join } from 'node:path';
import { createHash,randomBytes } from 'node:crypto';
import {spawnSync} from 'node:child_process';
import {setTimeout as sleep} from 'node:timers/promises';
const root=process.argv[2],exe=process.argv[3];
const base='http://127.0.0.1:18879/v1',env={...process.env,SYNC_DATA:join(root,'data')};
const hash=b=>createHash('sha256').update(b).digest('hex');
const c=spawnSync(exe,['pair'],{env,encoding:'utf8'});
if(c.status!==0)throw Error(c.stderr);
async function req(path,method='GET',token='',body){
 const headers=token?{Authorization:'Bearer '+token}:{};
 if(body!==undefined)headers['Content-Type']=Buffer.isBuffer(body)?'application/octet-stream':'application/json';
 const r=await fetch(base+path,{method,headers,body:body===undefined?undefined:Buffer.isBuffer(body)?body:JSON.stringify(body),signal:AbortSignal.timeout(10000)});
 if(!r.ok)throw Error(path+' HTTP '+r.status);
 const text=await r.text();return text?JSON.parse(text):undefined;
}
for(let i=0;i<50;i++){try{if((await fetch(base+'/health')).ok)break;}catch{}await sleep(100);}
const seed=(await req('/redeem','POST','',{code:c.stdout.trim(),name:'local GUI fixture'})).token;
const pair=await req('/pair','POST',seed,{});
const token=(await req('/redeem','POST','',{code:pair.code,name:'local Obsidian GUI'})).token;
for(const [path,b] of [['from-server.md',Buffer.from('# Local test\nHello from Rust server')],['attachment.bin',randomBytes(1048576+42)]]){
 const chunks=[];
 for(let i=0;i<b.length;i+=1048576){const part=b.subarray(i,i+1048576),id=hash(part);chunks.push(id);await req('/chunks/'+id,'PUT',seed,part);}
 await req('/commit','POST',seed,{path,base_rev:0,size:b.length,hash:hash(b),chunks});
}
const vault=join(root,'PrivateSync-GUI'),p=join(vault,'.obsidian','plugins','private-vault-sync');
await fs.mkdir(p,{recursive:true});
for(const f of ['main.js','manifest.json'])await fs.copyFile(new URL('../plugin/'+f,import.meta.url),join(p,f));
await fs.writeFile(join(p,'data.json'),JSON.stringify({server:'http://127.0.0.1:18879',token,device:'GUI test',base:{},deleteEnabled:false,pendingDeletes:{},tombstones:{}}));
await fs.writeFile(join(vault,'.obsidian','community-plugins.json'),'["private-vault-sync"]');
await fs.writeFile(join(vault,'from-obsidian.md'),'# Actual Obsidian test\nGUI local upload');
await fs.writeFile(join(root,'fixture.json'),JSON.stringify({token:seed}));
console.log('Local test vault created; server seeded with two synthetic files.');
