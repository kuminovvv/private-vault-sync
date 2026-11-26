import assert from 'node:assert/strict';
import {createHash,randomBytes} from 'node:crypto';
const base=process.env.SYNC_PILOT_URL;
const code=process.env.SYNC_PILOT_CODE;
if(!base||!base.startsWith('https://')||!code)throw Error('Set SYNC_PILOT_URL (HTTPS) and SYNC_PILOT_CODE.');
const api=base.replace(/\/$/,'')+'/v1';
const h=b=>createHash('sha256').update(b).digest('hex');
const runId='pilot-'+randomBytes(6).toString('hex');
const started=Date.now();
async function req(path,{method='GET',token='',body,expected=200}={}){
 const headers={};if(token)headers.Authorization='Bearer '+token;
 if(body!==undefined)headers['Content-Type']=Buffer.isBuffer(body)?'application/octet-stream':'application/json';
 const r=await fetch(api+path,{method,headers,body:body===undefined?undefined:Buffer.isBuffer(body)?body:JSON.stringify(body),signal:AbortSignal.timeout(90000)});
 assert.equal(r.status,expected,path+' '+method);
 const type=r.headers.get('content-type')||'';
 return type.includes('json')?r.json():Buffer.from(await r.arrayBuffer());
}
await req('/health');
await req('/index',{expected:401});
const a=(await req('/redeem',{method:'POST',body:{code,name:'pilot-a'}})).token;
await req('/redeem',{method:'POST',body:{code,name:'replay'},expected:401});
const pair=(await req('/pair',{method:'POST',token:a,body:{}})).code;
const b=(await req('/redeem',{method:'POST',body:{code:pair,name:'pilot-b'}})).token;
const ws=new WebSocket(api.replace(/^https/,'wss')+'/watch');
const event=expected=>new Promise((resolve,reject)=>{
 const timeout=setTimeout(()=>{ws.removeEventListener('message',listener);reject(Error('Missing WSS event '+expected));},30000);
 function listener(e){if(e.data===expected){clearTimeout(timeout);ws.removeEventListener('message',listener);resolve();}}
 ws.addEventListener('message',listener);
});
try {
 const ready=event('ready');ws.addEventListener('open',()=>ws.send(b),{once:true});await ready;
 console.log('PASS: TLS, one-time enrollment, unauthorized access rejected, WSS authenticated');
 const path=runId+'/attachment.bin';
 const blocks=[randomBytes(1024*1024),randomBytes(128*1024)];
 const chunks=blocks.map(h), all=Buffer.concat(blocks);
 await req('/chunks/'+chunks[0],{method:'PUT',token:a,body:blocks[0],expected:201});
 assert.deepEqual(await req('/missing',{method:'POST',token:a,body:{hashes:chunks}}),[chunks[1]]);
 await req('/chunks/'+chunks[1],{method:'PUT',token:a,body:blocks[1],expected:201});
 const changed=event('changed');
 const meta={path,base_rev:0,hash:h(all),size:all.length,chunks};
 const first=await req('/commit',{method:'POST',token:a,body:meta});assert.equal(first.rev,1);
 await changed;
 const row=(await req('/index',{token:b})).find(f=>f.path===path);
 assert.ok(row);
 const got=Buffer.concat(await Promise.all(row.chunks.map(id=>req('/chunks/'+id,{token:b}))));
 assert.equal(h(got),h(all));assert.deepEqual(got,all);
 console.log('PASS: 1.125 MiB upload, resume negotiation, WSS event and exact download');
 const changedData=Buffer.from('Updated from second device');
 const digest=h(changedData);
 await req('/chunks/'+digest,{method:'PUT',token:b,body:changedData,expected:201});
 const version=await req('/commit',{method:'POST',token:b,body:{path,base_rev:1,hash:digest,size:changedData.length,chunks:[digest]}});assert.equal(version.rev,2);
 assert.equal((await req('/index',{token:a})).find(f=>f.path===path).hash,digest);
 await req('/commit',{method:'POST',token:a,body:{...meta,base_rev:1},expected:409});
 const ds=await req('/devices',{token:a});
 const other=ds.find(d=>d.name==='pilot-b'&&!d.current);
 assert.ok(other);
 await req('/devices/'+other.id,{method:'DELETE',token:a,expected:204});
 await req('/index',{token:b,expected:401});
 console.log('PASS: reverse update, conflict protection, device revocation');
 console.log('Pilot checks passed in '+((Date.now()-started)/1000).toFixed(1)+'s.');
}finally{ws.close();}
