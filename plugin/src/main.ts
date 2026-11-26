import { App, Modal, Notice, Platform, Plugin, PluginSettingTab, Setting, TFile, requestUrl, normalizePath } from "obsidian";
import { sha256 } from "@noble/hashes/sha256";
import { bytesToHex } from "@noble/hashes/utils";
import * as QRCode from "qrcode";

const CHUNK = 1024 * 1024;
const MAX = 512 * CHUNK;
const digest = (data: Uint8Array) => bytesToHex(sha256(data));
type RemoteFile = { path: string; rev: number; hash: string; size: number; chunks: string[]; deleted?: boolean };
type Config = { server: string; token: string; base: Record<string, string>; device: string; deleteEnabled: boolean; pendingDeletes: Record<string,string>; tombstones: Record<string,number> };
const defaults: Config = {server:"",token:"",base:{},device:"Obsidian",deleteEnabled:false,pendingDeletes:{},tombstones:{}};
const valid = (path: string) => path.length>0 && path.length<=4096 && path.split("/").every(x=>x && x!=="." && x!==".." && !x.endsWith(".") && !x.endsWith(" ") && !/[\\:*?"<>|\x00-\x1f]/.test(x) && ![".obsidian",".trash",".git"].includes(x.toLowerCase()));
const delay = (ms:number)=>new Promise<void>(resolve=>window.setTimeout(resolve,ms));
class HttpError extends Error { constructor(public status:number){super("HTTP "+status)} }
export default class PrivateSync extends Plugin {
  cfg:Config={...defaults,base:Object.create(null),pendingDeletes:Object.create(null),tombstones:Object.create(null)};
  running=false;
  pending=false;
  stopped=false;
  status!:HTMLElement;
  progress="";
  saving:Promise<void>=Promise.resolve();
  remoteTrash=new Set<string>();
  allowBatchDelete=false;
  localHashes=new Map<string,{mtime:number,size:number,hash:string}>();
  fullCheckAt=0;
  socket:WebSocket|null=null;
  reconnectTimer=0;
  reconnectAttempts=0;
  realtime=false;
  startWatch(){
    if(this.stopped||!this.cfg.token||this.socket||typeof WebSocket==="undefined")return;
    let ws:WebSocket;
    try{ws=new WebSocket(this.endpoint().replace(/^http/,"ws")+"/v1/watch");}catch{this.scheduleWatch();return;}
    this.socket=ws;
    const deadline=window.setTimeout(()=>{if(!this.realtime)ws.close();},8000);
    ws.onopen=()=>{if(this.socket===ws)ws.send(this.cfg.token);};
    ws.onmessage=e=>{
      if(this.socket!==ws)return;
      if(e.data==="ready"){window.clearTimeout(deadline);this.realtime=true;this.reconnectAttempts=0;void this.sync();}
      else if(e.data==="changed"){void this.sync();}
    };
    ws.onerror=()=>{ws.close();};
    ws.onclose=()=>{window.clearTimeout(deadline);if(this.socket!==ws)return;this.socket=null;this.realtime=false;this.scheduleWatch();};
  }
  scheduleWatch(){
    if(this.stopped||!this.cfg.token||this.reconnectTimer)return;
    this.reconnectTimer=window.setTimeout(()=>{this.reconnectTimer=0;this.startWatch();},Math.min(60000,1000*2**Math.min(6,this.reconnectAttempts++)));
  }
  stopWatch(){
    window.clearTimeout(this.reconnectTimer);this.reconnectTimer=0;
    const old=this.socket;this.socket=null;this.realtime=false;old?.close();
  }
  errorsByPath:Record<string,string>=Object.create(null);
  conflictsByPath:string[]=[];
  transferred=0;
  syncStarted=0;
  completed=0;
  total=0;
  renderProgress(){
    const seconds=Math.max(1,(Date.now()-this.syncStarted)/1000);
    const mb=this.transferred/1048576;
    this.render(this.completed+"/"+this.total+" · "+mb.toFixed(1)+" МиБ · "+(mb/seconds).toFixed(2)+" МиБ/с");
  }
  async onload(){
    this.cfg={...defaults,...await this.loadData()};
    this.cfg.base=Object.assign(Object.create(null),this.cfg.base);
    this.cfg.pendingDeletes=Object.assign(Object.create(null),this.cfg.pendingDeletes);
    this.cfg.tombstones=Object.assign(Object.create(null),this.cfg.tombstones);
    this.status=this.addStatusBarItem(); this.render("Не подключено");
    this.addSettingTab(new SyncSettings(this.app,this));
    this.addCommand({id:"sync-now",name:"Синхронизировать сейчас",callback:()=>void this.sync()});
    this.registerInterval(window.setInterval(()=>void this.sync(),30000));
    let timer=0;
    const changed=()=>{window.clearTimeout(timer); timer=window.setTimeout(()=>void this.sync(),1200);};
    this.register(()=>window.clearTimeout(timer));
    this.registerEvent(this.app.vault.on("delete",f=>{
      this.localHashes.delete(f.path);if(!(f instanceof TFile)||this.remoteTrash.has(f.path)||!this.cfg.deleteEnabled||!this.cfg.base[f.path])return;
      this.cfg.pendingDeletes[f.path]=this.cfg.base[f.path];void this.save();changed();
    }));
    this.registerEvent(this.app.vault.on("modify",f=>{this.localHashes.delete(f.path);changed();}));
    this.registerEvent(this.app.vault.on("create",f=>{this.localHashes.delete(f.path);changed();}));
    this.registerEvent(this.app.vault.on("rename",(f,old)=>{this.localHashes.delete(old);this.localHashes.delete(f.path);changed();}));
    this.registerObsidianProtocolHandler("private-vault-sync",params=>{
      if(this.cfg.token){new Notice("Хранилище уже подключено");return;}
      new PairConnectModal(this.app,this,params.server??"",params.code??"").open();
    });
    this.app.workspace.onLayoutReady(()=>{this.startWatch();void this.sync();});
  }
  onunload(){this.stopped=true;this.stopWatch();}
  render(s:string){this.progress=s; this.status?.setText("Private Sync: "+s);}
  async save(){
    const snapshot=JSON.parse(JSON.stringify(this.cfg));
    const next=this.saving.catch(()=>{}).then(()=>this.saveData(snapshot));
    this.saving=next;await next;
  }
  endpoint(){const u=new URL(this.cfg.server.trim()); if(u.username||u.password||u.search||u.hash)throw new Error("Некорректный адрес сервера"); if(u.protocol!=="https:"&&!(u.protocol==="http:"&&["localhost","127.0.0.1"].includes(u.hostname)))throw new Error("Требуется HTTPS");return u.toString().replace(/\/+$/,"");}
  async req(method:string,path:string,body?:unknown,binary=false,auth=true):Promise<any>{
    const headers:Record<string,string>={};
    if(auth)headers.Authorization="Bearer "+this.cfg.token;
    let payload:string|ArrayBuffer|undefined;
    if(body!==undefined){if(binary){headers["Content-Type"]="application/octet-stream";payload=body as ArrayBuffer;}else{headers["Content-Type"]="application/json";payload=JSON.stringify(body);}}
    for(let i=0;i<4;i++){
      if(this.stopped)throw new Error("Плагин остановлен");
      try{
        let deadline=0;
        const request=requestUrl({url:this.endpoint()+"/v1"+path,method,headers,body:payload,throw:false});
        const timeout=new Promise<never>((_,reject)=>{deadline=window.setTimeout(()=>reject(new Error("Превышено время ожидания запроса")),path.startsWith("/chunks/")?60000:30000);});
        const r=await Promise.race([request,timeout]).finally(()=>window.clearTimeout(deadline));
        if(r.status<200||r.status>=300)throw new HttpError(r.status);
        return method==="GET"&&path.startsWith("/chunks/")?r.arrayBuffer:r.text?JSON.parse(r.text):undefined;
      }catch(e){if(i===3||path==="/redeem"||path==="/pair"||(e instanceof HttpError && e.status<500 && e.status!==429))throw e;await delay(500*2**i);}
    }
  }
  async connect(server:string,code:string,device:string){
    if(this.running)throw new Error("Синхронизация активна");
    this.cfg.server=server;this.cfg.device=device;
    const r=await this.req("POST","/redeem",{code:code.trim(),name:device},false,false);
    this.cfg.token=r.token;this.cfg.base=Object.create(null);this.cfg.pendingDeletes=Object.create(null);this.cfg.tombstones=Object.create(null);await this.save();this.startWatch();void this.sync();
  }
  async pair(){return await this.req("POST","/pair",{});}
  async devices():Promise<{id:number,name:string,created:number,current:boolean}[]>{return this.req("GET","/devices");}
  async revoke(id:number){await this.req("DELETE","/devices/"+id);}
  async ensureFolder(path:string){
    const a=this.app.vault.adapter;
    if(await a.exists(path))return;
    try{await a.mkdir(path);}catch(e){if(!await a.exists(path))throw e;}
  }
  cachePath(r:RemoteFile){return this.app.vault.configDir+"/plugins/"+this.manifest.id+"/chunks/"+digest(new TextEncoder().encode(r.path))+"-"+r.hash;}
  async fetchFile(r:RemoteFile):Promise<Uint8Array>{
    if(!valid(r.path)||!/^[0-9a-f]{64}$/.test(r.hash)||r.size>MAX||r.size<0||!Number.isSafeInteger(r.size)||r.chunks.length!==Math.ceil(r.size/CHUNK))throw new Error("Некорректный файл сервера");
    const a=this.app.vault.adapter,root=this.app.vault.configDir+"/plugins/"+this.manifest.id+"/chunks",dir=this.cachePath(r);
    await this.ensureFolder(root);await this.ensureFolder(dir);
    const data=new Uint8Array(r.size);let offset=0;
    for(let i=0;i<r.chunks.length;i++){
      if(this.stopped)throw new Error("Плагин остановлен");
      const id=r.chunks[i];if(!/^[0-9a-f]{64}$/.test(id))throw new Error("Некорректный хеш");
      const path=dir+"/"+i+"-"+id,expected=Math.min(CHUNK,r.size-offset);
      let b:Uint8Array|undefined;
      if(await a.exists(path)){try{const cached=new Uint8Array(await a.readBinary(path));if(cached.length===expected&&digest(cached)===id)b=cached;}catch{}}
      if(!b){
        b=new Uint8Array(await this.req("GET","/chunks/"+id));
        if(digest(b)!==id||b.length!==expected)throw new Error("Ошибка целостности блока");
        await a.writeBinary(path,b.buffer as ArrayBuffer);
        this.transferred+=b.length;this.renderProgress();
      }
      data.set(b,offset);offset+=b.length;
    }
    if(offset!==r.size||digest(data)!==r.hash)throw new Error("Ошибка целостности файла");
    return data;
  }
  async clearCache(r:RemoteFile){try{await this.app.vault.adapter.rmdir(this.cachePath(r),true);}catch{}}
  async markDeleted(path:string,rev:number){
    delete this.cfg.base[path];delete this.cfg.pendingDeletes[path];this.cfg.tombstones[path]=rev;
  }
  async deleteRemote(path:string,r:RemoteFile){
    if(await this.local(path))throw new Error("Файл появился снова");
    const result:RemoteFile=await this.req("POST","/delete",{path,base_rev:r.rev});
    await this.markDeleted(path,result.rev);
  }
  async trashLocal(r:RemoteFile,expected:string){
    const current=await this.local(r.path,true);
    if(current?.hash!==expected)throw new Error("Файл изменён перед удалением");
    const file=this.app.vault.getAbstractFileByPath(r.path);
    if(!(file instanceof TFile))throw new Error("Файл не найден");
    this.remoteTrash.add(r.path);
    try{await this.app.fileManager.trashFile(file);await this.markDeleted(r.path,r.rev);}
    finally{this.remoteTrash.delete(r.path);}
  }
  async restoreVersion(r:RemoteFile){
    if(this.running)throw new Error("Синхронизация активна");
    this.running=true;
    try{
      const latest:RemoteFile[]=await this.req("GET","/index");
      const current=latest.find(f=>f.path===r.path);
      if(!current)throw new Error("Файл не найден на сервере");
      const local=await this.local(r.path,true);
      if(local&&local.hash!==current.hash)throw new Error("Сначала сохраните локальные изменения");
      await this.fetchFile(r);
      await this.req("POST","/commit",{path:r.path,base_rev:current.rev,hash:r.hash,size:r.size,chunks:r.chunks});
      await this.pull(r,local?.hash??null);
      await this.clearCache(r);await this.save();
    }finally{this.running=false;}
  }
  async local(path:string,force=false):Promise<{data?:Uint8Array;hash:string}|null>{
    const f=this.app.vault.getAbstractFileByPath(path);
    if(!(f instanceof TFile)){this.localHashes.delete(path);return null;}
    if(f.stat.size>MAX)throw new Error("Файл больше 512 МиБ");
    const mtime=f.stat.mtime,size=f.stat.size,c=this.localHashes.get(path);
    if(!force&&c&&c.mtime===mtime&&c.size===size)return {hash:c.hash};
    const data=new Uint8Array(await this.app.vault.readBinary(f)),hash=digest(data);
    if(f.stat.mtime!==mtime||f.stat.size!==size)throw new Error("Файл изменён при чтении");
    this.localHashes.set(path,{mtime,size,hash});
    return {data,hash};
  }
  async push(path:string,local:{data?:Uint8Array;hash:string},remote?:RemoteFile){
    const data=local.data??(await this.local(path,true))?.data;
    if(!data||digest(data)!==local.hash)throw new Error("Файл изменён перед отправкой");
    const chunks:string[]=[],parts:Uint8Array[]=[];
    for(let i=0;i<data.length;i+=CHUNK){const b=data.slice(i,i+CHUNK);parts.push(b);chunks.push(digest(b));}
    const missing=new Set<string>(await this.req("POST","/missing",{hashes:chunks}));
    for(let i=0;i<chunks.length;i++){if(missing.has(chunks[i])){await this.req("PUT","/chunks/"+chunks[i],parts[i].buffer,true);missing.delete(chunks[i]);this.transferred+=parts[i].length;this.renderProgress();}}
    await this.req("POST","/commit",{path,base_rev:remote?.rev??0,hash:local.hash,size:data.length,chunks});
    this.cfg.base[path]=local.hash;delete this.cfg.tombstones[path];delete this.cfg.pendingDeletes[path];
  }
  async pull(r:RemoteFile,expected:string|null){
    const data=await this.fetchFile(r);
    const current=await this.local(r.path,true);if((current?.hash??null)!==expected)throw new Error("Файл изменён во время загрузки");
    const parts=r.path.split("/");parts.pop();let parent="";
    for(const p of parts){parent=parent?parent+"/"+p:p;if(!this.app.vault.getAbstractFileByPath(parent)){try{await this.app.vault.createFolder(parent);}catch(e){if(!this.app.vault.getAbstractFileByPath(parent))throw e;}}}
    const existing=this.app.vault.getAbstractFileByPath(r.path);
    if(existing instanceof TFile)await this.app.vault.modifyBinary(existing,data.buffer as ArrayBuffer);else if(!existing)await this.app.vault.createBinary(normalizePath(r.path),data.buffer as ArrayBuffer);else throw new Error("Конфликт файла и папки");
    this.cfg.base[r.path]=r.hash;delete this.cfg.tombstones[r.path];delete this.cfg.pendingDeletes[r.path];await this.clearCache(r);
  }
  async sync(){
    if(this.stopped||!this.cfg.token)return;if(this.running){this.pending=true;return;}
    this.running=true;let done=0,conflicts=0,errors=0;
    this.errorsByPath=Object.create(null);this.conflictsByPath=[];
    const deleteCount=Object.keys(this.cfg.pendingDeletes).length;
    const batchAllowed=deleteCount<=10||this.allowBatchDelete;
    this.allowBatchDelete=false;
    try{
      this.render("Проверка…");
      if(Date.now()-this.fullCheckAt>30*60*1000){this.localHashes.clear();this.fullCheckAt=Date.now();}
      const remote:RemoteFile[]=await this.req("GET","/index");
      const map=new Map(remote.map(r=>[r.path,r]));
      const paths=[...new Set([...this.app.vault.getFiles().map(f=>f.path),...map.keys()])].filter(valid);
      this.syncStarted=Date.now();this.total=paths.length;this.completed=0;this.transferred=0;let i=0;
      const worker=async()=>{while(i<paths.length&&!this.stopped){const path=paths[i++];try{
        const l=await this.local(path),r=map.get(path),base=this.cfg.base[path];
        if(l)delete this.cfg.pendingDeletes[path];
        if(r?.deleted){
          if(!l){await this.markDeleted(path,r.rev);}
          else if(this.cfg.tombstones[path]===r.rev){await this.push(path,l,r);}
          else if(this.cfg.deleteEnabled&&base===l.hash&&base===r.hash){await this.trashLocal(r,l.hash);}
          else{conflicts++;this.conflictsByPath.push(path);}
        }
        else if(l&&r&&l.hash===r.hash){this.cfg.base[path]=l.hash;delete this.cfg.tombstones[path];}
        else if(l&&!r){await this.push(path,l);}
        else if(!l&&r){
          const intent=this.cfg.pendingDeletes[path];
          if(this.cfg.deleteEnabled&&intent){
            if(batchAllowed&&intent===r.hash){await this.deleteRemote(path,r);}
            else{conflicts++;this.conflictsByPath.push(path);}
          }else{await this.pull(r,null);}
        }
        else if(l&&r){if(base===r.hash){await this.push(path,l,r);}else if(base===l.hash){await this.pull(r,l.hash);}else{conflicts++;this.conflictsByPath.push(path);}}
      }catch(e){errors++;this.errorsByPath[path]=e instanceof Error?e.message:"unknown";console.warn("Private Sync file error",this.errorsByPath[path]);}finally{done++;this.completed=done;this.renderProgress();}}};
      await Promise.all(Array.from({length:Platform.isMobile?2:3},()=>worker()));
      await this.save();this.render(errors||conflicts?"Ошибки: "+errors+" · Конфликты: "+conflicts:"Синхронизировано");
      if(conflicts)new Notice("Private Sync: конфликтующие файлы оставлены без изменений ("+conflicts+")");
    }catch(e){this.render("Ошибка: "+(e instanceof Error?e.message:"unknown"));}
    finally{this.running=false;if(this.pending&&!this.stopped){this.pending=false;window.setTimeout(()=>void this.sync(),500);}}
  }
}
class SyncSettings extends PluginSettingTab {
  constructor(app:App,private p:PrivateSync){super(app,p);}
  display(){
    const el=this.containerEl;el.empty();el.createEl("h2",{text:"Private Vault Sync"});
    let server=this.p.cfg.server,code="",device=this.p.cfg.device;
    new Setting(el).setName("Адрес сервера").addText(t=>t.setValue(server).onChange(v=>server=v));
    new Setting(el).setName("Одноразовый код").addText(t=>{t.inputEl.type="password";t.onChange(v=>code=v);});
    new Setting(el).setName("Имя устройства").addText(t=>t.setValue(device).onChange(v=>device=v));
    new Setting(el).setName("Подключение").addButton(b=>b.setButtonText("Подключить").setCta().onClick(async()=>{try{if(this.p.cfg.token)throw new Error("Уже подключено");await this.p.connect(server,code,device);code="";new Notice("Подключено");this.display();}catch(e){new Notice(String(e));}}));
    new Setting(el).setName("Новое устройство").addButton(b=>b.setButtonText("Получить код").setDisabled(!this.p.cfg.token).onClick(async()=>{try{const r=await this.p.pair();new PairCodeModal(this.app,this.p,r.code).open();}catch(e){new Notice(String(e));}}));
    new Setting(el).setName("Состояние").setDesc(this.p.progress).addButton(b=>b.setButtonText("Синхронизировать").onClick(()=>void this.p.sync()));
    new Setting(el).setName("Синхронизация удалений").setDesc("По умолчанию выключена. Только подтверждённые локальные удаления; старые версии остаются на сервере.").addToggle(t=>t.setValue(this.p.cfg.deleteEnabled).onChange(async v=>{this.p.cfg.deleteEnabled=v;if(!v)this.p.cfg.pendingDeletes=Object.create(null);await this.p.save();}));
    if(Object.keys(this.p.cfg.pendingDeletes).length>10)new Setting(el).setName("Пакет удалений приостановлен").addButton(b=>b.setButtonText("Разрешить один пакет").onClick(()=>{this.p.allowBatchDelete=true;void this.p.sync();}));
    new Setting(el).setName("Устройства").addButton(b=>b.setButtonText("Показать").setDisabled(!this.p.cfg.token).onClick(()=>new DevicesModal(this.app,this.p).open()));
    new Setting(el).setName("История файла").addButton(b=>b.setButtonText("Открыть").setDisabled(!this.p.cfg.token).onClick(()=>new HistoryModal(this.app,this.p).open()));
    new Setting(el).setName("Ошибки и конфликты").addButton(b=>b.setButtonText("Подробнее").onClick(()=>new ErrorsModal(this.app,this.p).open()));
    el.createEl("p",{text:"Экспериментальная версия: конфликты не перезаписываются. Не используйте для единственной копии данных. Настройки .obsidian пока не передаются."});
  }
}

class DevicesModal extends Modal{
  constructor(app:App,private p:PrivateSync){super(app);}
  async onOpen(){
    const el=this.contentEl;el.empty();el.createEl("h2",{text:"Подключённые устройства"});
    try{for(const d of await this.p.devices()){
      new Setting(el).setName(d.name+(d.current?" (это устройство)":"")).setDesc(new Date(d.created*1000).toLocaleString()).addButton(b=>b.setButtonText("Отключить").setDisabled(d.current).onClick(async()=>{b.setDisabled(true);try{await this.p.revoke(d.id);await this.onOpen();}catch(e){new Notice(String(e));b.setDisabled(false);}}));
    }}catch(e){el.createEl("p",{text:String(e)});}
  }
}
class HistoryModal extends Modal{
  constructor(app:App,private p:PrivateSync){super(app);}
  onOpen(){
    const el=this.contentEl;el.empty();el.createEl("h2",{text:"История версий"});
    let path=this.app.workspace.getActiveFile()?.path??"";
    const results=el.createDiv();
    new Setting(el).setName("Путь файла").addText(t=>t.setValue(path).onChange(v=>path=v)).addButton(b=>b.setButtonText("Найти").onClick(async()=>{
      results.empty();try{const rows:RemoteFile[]=await this.p.req("POST","/history",{path});if(!rows.length)results.createEl("p",{text:"Нет предыдущих версий"});
      for(const r of rows)new Setting(results).setName("Версия "+r.rev).setDesc(r.size+" байт").addButton(btn=>btn.setButtonText("Восстановить").onClick(async()=>{btn.setDisabled(true);try{await this.p.restoreVersion(r);new Notice("Версия восстановлена");this.close();}catch(e){new Notice(String(e));btn.setDisabled(false);}}));
      }catch(e){results.createEl("p",{text:String(e)});}
    }));
  }
}
class ErrorsModal extends Modal{
  constructor(app:App,private p:PrivateSync){super(app);}
  onOpen(){const el=this.contentEl;el.empty();el.createEl("h2",{text:"Последняя синхронизация"});
    for(const [path,error] of Object.entries(this.p.errorsByPath))el.createEl("p",{text:path+": "+error});
    for(const path of this.p.conflictsByPath)el.createEl("p",{text:"Конфликт: "+path+" — обе версии сохранены"});
    if(!Object.keys(this.p.errorsByPath).length&&!this.p.conflictsByPath.length)el.createEl("p",{text:"Нет ошибок или конфликтов"});
  }
}
class PairCodeModal extends Modal{
  constructor(app:App,private p:PrivateSync,private code:string){super(app);}
  onOpen(){
    const el=this.contentEl;el.empty();el.createEl("h2",{text:"Подключить новое устройство"});
    const link="obsidian://private-vault-sync?"+new URLSearchParams({server:this.p.endpoint(),code:this.code}).toString();
    el.createEl("p",{text:"Установи плагин на новом устройстве, открой нужное хранилище и импортируй ссылку. Код действует 10 минут и только один раз."});
    const canvas=el.createEl("canvas");canvas.style.display="block";canvas.style.margin="12px auto";canvas.style.maxWidth="100%";void QRCode.toCanvas(canvas,link,{width:260,margin:2,errorCorrectionLevel:"M"}).catch(()=>canvas.remove());
    const box=el.createEl("textarea",{text:link});box.readOnly=true;box.rows=4;box.style.width="100%";
    new Setting(el).addButton(b=>b.setButtonText("Скопировать ссылку").setCta().onClick(async()=>{try{await navigator.clipboard.writeText(link);new Notice("Ссылка скопирована");}catch{box.select();new Notice("Скопируйте выделенную ссылку");}}));
    new Setting(el).setName("Код для ручного ввода").addText(t=>{t.setValue(this.code);t.inputEl.readOnly=true;});
  }
  onClose(){this.contentEl.empty();this.code="";}
}
class PairConnectModal extends Modal{
  constructor(app:App,private p:PrivateSync,private server:string,private code:string){super(app);}
  onOpen(){
    const el=this.contentEl;el.empty();el.createEl("h2",{text:"Подключить хранилище"});
    el.createEl("p",{text:"Сервер: "+this.server});
    el.createEl("p",{text:"Будут синхронизированы файлы текущего хранилища. Убедись, что выбран правильный сервер."});
    let device=this.p.cfg.device;
    new Setting(el).setName("Имя устройства").addText(t=>t.setValue(device).onChange(v=>device=v));
    new Setting(el).addButton(b=>b.setButtonText("Подключить").setCta().onClick(async()=>{b.setDisabled(true);try{await this.p.connect(this.server,this.code,device);this.close();}catch(e){new Notice(String(e));b.setDisabled(false);}}));
  }
  onClose(){this.contentEl.empty();this.code="";}
}