import { requestUrl } from "obsidian";
import { deriveAccount, randomHex } from "./account-crypto";
import { bytesToHex, hexToBytes } from "@noble/hashes/utils";

type AccountStatus={initialized:boolean;salt:string|null};
type AccountSession={token:string;envelope:string};
export type AccountCredentials={username:string;password:string;device:string};
export function validateAccountFields(input:AccountCredentials,creating:boolean){
  if(!/^[a-zA-Z0-9._-]{3,64}$/.test(input.username.trim()))throw new Error("Логин: от 3 до 64 латинских букв, цифр, точек, дефисов или подчёркиваний");
  if(!input.password||input.password.length>1024)throw new Error("Введите пароль");
  if(creating&&input.password.length<16)throw new Error("Придумайте пароль не короче 16 символов");
  if(!input.device.trim()||input.device.length>60)throw new Error("Введите имя устройства (до 60 символов)");
}
export async function accountStatus(origin:string):Promise<AccountStatus>{
  const r=await requestUrl({url:origin+"/v1/account/status",headers:{"X-Private-Sync-Protocol":"e2ee-v1"},throw:false});
  if(r.status!==200)throw new Error("Сервер не поддерживает вход по аккаунту (HTTP "+r.status+")");
  return r.json;
}
async function post(origin:string,path:string,body:unknown){
  const r=await requestUrl({url:origin+path,method:"POST",headers:{"X-Private-Sync-Protocol":"e2ee-v1","Content-Type":"application/json"},body:JSON.stringify(body),throw:false});
  if(r.status===401)throw new Error("Неверный логин или пароль");
  if(r.status===403)throw new Error("Первичная настройка недоступна");
  if(r.status===409)throw new Error("Аккаунт уже создан или хранилище не пустое");
  if(r.status===429)throw new Error("Слишком много попыток. Попробуйте позже");
  if(r.status!==200&&r.status!==201)throw new Error("Ошибка сервера: HTTP "+r.status);
  return r;
}
export async function createOwner(adminOrigin:string,input:AccountCredentials){
  validateAccountFields(input,true);
  // The administrator's bootstrap transport is local and never published by Caddy.
  if(!/^http:\/\/127\.0\.0\.1:\d{1,5}$/.test(adminOrigin))throw new Error("Первичная настройка разрешена только через локальный административный канал");
  const username=input.username.trim(),salt=randomHex(32);
  const derived=await deriveAccount(username,input.password,salt);
  try {
    const envelope=derived.wrap(hexToBytes(randomHex(32)));
    await post(adminOrigin,"/v1/account/setup",{username,salt,auth:derived.proof,envelope});
  } finally {derived.dispose();}
}
export async function signIn(origin:string,input:AccountCredentials){
  validateAccountFields(input,false);
  const username=input.username.trim(),status=await accountStatus(origin);
  if(!status.initialized||!status.salt)throw new Error("Сначала создайте аккаунт владельца");
  const derived=await deriveAccount(username,input.password,status.salt);
  try {
    const response=await post(origin,"/v1/account/login",{username,auth:derived.proof,name:input.device.trim()});
    const session:AccountSession=response.json;
    return {sessionId:session.token,vaultKey:bytesToHex(derived.unwrap(session.envelope))};
  } finally {derived.dispose();}
}
