import { gcmsiv } from "@noble/ciphers/aes";
import { sha256 } from "@noble/hashes/sha256";
import { hkdf } from "@noble/hashes/hkdf";
import { hmac } from "@noble/hashes/hmac";
import { bytesToHex, hexToBytes, concatBytes } from "@noble/hashes/utils";

export const WIRE_CHUNK = 1024*1024;
const OVERHEAD = 28; // 12-byte nonce + 16-byte authentication tag
const PLAIN_CHUNK = WIRE_CHUNK - OVERHEAD;
export const E2EE_PREFIX = "e2ee-v1/";
export const KEY_CHECK = E2EE_PREFIX+"keycheck";
const enc = new TextEncoder();
const dec = new TextDecoder("utf-8",{fatal:true});
const empty = new Uint8Array();
export function newVaultKey(): string {
  return bytesToHex(globalThis.crypto.getRandomValues(new Uint8Array(32)));
}
export class VaultCipher {
  private readonly pathKey:Uint8Array;
  private readonly dataKey:Uint8Array;
  private readonly nonceKey:Uint8Array;
  constructor(key:string){
    if(!/^[0-9a-f]{64}$/i.test(key))throw Error("Encryption key must contain exactly 64 hexadecimal characters.");
    const master=hexToBytes(key);
    this.pathKey=hkdf(sha256,master,empty,enc.encode("private-vault-sync/v1/path"),32);
    this.dataKey=hkdf(sha256,master,empty,enc.encode("private-vault-sync/v1/data"),32);
    this.nonceKey=hkdf(sha256,master,empty,enc.encode("private-vault-sync/v1/nonce"),32);
    master.fill(0);
  }
  // Keyed deterministic nonces preserve resumability/deduplication. GCM-SIV is
  // nonce-misuse resistant. Equality within the same context remains visible.
  private seal(key:Uint8Array,aad:Uint8Array,plain:Uint8Array):Uint8Array {
    const nonce=hmac.create(sha256,this.nonceKey).update(sha256(aad)).update(plain).digest().slice(0,12);
    return concatBytes(nonce,gcmsiv(key,nonce,aad).encrypt(plain));
  }
  private open(key:Uint8Array,aad:Uint8Array,wire:Uint8Array):Uint8Array {
    if(wire.length<OVERHEAD)throw Error("Invalid encrypted block");
    const nonce=wire.subarray(0,12);
    const plain=gcmsiv(key,nonce,aad).decrypt(wire.subarray(12));
    const expected=hmac.create(sha256,this.nonceKey).update(sha256(aad)).update(plain).digest().slice(0,12);
    if(!expected.every((b,i)=>b===nonce[i]))throw Error("Noncanonical encrypted block");
    return plain;
  }
  path(path:string):string {
    const wire=bytesToHex(this.seal(this.pathKey,enc.encode("path/v1"),enc.encode(path)));
    const result=E2EE_PREFIX+(wire.match(/.{1,120}/g)??[]).join("/");
    if(result.length>4096)throw Error("Encrypted path is too long");
    return result;
  }
  unpath(wire:string):string {
    if(!wire.startsWith(E2EE_PREFIX)||wire===KEY_CHECK)throw Error("Unencrypted or incompatible remote vault");
    const hex=wire.slice(E2EE_PREFIX.length).replace(/\//g,"");
    if(!/^(?:[0-9a-f]{2}){28,2048}$/.test(hex))throw Error("Invalid encrypted path");
    const path=dec.decode(this.open(this.pathKey,enc.encode("path/v1"),hexToBytes(hex)));
    if(this.path(path)!==wire)throw Error("Invalid encrypted path encoding");
    return path;
  }
  private aad(path:string,index:number,count:number):Uint8Array{
    return enc.encode(JSON.stringify(["file/v1",path,index,count]));
  }
  encode(path:string,plain:Uint8Array):Uint8Array {
    const framed=concatBytes(sha256(plain),plain);
    const count=Math.ceil(framed.length/PLAIN_CHUNK);
    const wire=new Uint8Array(framed.length+count*OVERHEAD);
    for(let i=0;i<count;i++){
      const part=framed.subarray(i*PLAIN_CHUNK,(i+1)*PLAIN_CHUNK);
      wire.set(this.seal(this.dataKey,this.aad(path,i,count),part),i*WIRE_CHUNK);
    }
    return wire;
  }
  decode(path:string,wire:Uint8Array):Uint8Array {
    const count=Math.ceil(wire.length/WIRE_CHUNK);
    if(count<1||wire.length<count*OVERHEAD)throw Error("Invalid encrypted file length");
    const plain=new Uint8Array(wire.length-count*OVERHEAD);
    for(let i=0;i<count;i++){
      const part=wire.subarray(i*WIRE_CHUNK,(i+1)*WIRE_CHUNK);
      plain.set(this.open(this.dataKey,this.aad(path,i,count),part),i*PLAIN_CHUNK);
    }
    if(plain.length<32||!sha256(plain.subarray(32)).every((b,i)=>b===plain[i]))throw Error("Encrypted file digest mismatch");
    return plain.slice(32);
  }
  marker():Uint8Array{return this.encode(KEY_CHECK,enc.encode("Private Vault Sync encryption v1"));}
}
