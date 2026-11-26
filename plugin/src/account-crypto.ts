import { scryptAsync } from "@noble/hashes/scrypt";
import { sha256 } from "@noble/hashes/sha256";
import { hkdf } from "@noble/hashes/hkdf";
import { gcmsiv } from "@noble/ciphers/aes";
import { bytesToHex, hexToBytes, concatBytes } from "@noble/hashes/utils";

const encoder=new TextEncoder();
const context=encoder.encode("private-vault-sync/account/v1");
export function randomHex(length:number):string {
  return bytesToHex(globalThis.crypto.getRandomValues(new Uint8Array(length)));
}
export async function deriveAccount(username:string,passphrase:string,salt:string){
  if(!/^[0-9a-f]{64}$/.test(salt))throw new Error("Invalid account salt");
  const master=await scryptAsync(encoder.encode(passphrase),hexToBytes(salt),{N:131072,r:8,p:1,dkLen:32,maxmem:160*1024*1024});
  const aad=concatBytes(context,encoder.encode("/"+username));
  const proof=bytesToHex(hkdf(sha256,master,new Uint8Array(),concatBytes(aad,encoder.encode("/auth")),32));
  const wrappingKey=hkdf(sha256,master,new Uint8Array(),concatBytes(aad,encoder.encode("/wrap")),32);
  master.fill(0);
  return {proof,
    wrap(value:Uint8Array){
      if(value.length!==32)throw new Error("Invalid vault key length");
      const nonce=globalThis.crypto.getRandomValues(new Uint8Array(12));
      return bytesToHex(concatBytes(nonce,gcmsiv(wrappingKey,nonce,aad).encrypt(value)));
    },
    unwrap(value:string){
      if(!/^[0-9a-f]{120}$/.test(value))throw new Error("Invalid account envelope");
      const wire=hexToBytes(value);
      return gcmsiv(wrappingKey,wire.subarray(0,12),aad).decrypt(wire.subarray(12));
    },
    dispose(){wrappingKey.fill(0);}
  };
}
