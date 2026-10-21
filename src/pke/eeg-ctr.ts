import {base,scalar,shared,decode} from '../group/ristretto';
import {kdf,randomBytes} from '../crypto';
import {concat} from '../encode';
import type {Cipher} from './eeg';
/** BROKEN: V6 alone; AES-CTR does not authenticate the ciphertext. */
export async function encryptCtr(pub:Uint8Array,payload:Uint8Array):Promise<Cipher>{
 decode(pub);const beta=scalar(),v=base.multiply(beta).toBytes(),key=await kdf('AKE1/E_EG/KEM',concat(v,shared(pub,beta))),iv=randomBytes(16);
 return {v,ctr:true,box:{iv,data:await ctrEncrypt(key,iv,payload)}};
}
export async function decryptCtr(secret:bigint,c:Cipher):Promise<Uint8Array>{
 if(!c.ctr||c.box.iv.length!==16)throw new Error('Invalid CTR cipher');
 const key=await kdf('AKE1/E_EG/KEM',concat(c.v,shared(c.v,secret)));
 const k=await crypto.subtle.importKey('raw',new Uint8Array(key),'AES-CTR',false,['decrypt']);
 return new Uint8Array(await crypto.subtle.decrypt({name:'AES-CTR',counter:new Uint8Array(c.box.iv),length:64},k,new Uint8Array(c.box.data)));
}


/** Raw CTR primitive; fixed counter is used only by published KATs. */
export async function ctrEncrypt(key:Uint8Array,iv:Uint8Array,payload:Uint8Array){
 const k=await crypto.subtle.importKey('raw',new Uint8Array(key),'AES-CTR',false,['encrypt']);
 return new Uint8Array(await crypto.subtle.encrypt({name:'AES-CTR',counter:new Uint8Array(iv),length:64},k,new Uint8Array(payload)));
}
