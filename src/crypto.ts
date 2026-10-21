import {tuple} from './encode';
export const randomBytes=(n:number)=>crypto.getRandomValues(new Uint8Array(n));
export async function kdf(domain:string,input:Uint8Array,length=32):Promise<Uint8Array>{
 const material=await crypto.subtle.importKey('raw',new Uint8Array(input),'HKDF',false,['deriveBits']);
 return new Uint8Array(await crypto.subtle.deriveBits({name:'HKDF',hash:'SHA-256',salt:new Uint8Array(32),info:new Uint8Array(tuple(domain))},material,length*8));
}
export type Sealed={iv:Uint8Array;data:Uint8Array};
export async function seal(key:Uint8Array,plain:Uint8Array):Promise<Sealed>{
 const iv=randomBytes(12),k=await crypto.subtle.importKey('raw',new Uint8Array(key),'AES-GCM',false,['encrypt']);
 return {iv,data:new Uint8Array(await crypto.subtle.encrypt({name:'AES-GCM',iv},k,new Uint8Array(plain)))};
}
export async function open(key:Uint8Array,box:Sealed):Promise<Uint8Array>{
 const k=await crypto.subtle.importKey('raw',new Uint8Array(key),'AES-GCM',false,['decrypt']);
 try{return new Uint8Array(await crypto.subtle.decrypt({name:'AES-GCM',iv:new Uint8Array(box.iv)},k,new Uint8Array(box.data)))}catch{throw new Error('decryption failed (AES-GCM tag)')}
}
export async function fingerprint(key:Uint8Array):Promise<string>{const h=await crypto.subtle.digest('SHA-256',new Uint8Array(key));return Array.from(new Uint8Array(h).slice(0,8),b=>b.toString(16).padStart(2,'0')).join('')}

