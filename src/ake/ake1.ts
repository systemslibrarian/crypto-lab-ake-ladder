import {base,scalar} from '../group/ristretto';
import {keypair,sign,verify} from '../sig/ed25519';
import {ToyCA,type Cert} from '../ca/ca';
import {bytes,concat,equal,hex,tuple} from '../encode';
import {randomBytes,fingerprint} from '../crypto';
import {encrypt,decrypt,encodeCipher,type Cipher} from '../pke/eeg';
import {encryptCtr,decryptCtr} from '../pke/eeg-ctr';
import {HONEST,type Definition} from './variants';

export type Party={id:string;encSecret:bigint;signSecret:Uint8Array;cert:Cert};
export type Context={ca:ToyCA;p:Party;q:Party;r:Party};
export type Start={r:Uint8Array;cert:Cert};
export type Response={cipher:Cipher;signature:Uint8Array;cert:Cert;key:Uint8Array;peer:string};
export type View={partner:string;key:Uint8Array;fingerprint:string;binding:string};
export function setup():Context {
 const ca=new ToyCA();
 const party=(id:string):Party=>{const encSecret=scalar(),kp=keypair(),pub=base.multiply(encSecret).toBytes();return {id,encSecret,signSecret:kp.secretKey,cert:ca.register(id,pub,kp.publicKey)}};
 const p=party('P'),q=party('Q'),r=party('R');return {ca,p,q,r};
}
export function first(p:Party):Start{return {r:randomBytes(32),cert:p.cert}}
export function signatureInput(def:Definition,start:Start,cipher:Cipher,idP:string):Uint8Array{
 return tuple(`AKE1/V${def.id}/sig`,...(def.omitR?[]:[start.r]),...(def.omitC?[]:[encodeCipher(cipher)]),...(def.omitIdP?[]:[bytes(idP)]));
}
function payload(def:Definition,key:Uint8Array,id:string,nonce:Uint8Array):Uint8Array{
 return def.payload==='key-id'?concat(key,bytes(id)):def.payload==='key-r'?concat(key,nonce):key;
}
export async function respond(def:Definition,start:Start,q:Party,ca:ToyCA):Promise<Response>{
 if(!ca.check(start.cert))throw new Error('certificate invalid at Q');
 const key=randomBytes(32),plain=payload(def,key,q.id,start.r);
 const cipher=def.ctr?await encryptCtr(start.cert.enc,plain):await encrypt(start.cert.enc,plain);
 return {cipher,signature:sign(q.signSecret,signatureInput(def,start,cipher,start.cert.id)),cert:q.cert,key,peer:start.cert.id};
}
export async function finish(def:Definition,start:Start,response:Response,p:Party,ca:ToyCA):Promise<View>{
 if(!ca.check(response.cert))throw new Error('certificate invalid at P');
 if(!verify(response.cert.sig,signatureInput(def,start,response.cipher,p.id),response.signature))throw new Error('signature verification failed');
 const plain=def.ctr?await decryptCtr(p.encSecret,response.cipher):await decrypt(p.encSecret,response.cipher);
 if(plain.length!==(def.payload==='key-id'?33:def.payload==='key-r'?64:32))throw new Error('decrypted payload length invalid');
 const key=plain.slice(0,32),bound=plain.slice(32);
 if(def.payload==='key-id'&&!equal(bound,bytes(response.cert.id)))throw new Error(`decrypted identity ${String.fromCharCode(...bound)} ≠ certificate identity ${response.cert.id}`);
 if(def.payload==='key-r'&&!equal(bound,start.r))throw new Error('decrypted nonce ≠ current r');
 const binding=hex(tuple('AKE1/channel-binding',bytes(p.id),bytes(response.cert.id),start.r,encodeCipher(response.cipher)));
 return {partner:response.cert.id,key,fingerprint:await fingerprint(key),binding};
}
export async function honest():Promise<{p:View;q:View;ctx:Context;start:Start;response:Response}>{
 const ctx=setup(),start=first(ctx.p),response=await respond(HONEST,start,ctx.q,ctx.ca),p=await finish(HONEST,start,response,ctx.p,ctx.ca);
 const q:View={partner:response.peer,key:response.key,fingerprint:await fingerprint(response.key),binding:hex(tuple('AKE1/channel-binding',bytes(start.cert.id),bytes(ctx.q.id),start.r,encodeCipher(response.cipher)))};
 return {p,q,ctx,start,response};
}
