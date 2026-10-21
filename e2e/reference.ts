// Independent protocol encodings and crypto calculations: no imports from src/.
import {createHash,createDecipheriv,createPublicKey,verify,hkdfSync} from 'node:crypto';
import {ristretto255} from '@noble/curves/ed25519.js';
export const unhex=(s:string)=>Buffer.from(s,'hex');
export function tuple(domain:string,...parts:Buffer[]){return Buffer.concat([Buffer.from(domain),...parts].map(p=>{const n=Buffer.alloc(4);n.writeUInt32BE(p.length);return Buffer.concat([n,p])}))}
export function binding(w:any){const cipher=tuple('AKE1/cipher',unhex(w.v),unhex(w.iv),unhex(w.data));return tuple('AKE1/channel-binding',Buffer.from(w.p),Buffer.from(w.q),unhex(w.r),cipher).toString('hex')}
export function fingerprint(key:string){return createHash('sha256').update(unhex(key)).digest('hex').slice(0,16)}
export function decrypt(key:string,record:{iv:string;data:string}){const data=unhex(record.data),d=createDecipheriv('aes-256-gcm',unhex(key),unhex(record.iv));d.setAuthTag(data.subarray(-16));return Buffer.concat([d.update(data.subarray(0,-16)),d.final()])}
export function sig(publicKey:string,message:Buffer,signature:string){const key=createPublicKey({key:{kty:'OKP',crv:'Ed25519',x:unhex(publicKey).toString('base64url')},format:'jwk'});return verify(null,message,key,unhex(signature))}
export function kdf(domain:string,input:Buffer,len=32){return Buffer.from(hkdfSync('sha256',input,Buffer.alloc(32),tuple(domain),len))}
export function ake1LeakedKey(scalar:string,cipher:any){const v=unhex(cipher.v),w=ristretto255.Point.fromBytes(v).multiply(BigInt(scalar)).toBytes();const k=kdf('AKE1/E_EG/KEM',Buffer.concat([v,w]));return decrypt(k.toString('hex'),cipher.box).subarray(0,32).toString('hex')}
export function ake5Keys(e:any){const p=ristretto255.Point.fromBytes(unhex(e.pubP)),mu=ristretto255.Point.fromBytes(unhex(e.mu)),order=2n**252n+27742317777372353535851937790883648493n;
 const dh1=p.add(mu).multiply((BigInt(e.beta)+BigInt(e.nuSecret))%order).toBytes(),dh2=mu.multiply(BigInt(e.nuSecret)).toBytes();
 return kdf('AKE5/H',tuple('AKE5/inputs',Buffer.from(dh1),Buffer.from(dh2),unhex(e.pubP),unhex(e.mu),unhex(e.pubQ),unhex(e.nu),Buffer.from('P'),Buffer.from('Q')),96).toString('hex');}
