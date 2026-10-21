import {base,scalar,decode,shared} from '../group/ristretto';
import {kdf,open,seal,type Sealed} from '../crypto';
import {concat,tuple} from '../encode';
export type Cipher={v:Uint8Array;box:Sealed;ctr?:boolean};
export async function encrypt(pub:Uint8Array,payload:Uint8Array):Promise<Cipher>{
 decode(pub);const beta=scalar(),v=base.multiply(beta).toBytes(),w=shared(pub,beta);
 const key=await kdf('AKE1/E_EG/KEM',concat(v,w));return {v,box:await seal(key,payload)};
}
export async function decrypt(secret:bigint,c:Cipher):Promise<Uint8Array>{
 if(c.ctr)throw new Error('CTR ciphertext cannot use honest AEAD decryptor');
 const key=await kdf('AKE1/E_EG/KEM',concat(c.v,shared(c.v,secret)));
 return open(key,c.box);
}
export function encodeCipher(c:Cipher):Uint8Array{return tuple('AKE1/cipher',c.v,c.box.iv,c.box.data)}

