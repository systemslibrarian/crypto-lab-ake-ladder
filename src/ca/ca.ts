import {keypair,sign,verify} from '../sig/ed25519';
import {tuple,bytes} from '../encode';
export type Cert={id:string;enc:Uint8Array;sig:Uint8Array;ca:Uint8Array};
export class ToyCA {
 private key=keypair();
 register(id:string,enc:Uint8Array,sig:Uint8Array,{requirePoP=false}:{requirePoP?:boolean}={}):Cert{
  if(!/^[PQR]$/.test(id)||enc.length!==32||sig.length!==32)throw new RangeError('Invalid certificate registration');
  if(requirePoP)throw new Error('Proof-of-possession extension is not implemented');
  const content=tuple('AKE-LADDER/cert/v1',bytes(id),enc,sig);
  return {id,enc,sig,ca:sign(this.key.secretKey,content)};
 }
 check(cert:Cert):boolean{return verify(this.key.publicKey,tuple('AKE-LADDER/cert/v1',bytes(cert.id),cert.enc,cert.sig),cert.ca)}
 // [extension] point: requirePoP would prevent V3's same-public-key certificate registration.
}
