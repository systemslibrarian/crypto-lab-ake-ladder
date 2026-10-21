import {base,scalar,shared} from '../group/ristretto';
import {bytes,concat,tuple} from '../encode';
import {kdf,seal} from '../crypto';
import type {Cert} from '../ca/ca';
/** A fake responder knows its own exponent and public material, never P's state. */
export async function fakeResponder(u:Uint8Array,knownCertificate:Cert){
 const beta=scalar(),v=base.multiply(beta).toBytes();
 const keys=await kdf('AKE4eg/k,k1,k2',tuple('AKE4eg/DH',u,v,shared(u,beta)),96);
 const cert=structuredClone(knownCertificate);cert.ca[0]^=1;
 const c1=await seal(keys.slice(32,64),concat(new Uint8Array(64),bytes(cert.id),cert.enc,cert.sig,cert.ca));
 return {v,c1};
}
