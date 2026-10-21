import {base,scalar,shared} from '../group/ristretto';
import {bytes,concat,equal,tuple} from '../encode';
import {fingerprint,kdf,seal,open} from '../crypto';
import {sign,verify} from '../sig/ed25519';
import {setup} from './ake1';
import type {Cert} from '../ca/ca';
import {fakeResponder} from '../attack/probe';
const certWire=(cert:Cert)=>concat(bytes(cert.id),cert.enc,cert.sig,cert.ca);
function parseCert(data:Uint8Array):Cert {
 if(data.length!==129)throw new Error('certificate byte length invalid');
 return {id:String.fromCharCode(data[0]),enc:data.slice(1,33),sig:data.slice(33,65),ca:data.slice(65,129)};
}
async function keys4(u:Uint8Array,v:Uint8Array,dh:Uint8Array):Promise<[Uint8Array,Uint8Array,Uint8Array]>{
 const block=await kdf('AKE4eg/k,k1,k2',tuple('AKE4eg/DH',u,v,dh),96);
 return [block.slice(0,32),block.slice(32,64),block.slice(64,96)];
}
export async function ake4(activeFake=false):Promise<{u:Uint8Array;v:Uint8Array;c1:{iv:Uint8Array;data:Uint8Array};c2?:{iv:Uint8Array;data:Uint8Array};partner?:string;reason:string;fingerprint?:string;signatureP?:Uint8Array;publicP?:Uint8Array}>{
 const ctx=setup(),a=scalar(),b=scalar(),u=base.multiply(a).toBytes();let v=base.multiply(b).toBytes();
 const [qKey,q1,q2]=await keys4(u,v,shared(u,b));
 let c1;
 if(activeFake){const fake=await fakeResponder(u,ctx.q.cert);v=fake.v;c1=fake.c1}
 else{const signature=sign(ctx.q.signSecret,tuple('AKE4eg/Q/sig',bytes('1'),u,v));c1=await seal(q1,concat(signature,certWire(ctx.q.cert)))}
 const [key,k1,k2]=await keys4(u,v,shared(v,a));
 if(!activeFake&&(!equal(qKey,key)||!equal(q1,k1)||!equal(q2,k2)))throw new Error('AKE4 key mismatch');
 const decoded=await open(k1,c1),readCert=parseCert(decoded.slice(64));
 if(!ctx.ca.check(readCert))return {u,v,c1,reason:'Fake responder: certificate invalid; P aborted before c2 and kept its identity hidden.'};
 if(!verify(readCert.sig,tuple('AKE4eg/Q/sig',bytes('1'),u,v),decoded.slice(0,64)))return {u,v,c1,reason:'Q signature invalid; P aborted before c2.'};
 const sigP=sign(ctx.p.signSecret,tuple('AKE4eg/P/sig',bytes('2'),u,v));
 const c2=await seal(k2,concat(sigP,certWire(ctx.p.cert)));
 const other=await open(q2,c2),pCert=parseCert(other.slice(64));
 if(!ctx.ca.check(pCert)||!verify(pCert.sig,tuple('AKE4eg/P/sig',bytes('2'),u,v),other.slice(0,64)))throw new Error('P confirmation failed');
 return {u,v,c1,c2,partner:readCert.id,reason:'Both identities remained in AES-GCM ciphertext on the wire; the signed peers agreed.',fingerprint:await fingerprint(key),signatureP:sigP,publicP:ctx.p.cert.sig};
}
