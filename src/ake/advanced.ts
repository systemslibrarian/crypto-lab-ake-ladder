import {base,decode,scalar,shared,ORDER} from '../group/ristretto';
import {bytes,concat,equal,tuple} from '../encode';
import {fingerprint,kdf,seal,open} from '../crypto';
import {sign,verify} from '../sig/ed25519';
import {setup,type Context} from './ake1';
import type {Cert} from '../ca/ca';

const sig2=(role:string,...fields:Uint8Array[])=>tuple(`AKE2eg/${role}`, ...fields);
export async function ake2():Promise<{ctx:Context;alpha:bigint;u:Uint8Array;v:Uint8Array;signatureP:Uint8Array;key:Uint8Array;p:string;q:string;record:{iv:Uint8Array;data:Uint8Array};leak:string;ephemeral:string}>{
 const ctx=setup(),alpha=scalar(),beta=scalar(),u=base.multiply(alpha).toBytes(),v=base.multiply(beta).toBytes();
 const signatureP=sign(ctx.p.signSecret,sig2('P',u));
 if(!ctx.ca.check(ctx.p.cert)||!verify(ctx.p.cert.sig,sig2('P',u),signatureP))throw new Error('P certificate or signature failed');
 const signatureQ=sign(ctx.q.signSecret,sig2('Q',u,v,bytes('P')));
 if(!ctx.ca.check(ctx.q.cert)||!verify(ctx.q.cert.sig,sig2('Q',u,v,bytes('P')),signatureQ))throw new Error('Q certificate or signature failed');
 const key=await kdf('AKE2eg/k',tuple('AKE2eg/DH',u,v,shared(v,alpha),bytes('Q')));
 const qKey=await kdf('AKE2eg/k',tuple('AKE2eg/DH',u,v,shared(u,beta),bytes('Q')));
 if(!equal(key,qKey))throw new Error('DH key mismatch');
 const record=await seal(key,bytes('private prior session'));
 const leak='Later disclosure of P’s Ed25519 signing key does not reveal the erased ephemeral α, so these recorded u,v,signature,record bytes do not yield the old DH key.';
 const attackV=base.multiply(scalar()).toBytes(),impersonated=await kdf('AKE2eg/k',tuple('AKE2eg/DH',u,attackV,shared(attackV,alpha),bytes('R')));
 const ephemeral=`With α and P’s earlier valid signature on u, an adversary computes a fresh Q-side DH key ${await fingerprint(impersonated)} using a new v and reuses P’s signed u.`;
 return {ctx,alpha,u,v,signatureP,key,p:await fingerprint(key),q:await fingerprint(qKey),record,leak,ephemeral};
}

const certWire=(cert:Cert)=>concat(bytes(cert.id),cert.enc,cert.sig,cert.ca);
function parseCert(data:Uint8Array):Cert {
 if(data.length!==129)throw new Error('certificate byte length invalid');
 return {id:String.fromCharCode(data[0]),enc:data.slice(1,33),sig:data.slice(33,65),ca:data.slice(65,129)};
}
async function keys4(u:Uint8Array,v:Uint8Array,dh:Uint8Array):Promise<[Uint8Array,Uint8Array,Uint8Array]>{
 const block=await kdf('AKE4eg/k,k1,k2',tuple('AKE4eg/DH',u,v,dh),96);
 return [block.slice(0,32),block.slice(32,64),block.slice(64,96)];
}
export async function ake4(activeFake=false):Promise<{u:Uint8Array;v:Uint8Array;c1:{iv:Uint8Array;data:Uint8Array};c2?:{iv:Uint8Array;data:Uint8Array};partner?:string;reason:string;fingerprint?:string}>{
 const ctx=setup(),a=scalar(),b=scalar(),u=base.multiply(a).toBytes(),v=base.multiply(b).toBytes();
 const [qKey,q1,q2]=await keys4(u,v,shared(u,b));
 let cert=ctx.q.cert,signature=sign(ctx.q.signSecret,tuple('AKE4eg/Q/sig',bytes('1'),u,v));
 if(activeFake){
  // A fake responder can choose v and derive the keys, but cannot forge CA and Q signatures.
  cert={...ctx.q.cert,ca:ctx.q.cert.ca.slice()};cert.ca[0]^=1;
  signature=new Uint8Array(64);
 }
 const c1=await seal(q1,concat(signature,certWire(cert)));
 const [key,k1,k2]=await keys4(u,v,shared(v,a));
 if(!equal(qKey,key)||!equal(q1,k1)||!equal(q2,k2))throw new Error('AKE4 key mismatch');
 const decoded=await open(k1,c1),readCert=parseCert(decoded.slice(64));
 if(!ctx.ca.check(readCert))return {u,v,c1,reason:'Fake responder: certificate invalid; P aborted before c2 and kept its identity hidden.'};
 if(!verify(readCert.sig,tuple('AKE4eg/Q/sig',bytes('1'),u,v),decoded.slice(0,64)))return {u,v,c1,reason:'Q signature invalid; P aborted before c2.'};
 const sigP=sign(ctx.p.signSecret,tuple('AKE4eg/P/sig',bytes('2'),u,v));
 const c2=await seal(k2,concat(sigP,certWire(ctx.p.cert)));
 const other=await open(q2,c2),pCert=parseCert(other.slice(64));
 if(!ctx.ca.check(pCert)||!verify(pCert.sig,tuple('AKE4eg/P/sig',bytes('2'),u,v),other.slice(0,64)))throw new Error('P confirmation failed');
 return {u,v,c1,c2,partner:readCert.id,reason:'Both identities remained in AES-GCM ciphertext on the wire; the signed peers agreed.',fingerprint:await fingerprint(key)};
}

function addGroup(left:Uint8Array,right:Uint8Array):Uint8Array{return decode(left).add(decode(right)).toBytes()}
type Evidence={pubP:Uint8Array;pubQ:Uint8Array;mu:Uint8Array;nu:Uint8Array;key:Uint8Array;k1:Uint8Array;k2:Uint8Array;beta:bigint;nuSecret:bigint};
async function derive5(pubP:Uint8Array,pubQ:Uint8Array,mu:Uint8Array,nu:Uint8Array,dh1:Uint8Array,dh2:Uint8Array):Promise<[Uint8Array,Uint8Array,Uint8Array]>{
 const key=await kdf('AKE5/H',tuple('AKE5/inputs',dh1,dh2,pubP,mu,pubQ,nu,bytes('P'),bytes('Q')),96);
 return [key.slice(0,32),key.slice(32,64),key.slice(64)];
}
async function evidence(ctx:Context,muSecret:bigint,nuSecret:bigint):Promise<Evidence>{
 const pubP=ctx.p.cert.enc,pubQ=ctx.q.cert.enc,mu=base.multiply(muSecret).toBytes(),nu=base.multiply(nuSecret).toBytes();
 const dh1=decode(addGroup(pubP,mu)).multiply((ctx.q.encSecret+nuSecret)%ORDER).toBytes();
 const dh2=shared(mu,nuSecret),[key,k1,k2]=await derive5(pubP,pubQ,mu,nu,dh1,dh2);
 return {pubP,pubQ,mu,nu,key,k1,k2,beta:ctx.q.encSecret,nuSecret};
}
export async function ake5():Promise<{real:Evidence;fabricated:Evidence;realPass:boolean;fabricatedPass:boolean;fingerprints:[string,string]}> {
 const ctx=setup(),muSecret=scalar(),nuSecret=scalar(),real=await evidence(ctx,muSecret,nuSecret);
 // P independently computes both terms, then checks Q's k1 before replying with k2.
 const pDh1=decode(addGroup(real.pubQ,real.nu)).multiply((ctx.p.encSecret+muSecret)%ORDER).toBytes();
 const pDh2=shared(real.nu,muSecret),[pk,pk1,pk2]=await derive5(real.pubP,real.pubQ,real.mu,real.nu,pDh1,pDh2);
 const realPass=equal(pk,real.key)&&equal(pk1,real.k1)&&equal(pk2,real.k2);
 // Q chooses its own mu: no query or message from P is used in this fabricated transcript.
 const fabricated=await evidence(ctx,scalar(),scalar());
 const qJudge=async(e:Evidence)=>{
  const dh1=decode(addGroup(e.pubP,e.mu)).multiply((e.beta+e.nuSecret)%ORDER).toBytes();
  const dh2=shared(e.mu,e.nuSecret),[k,k1,k2]=await derive5(e.pubP,e.pubQ,e.mu,e.nu,dh1,dh2);
  return equal(k,e.key)&&equal(k1,e.k1)&&equal(k2,e.k2);
 };
 return {real,fabricated,realPass:realPass&&await qJudge(real),fabricatedPass:await qJudge(fabricated),fingerprints:[await fingerprint(real.key),await fingerprint(fabricated.key)]};
}
