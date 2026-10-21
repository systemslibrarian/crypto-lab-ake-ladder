import {base,scalar,shared} from '../group/ristretto';
import {bytes,equal,tuple} from '../encode';
import {fingerprint,kdf,seal,open} from '../crypto';
import {sign,verify} from '../sig/ed25519';
import {setup,type Context} from './ake1';
import type {Cert} from '../ca/ca';
import {signingLeak} from '../attack/pfs';
import {ephemeralKey} from '../attack/ephemeral';
const sig2=(role:string,...fields:Uint8Array[])=>tuple(`AKE2eg/${role}`, ...fields);
// This responder owns beta and its private state; the adversary only receives the reply.
export async function answer2(start:{u:Uint8Array;signature:Uint8Array;cert:Cert},ctx:Context){
 if(!ctx.ca.check(start.cert)||!verify(start.cert.sig,sig2('P',start.u),start.signature))throw Error('P certificate or signature failed');
 const beta=scalar(),v=base.multiply(beta).toBytes();
 const key=await kdf('AKE2eg/k',tuple('AKE2eg/DH',start.u,v,shared(start.u,beta),bytes(ctx.q.id)));
 const signature=sign(ctx.q.signSecret,sig2('Q',start.u,v,bytes(start.cert.id)));
 return {key,partner:start.cert.id,reply:{v,signature,cert:ctx.q.cert}};
}
export async function ake2(){
 const ctx=setup();let alpha=scalar();const u=base.multiply(alpha).toBytes(),signatureP=sign(ctx.p.signSecret,sig2('P',u));
 const q=await answer2({u,signature:signatureP,cert:ctx.p.cert},ctx),v=q.reply.v;
 if(!ctx.ca.check(q.reply.cert)||!verify(q.reply.cert.sig,sig2('Q',u,v,bytes('P')),q.reply.signature))throw Error('Q certificate or signature failed');
 const key=await kdf('AKE2eg/k',tuple('AKE2eg/DH',u,v,shared(v,alpha),bytes('Q')));
 if(!equal(key,q.key))throw Error('DH key mismatch');
 const record=await seal(key,bytes('private prior session'));
 alpha=0n; // The after-the-fact leak probe receives no ephemeral scalar or session key.
 const leak=await signingLeak({u,v,signatureP,record},ctx.p.signSecret.slice());
 return {u,v,certP:ctx.p.cert,certQ:ctx.q.cert,signatureP,key,p:await fingerprint(key),q:await fingerprint(q.key),record,leak,ephemeralErased:alpha===0n};
}
export async function ephemeralLeak(){
 const ctx=setup(),alpha=scalar(),u=base.multiply(alpha).toBytes(),signatureP=sign(ctx.p.signSecret,sig2('P',u));
 // A recorded signed u is replayed to a new honest Q instance with fresh beta.
 const original=await answer2({u,signature:signatureP,cert:ctx.p.cert},ctx);
 const fresh=await answer2({u,signature:signatureP,cert:ctx.p.cert},ctx);
 const candidate=await ephemeralKey(alpha,u,fresh.reply.v,'Q');
 const record=await seal(candidate,bytes('adversary completed a new session as P'));
 let accepted=false;try{accepted=new TextDecoder().decode(await open(fresh.key,record))==='adversary completed a new session as P'}catch{}
 return {accepted,partner:fresh.partner,attackerKey:candidate,qKey:fresh.key,u,v:fresh.reply.v,oldV:original.reply.v,signatureP};
}
