import {base,decode,scalar,shared,ORDER} from '../group/ristretto';
import {bytes,equal,tuple} from '../encode';
import {fingerprint,kdf} from '../crypto';
import {setup} from './ake1';
function addGroup(left:Uint8Array,right:Uint8Array):Uint8Array{return decode(left).add(decode(right)).toBytes()}
type Evidence={pubP:Uint8Array;pubQ:Uint8Array;mu:Uint8Array;nu:Uint8Array;key:Uint8Array;k1:Uint8Array;k2:Uint8Array;beta:bigint;nuSecret:bigint};
async function derive5(pubP:Uint8Array,pubQ:Uint8Array,mu:Uint8Array,nu:Uint8Array,dh1:Uint8Array,dh2:Uint8Array):Promise<[Uint8Array,Uint8Array,Uint8Array]>{
 const key=await kdf('AKE5/H',tuple('AKE5/inputs',dh1,dh2,pubP,mu,pubQ,nu,bytes('P'),bytes('Q')),96);
 return [key.slice(0,32),key.slice(32,64),key.slice(64)];
}
async function evidence(pubP:Uint8Array,pubQ:Uint8Array,beta:bigint,muSecret:bigint,nuSecret:bigint):Promise<Evidence>{
 const mu=base.multiply(muSecret).toBytes(),nu=base.multiply(nuSecret).toBytes();
 const dh1=decode(addGroup(pubP,mu)).multiply((beta+nuSecret)%ORDER).toBytes();
 const dh2=shared(mu,nuSecret),[key,k1,k2]=await derive5(pubP,pubQ,mu,nu,dh1,dh2);
 return {pubP,pubQ,mu,nu,key,k1,k2,beta,nuSecret};
}
export async function ake5():Promise<{real:Evidence;fabricated:Evidence;realPass:boolean;fabricatedPass:boolean;fingerprints:[string,string]}> {
 const ctx=setup(),muSecret=scalar(),nuSecret=scalar(),real=await evidence(ctx.p.cert.enc,ctx.q.cert.enc,ctx.q.encSecret,muSecret,nuSecret);
 // P independently computes both terms, then checks Q's k1 before replying with k2.
 const pDh1=decode(addGroup(real.pubQ,real.nu)).multiply((ctx.p.encSecret+muSecret)%ORDER).toBytes();
 const pDh2=shared(real.nu,muSecret),[pk,pk1,pk2]=await derive5(real.pubP,real.pubQ,real.mu,real.nu,pDh1,pDh2);
 const realPass=equal(pk,real.key)&&equal(pk1,real.k1)&&equal(pk2,real.k2);
 // Q chooses its own mu: no query or message from P is used in this fabricated transcript.
 const fabricated=await evidence(ctx.p.cert.enc,ctx.q.cert.enc,ctx.q.encSecret,scalar(),scalar());
 const qJudge=async(e:Evidence)=>{
  const dh1=decode(addGroup(e.pubP,e.mu)).multiply((e.beta+e.nuSecret)%ORDER).toBytes();
  const dh2=shared(e.mu,e.nuSecret),[k,k1,k2]=await derive5(e.pubP,e.pubQ,e.mu,e.nu,dh1,dh2);
  return equal(k,e.key)&&equal(k1,e.k1)&&equal(k2,e.k2);
 };
 return {real,fabricated,realPass:realPass&&await qJudge(real),fabricatedPass:await qJudge(fabricated),fingerprints:[await fingerprint(real.key),await fingerprint(fabricated.key)]};
}
