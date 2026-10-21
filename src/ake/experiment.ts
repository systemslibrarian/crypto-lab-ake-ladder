import {bytes,hex} from '../encode';
import {fingerprint} from '../crypto';
import {sealRecord,openRecord} from '../record/aead';
import {first,finish,respond,setup,wire,responderView,type View} from './ake1';
import {HONEST,VARIANTS,type Definition} from './variants';
import {sign} from '../sig/ed25519';
import {editWire} from '../attack/variations';
import {replaceCertificate} from '../attack/v3';
import type {Start,Reply} from '../attack/wire';
export type Evidence={p:ReturnType<typeof inspect>;q:ReturnType<typeof inspect>;pWire:ReturnType<typeof wireEvidence>;qWire:ReturnType<typeof wireEvidence>;record?:{iv:string;data:string;origin:string;opened:string;chosenKey?:string};cipher?:{before:string;after:string}};
function inspect(v:View){return {partner:v.partner,key:hex(v.key),fingerprint:v.fingerprint,binding:v.binding}}
function wireEvidence(p:string,q:string,start:Start,reply:Reply){return {p,q,r:hex(start.r),v:hex(reply.cipher.v),iv:hex(reply.cipher.box.iv),data:hex(reply.cipher.box.data)}}
async function session(id:number,definition:Definition){
 const ctx=setup(),start=first(ctx.p),freshStart=first(ctx.p);
 const sent=id===3?replaceCertificate(start,ctx.ca.register('R',ctx.p.cert.enc,ctx.r.cert.sig,{requirePoP:false})):start;
 const response=await respond(definition,sent,ctx.q,ctx.ca),q=await responderView(sent,response,ctx.q);
 const edit=await editWire(id,{definition,start,freshStart,reply:wire(response),receiverPublic:ctx.p.cert.enc,corruptCert:ctx.r.cert,signCorrupt:m=>sign(ctx.r.signSecret,m)});
 // finish consumes wire fields; key/peer are never trusted from the network.
 const p=await finish(definition,edit.start,{...edit.reply,key:new Uint8Array(),peer:''},ctx.p,ctx.ca);
 const evidence:Evidence={p:inspect(p),q:inspect(q),pWire:wireEvidence('P',edit.reply.cert.id,edit.start,edit.reply),qWire:wireEvidence(sent.cert.id,'Q',sent,response)};
 let attacker='Does not learn the shared key';
 if(id===1){
  const origin='P application record for nonce '+hex(edit.start.r);
  const record=await sealRecord(p.key,bytes(origin));
  const opened=new TextDecoder().decode(await openRecord(edit.chosenKey!,record));
  evidence.record={iv:hex(record.iv),data:hex(record.data),origin,opened,chosenKey:hex(edit.chosenKey!)};
  attacker=`Chose key ${await fingerprint(edit.chosenKey!)} and decrypted P's accepted-key record: ${opened}`;
 }
 if(id===2||id===4||id===6){
  const oldView=await finish(definition,start,response,ctx.p,ctx.ca),origin='P recorded transfer '+hex(start.r),record=await sealRecord(oldView.key,bytes(origin));
  const opened=new TextDecoder().decode(await openRecord(p.key,record));
  evidence.record={iv:hex(record.iv),data:hex(record.data),origin,opened};
 }
 if(edit.before&&edit.after)evidence.cipher={before:hex(edit.before),after:hex(edit.after)};
 return {p,q,attacker,evidence};
}
export async function runVariation(id:number){
 const def=VARIANTS.find(v=>v.id===id);if(!def)throw Error('Choose V1–V6');
 const r=await session(id,def);let restored='Unexpected accept — test must fail';
 try{await session(id,HONEST)}catch(e){restored=String(e)}
 const effects=['','P accepted the adversary’s key; Q retained its own.','A fresh P session accepted the old key and opened a replayed application record.','P thinks Q; honest Q returned R. Their keys match but their bindings differ.','A fresh P session named R and reopened an old application record.','P named R while Q named P. Their keys match but their bindings differ.','The attacker changed the CTR identity byte and re-signed as R; a fresh P session accepted the old key and reopened an old application record.'];
 return {id,name:def.name,class:def.class,p:{partner:r.p.partner,fingerprint:r.p.fingerprint,binding:r.p.binding},q:{partner:r.q.partner,fingerprint:r.q.fingerprint,binding:r.q.binding},attacker:r.attacker,effect:effects[id],restored,evidence:r.evidence,cipher:r.evidence.cipher?{before:Uint8Array.from([parseInt(r.evidence.cipher.before,16)]),after:Uint8Array.from([parseInt(r.evidence.cipher.after,16)])}:undefined};
}
export {inspect,wireEvidence};
