import {bytes,concat,hex,tuple} from '../encode';
import {fingerprint,seal,open} from '../crypto';
import {encrypt,encodeCipher} from '../pke/eeg';
import {sign} from '../sig/ed25519';
import {first,finish,respond,setup,signatureInput,type Response,type Start} from '../ake/ake1';
import {HONEST,VARIANTS,type Definition} from '../ake/variants';
export type Outcome={id:number;name:string;class:string;p?:{partner:string;fingerprint:string;binding:string};q:{partner:string;fingerprint:string;binding:string};attacker:string;effect:string;restored:string;cipher?:{before:Uint8Array;after:Uint8Array}};
const responseAs=(original:Response,cert:Response['cert'],signature:Uint8Array,cipher=original.cipher):Response=>({...original,cert,signature,cipher});
const signAs=(def:Definition,start:Start,response:Response,party:{signSecret:Uint8Array},idP='P')=>sign(party.signSecret,signatureInput(def,start,response.cipher,idP));
export async function runVariation(id:number):Promise<Outcome>{
 const def=VARIANTS.find(v=>v.id===id);if(!def)throw new RangeError('Choose a variation 1–6');
 const ctx=setup(),old=first(ctx.p),original=await respond(def,old,ctx.q,ctx.ca);
 const sameKey=await fingerprint(original.key);
 let start=old,modified=original,attacker='Does not learn the shared key',effect='';
 if(id===1){
  const ownKey=new Uint8Array(32);crypto.getRandomValues(ownKey);
  modified=responseAs(original,ctx.q.cert,original.signature,await encrypt(ctx.p.cert.enc,concat(ownKey,bytes('Q'))));
  const record=await seal(ownKey,bytes('bank transfer'));
  const stolen=await open(ownKey,record);
  attacker=`Chose key ${await fingerprint(ownKey)} and read P's first AES-GCM record: ${new TextDecoder().decode(stolen)}`;
  effect='P accepted a key chosen by the adversary; Q kept a different key.';
 }else if(id===2){start=first(ctx.p);effect='Recorded reply replayed into a new P session; old key accepted again.';
 }else if(id===3){
  const certR=ctx.ca.register('R',ctx.p.cert.enc,ctx.r.cert.sig,{requirePoP:false});
  original.peer='R';start=old;
  // Q actually received R's certificate with P's encryption public key.
  const sentToQ={...old,cert:certR};modified=await respond(def,sentToQ,ctx.q,ctx.ca);
  effect='P thinks Q; Q thinks R. The key is shared and unknown to the adversary.';
 }else if(id===4||id===5){
  if(id===4)start=first(ctx.p);
  modified=responseAs(original,ctx.r.cert,signAs(def,start,original,ctx.r));
  effect=id===4?'R re-signed a recorded ciphertext for a fresh nonce; P reused the old key and named R.':'R re-signed Q’s ciphertext; P named R while Q named P.';
 }else {
  start=first(ctx.p);
  const cipher={...original.cipher,box:{...original.cipher.box,data:original.cipher.box.data.slice()}};
  cipher.box.data[32]^=bytes('Q')[0]^bytes('R')[0];
  modified=responseAs(original,ctx.r.cert,new Uint8Array(),cipher);
  modified.signature=signAs(def,start,modified,ctx.r);
  effect='CTR’s identity byte changed Q→R without decrypting; R re-signed the changed ciphertext for the new session.';
 }
 const p=await finish(def,start,modified,ctx.p,ctx.ca);
 const qBind=hex(tuple('AKE1/channel-binding',bytes(original.peer),bytes('Q'),old.r,encodeCipher(id===3?modified.cipher:original.cipher)));
 const outcome:Outcome={id,name:def.name,class:def.class,p:{partner:p.partner,fingerprint:p.fingerprint,binding:p.binding},q:{partner:original.peer,fingerprint:id===3?await fingerprint(modified.key):sameKey,binding:qBind},attacker,effect,restored:''};
 if(id===6)outcome.cipher={before:original.cipher.box.data.slice(32,33),after:modified.cipher.box.data.slice(32,33)};
 // Run the same network edit under honest AKE1. All checks are actually performed by finish().
 const fixed=setup(),firstFixed=first(fixed.p),reply=await respond(HONEST,firstFixed,fixed.q,fixed.ca);
 let altered=reply,initial=firstFixed;
 if(id===1)altered=responseAs(reply,reply.cert,reply.signature,await encrypt(fixed.p.cert.enc,concat(new Uint8Array(32),bytes('Q'))));
 if(id===2)initial=first(fixed.p);
 if(id===3){
  const certR=fixed.ca.register('R',fixed.p.cert.enc,fixed.r.cert.sig);
  altered=await respond(HONEST,{...firstFixed,cert:certR},fixed.q,fixed.ca);
 }
 if(id===4||id===5){if(id===4)initial=first(fixed.p);altered=responseAs(reply,fixed.r.cert,new Uint8Array());altered.signature=signAs(HONEST,initial,altered,fixed.r)}
 if(id===6){initial=first(fixed.p);const c={...reply.cipher,box:{...reply.cipher.box,data:reply.cipher.box.data.slice()}};c.box.data[32]^=bytes('Q')[0]^bytes('R')[0];altered=responseAs(reply,fixed.r.cert,new Uint8Array(),c);altered.signature=signAs(HONEST,initial,altered,fixed.r)}
 try{await finish(HONEST,initial,altered,fixed.p,fixed.ca);outcome.restored='Unexpected accept — test must fail'}catch(error){outcome.restored=String(error)}
 return outcome;
}
