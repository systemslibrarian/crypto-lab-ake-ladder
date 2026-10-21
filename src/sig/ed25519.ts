import {ed25519} from '@noble/curves/ed25519.js';
export const keypair=()=>ed25519.keygen();
export const sign=(key:Uint8Array,message:Uint8Array)=>ed25519.sign(message,key);
export const verify=(pub:Uint8Array,message:Uint8Array,sig:Uint8Array)=>{try{return ed25519.verify(sig,message,pub,{zip215:false})}catch{return false}};

