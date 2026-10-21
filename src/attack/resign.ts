import {tuple,bytes} from '../encode';
import {encodeCipher} from '../pke/eeg';
import type {PublicAttack,Start,Reply} from './wire';
export function resign(w:PublicAttack,start:Start,reply:Reply):Reply {
 const d=w.definition;
 const message=tuple(`AKE1/V${d.id}/sig`,...(d.omitR?[]:[start.r]),...(d.omitC?[]:[encodeCipher(reply.cipher)]),...(d.omitIdP?[]:[bytes('P')]));
 return {...reply,cert:w.corruptCert,signature:w.signCorrupt(message)};
}
