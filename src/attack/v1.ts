import {encrypt} from '../pke/eeg';
import {bytes,concat} from '../encode';
import {randomBytes} from '../crypto';
import type {PublicAttack,Edit} from './wire';
export async function v1(w:PublicAttack):Promise<Edit>{
 const chosenKey=randomBytes(32);
 return {start:w.start,reply:{...w.reply,cipher:await encrypt(w.receiverPublic,concat(chosenKey,bytes('Q')))},chosenKey};
}
