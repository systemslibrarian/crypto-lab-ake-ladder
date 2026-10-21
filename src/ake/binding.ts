import {bytes,hex,tuple} from '../encode';
import {encodeCipher,type Cipher} from '../pke/eeg';
export function binding(p:string,q:string,r:Uint8Array,cipher:Cipher):string {
 return hex(tuple('AKE1/channel-binding',bytes(p),bytes(q),r,encodeCipher(cipher)));
}
