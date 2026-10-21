import {verify} from '../sig/ed25519';
import {tuple,bytes} from '../encode';
export function replaySignature(publicP:Uint8Array,signature:Uint8Array,u:Uint8Array,v:Uint8Array){
 return verify(publicP,tuple('AKE4eg/P/sig',bytes('2'),u,v),signature);
}
