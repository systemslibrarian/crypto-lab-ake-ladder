import {kdf,open,type Sealed} from '../crypto';
import {tuple,hex} from '../encode';
export type Recording={u:Uint8Array;v:Uint8Array;signatureP:Uint8Array;record:Sealed};
/** These are finite executable probes, not a computational-security proof. */
export async function signingLeak(recording:Recording,leakedSigningKey:Uint8Array){
 const candidates=[leakedSigningKey,await kdf('AKE2eg/k',leakedSigningKey),await kdf('AKE2eg/k',tuple('AKE2eg/leak-probe',recording.u,recording.v,leakedSigningKey))];
 const probes=[];
 for(const key of candidates){let plaintext:string|null=null;try{plaintext=new TextDecoder().decode(await open(key,recording.record))}catch{}
 probes.push({candidate:hex(key),accepted:plaintext!==null,plaintext});}
 return {leakedSigningKey:hex(leakedSigningKey),probes,opened:probes.some(p=>p.accepted)};
}
