import {shared} from '../group/ristretto';
import {kdf} from '../crypto';
import {tuple,bytes} from '../encode';
export async function ephemeralKey(alpha:bigint,u:Uint8Array,v:Uint8Array,responder:string){
 return kdf('AKE2eg/k',tuple('AKE2eg/DH',u,v,shared(v,alpha),bytes(responder)));
}
