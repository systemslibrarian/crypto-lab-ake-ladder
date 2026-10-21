import {ake4} from './ake4eg';
import {generator} from '../group/ristretto';
import {replaySignature} from '../attack/fabricate';
export async function fabrication4(){
 const recorded=await ake4(),newU=generator(),newV=generator();
 if(!recorded.signatureP||!recorded.publicP)throw Error('No authenticated prior transcript');
 return {publicP:recorded.publicP,signature:recorded.signatureP,oldU:recorded.u,oldV:recorded.v,newU,newV,originalValid:replaySignature(recorded.publicP,recorded.signatureP,recorded.u,recorded.v),forgedValid:replaySignature(recorded.publicP,recorded.signatureP,newU,newV)};
}
