import {bytes} from '../encode';
import {resign} from './resign';
import type {PublicAttack,Edit} from './wire';
export function v6(w:PublicAttack):Edit {
 const reply=structuredClone(w.reply),before=reply.cipher.box.data.slice(32,33);
 reply.cipher.box.data[32]^=bytes('Q')[0]^bytes('R')[0];
 return {start:w.freshStart,reply:resign(w,w.freshStart,reply),before,after:reply.cipher.box.data.slice(32,33)};
}
