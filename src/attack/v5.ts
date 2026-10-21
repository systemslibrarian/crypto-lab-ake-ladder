import {resign} from './resign';
import type {PublicAttack,Edit} from './wire';
export const v5=(w:PublicAttack):Edit=>{const start=w.start;return {start,reply:resign(w,start,w.reply)}};
