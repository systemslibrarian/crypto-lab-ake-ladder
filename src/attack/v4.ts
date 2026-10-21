import {resign} from './resign';
import type {PublicAttack,Edit} from './wire';
export const v4=(w:PublicAttack):Edit=>{const start=w.freshStart;return {start,reply:resign(w,start,w.reply)}};
