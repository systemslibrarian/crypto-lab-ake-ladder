import type {PublicAttack,Edit} from './wire';
export const v2=(w:PublicAttack):Edit=>({start:w.freshStart,reply:w.reply});
