import {v1} from './v1';import {v2} from './v2';import {v4} from './v4';import {v5} from './v5';import {v6} from './v6';
import type {PublicAttack,Edit} from './wire';
export async function editWire(id:number,wire:PublicAttack):Promise<Edit>{
 switch(id){case 1:return v1(wire);case 2:return v2(wire);case 3:return {start:wire.start,reply:wire.reply};case 4:return v4(wire);case 5:return v5(wire);case 6:return v6(wire);default:throw Error('Unknown attack')}
}
