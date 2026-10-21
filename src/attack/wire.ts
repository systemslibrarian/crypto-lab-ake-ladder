import type {Cert} from '../ca/ca';
import type {Cipher} from '../pke/eeg';
import type {Definition} from '../ake/variants';
export type Start={r:Uint8Array;cert:Cert};
export type Reply={cipher:Cipher;signature:Uint8Array;cert:Cert};
export type PublicAttack={definition:Definition;start:Start;freshStart:Start;reply:Reply;receiverPublic:Uint8Array;corruptCert:Cert;signCorrupt:(message:Uint8Array)=>Uint8Array};
export type Edit={start:Start;reply:Reply;chosenKey?:Uint8Array;before?:Uint8Array;after?:Uint8Array};
