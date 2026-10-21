import type {Start} from './wire';
import type {Cert} from '../ca/ca';
// R's CA-certified identity carries P's public encryption key, without proof of possession.
export const replaceCertificate=(start:Start,cert:Cert):Start=>({...start,cert:cert.id==='R'?cert:start.cert});
