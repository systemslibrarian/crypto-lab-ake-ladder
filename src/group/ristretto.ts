import {ristretto255} from '@noble/curves/ed25519.js';
export const ORDER=(1n<<252n)+27742317777372353535851937790883648493n;
export type Point=InstanceType<typeof ristretto255.Point>;
export const base=ristretto255.Point.BASE;
export function scalar():bigint{
 const random=crypto.getRandomValues(new Uint8Array(32));let n=0n;for(let i=31;i>=0;i--)n=(n<<8n)|BigInt(random[i]);return n%(ORDER-1n)+1n;
}
export function decode(input:Uint8Array):Point {
 if(input.length!==32)throw new RangeError('Group element must be 32 bytes');
 try{return ristretto255.Point.fromBytes(input)}catch{throw new RangeError('v ∉ G (canonical decode rejected)')}
}
export function shared(point:Uint8Array,secret:bigint):Uint8Array{return decode(point).multiply(secret).toBytes()}
export const generator=()=>base.multiply(scalar()).toBytes();

