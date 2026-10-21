import {it,expect,vi} from 'vitest';
import {ristretto255,ed25519} from '@noble/curves/ed25519.js';
import {base,decode} from '../group/ristretto';
import {hkdf,seal,open} from '../crypto';
import {ctrEncrypt} from '../pke/eeg-ctr';
import vectors from './vectors.json';
const b=(s:string)=>Uint8Array.from(Buffer.from(s,'hex'));
const h=(v:Uint8Array)=>Buffer.from(v).toString('hex');
it.each(vectors.generator.map((v,i)=>[i,v] as const))('RFC 9496 A.1 B[%i] canonical encoding',(i,v)=>{
 const point=i===0?ristretto255.Point.ZERO:base.multiply(BigInt(i));expect(h(point.toBytes())).toBe(v);expect(decode(b(v)).equals(point)).toBe(true);
});
it.each(vectors.invalid.map((v,i)=>[i,v] as const))('RFC 9496 A.2 invalid encoding %i rejects',(_i,v)=>{expect(()=>decode(b(v))).toThrow()});
it.each(vectors.ed25519)('RFC 8032 section 7.1 $name',v=>{
 expect(h(ed25519.getPublicKey(b(v['SECRET KEY'])))).toBe(v['PUBLIC KEY']);
 expect(h(ed25519.sign(b(v.MESSAGE),b(v['SECRET KEY'])))).toBe(v.SIGNATURE);
 expect(ed25519.verify(b(v.SIGNATURE),b(v.MESSAGE),b(v['PUBLIC KEY']))).toBe(true);
 const corrupt=b(v.SIGNATURE);corrupt[0]^=1;expect(ed25519.verify(corrupt,b(v.MESSAGE),b(v['PUBLIC KEY']))).toBe(false);
});
it.each(vectors.hkdf.map((v,i)=>({case:i+1,...v})))('RFC 5869 A.$case HKDF known answer',async v=>{
 expect(h(await hkdf(b(v.IKM),b(v.salt),b(v.info),v.L))).toBe(v.OKM);
});
it('NIST SP 800-38A F.5.1 CTR four-block known answer',async()=>{
 const v=vectors.ctr;expect(h(await ctrEncrypt(b(v.Key),b(v.counter),b(v.Plaintext)))).toBe(v.Ciphertext);
});
it('NIST AES-GCM AES256 Example 2 four-block ciphertext and tag',async()=>{
 const v=vectors.gcm;
 const rng=vi.spyOn(crypto,'getRandomValues').mockImplementation(((array:Uint8Array)=>{array.set(b(v.IV));return array}) as typeof crypto.getRandomValues);
 try{const record=await seal(b(v.K),b(v.P));expect(h(record.iv)).toBe(v.IV);expect(h(record.data)).toBe(v.C+v.Tag);expect(h(await open(b(v.K),record))).toBe(v.P)}finally{rng.mockRestore()}
});
