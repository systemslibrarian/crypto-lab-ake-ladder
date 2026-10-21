import {describe,it,expect} from 'vitest';
import {ristretto255,ed25519} from '@noble/curves/ed25519.js';
import {base,decode} from '../group/ristretto';
import {kdf,open,seal} from '../crypto';
import {honest} from './ake1';
import {runVariation} from '../attack/variations';
import {ake2,ake4,ake5} from './advanced';

describe('published primitive behavior',()=>{
 it('RFC 9496 generator and invalid encoding',()=>{
  expect(Buffer.from(base.toBytes()).toString('hex')).toBe('e2f2ae0a6abc4e71a884a961c500515f58e30b6aa582dd8db6a65945e08d2d76');
  expect(()=>decode(new Uint8Array(32).fill(0xff))).toThrow(/canonical/);
  expect(ristretto255.Point.fromBytes(base.toBytes()).equals(base)).toBe(true);
 });
 it('RFC 8032 Ed25519 test 1 and AES-GCM tamper rejection',async()=>{
  const key=Buffer.from('9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60','hex');
  expect(Buffer.from(ed25519.sign(new Uint8Array(),key)).toString('hex')).toBe('e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b');
  const box=await seal(new Uint8Array(32),new TextEncoder().encode('record'));
  expect(new TextDecoder().decode(await open(new Uint8Array(32),box))).toBe('record');
  const corrupt={iv:box.iv,data:box.data.slice()};corrupt.data[0]^=1;
  await expect(open(new Uint8Array(32),corrupt)).rejects.toThrow(/decryption failed/);
 });
 it('HKDF output is stable and length-bounded',async()=>{
  const a=await kdf('test/domain',new Uint8Array(80).fill(0xab),82);
  expect(a).toHaveLength(82);expect(a).toEqual(await kdf('test/domain',new Uint8Array(80).fill(0xab),82));
  expect(a).not.toEqual(await kdf('test/other',new Uint8Array(80).fill(0xab),82));
 });
});
describe('AKE1 fields and actual scripted attacks',()=>{
 it('honest peers agree on key, name and binding',async()=>{
  const result=await honest();expect(result.p.fingerprint).toBe(result.q.fingerprint);
  expect(result.p.partner).toBe('Q');expect(result.q.partner).toBe('P');
  expect(result.p.binding).toBe(result.q.binding);
 });
 it.each([1,2,3,4,5,6])('variation %i succeeds, but the same network edit fails with fields restored',async id=>{
  const result=await runVariation(id);
  expect(result.p).toBeDefined();expect(result.restored).not.toMatch(/Unexpected accept/);
  expect(result.restored).toMatch(/signature verification|decrypted identity|decryption failed/);
  if(id===1)expect(result.p?.fingerprint).not.toBe(result.q.fingerprint);
  if(id===3||id===5){expect(result.p?.partner).not.toBe(result.q.partner);expect(result.p?.fingerprint).toBe(result.q.fingerprint)}
  if(id===6)expect(result.cipher?.before[0]!^result.cipher!.after[0]).toBe('Q'.charCodeAt(0)^'R'.charCodeAt(0));
 });
});
describe('AKE2eg, AKE4eg, AKE5',()=>{
 it('ephemeral DH agrees; a later signing-key leak does not decrypt the record',async()=>{const r=await ake2();expect(r.p).toBe(r.q);await expect(open(new Uint8Array(32),r.record)).rejects.toThrow(/decryption failed/)});
 it('identity-protected AKE4 checks Q before sending c2',async()=>{
  const good=await ake4(),fake=await ake4(true);
  expect(good.partner).toBe('Q');expect(good.c2).toBeDefined();
  expect(fake.c2).toBeUndefined();expect(fake.reason).toMatch(/certificate invalid/);
 });
 it('AKE5 real and Q-alone fabricated transcripts pass the same key consistency check',async()=>{
  const r=await ake5();expect(r.realPass).toBe(true);expect(r.fabricatedPass).toBe(true);
 });
});
