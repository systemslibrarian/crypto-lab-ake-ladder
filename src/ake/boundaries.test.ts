import {it,expect} from 'vitest';
import {readFileSync,readdirSync} from 'node:fs';
import {fileURLToPath} from 'node:url';
import {honest,wire,setup,first,respond,finish} from './ake1';
import {HONEST} from './variants';
import {decrypt} from '../pke/eeg';
import {seal,open} from '../crypto';
import {bytes,hex} from '../encode';
import {signingLeak} from '../attack/pfs';
import {runVariation} from './experiment';
import {ephemeralLeak} from './ake2eg';
import {fabrication4} from './fabrication';
it('adversaries import only public primitives and never honest state',()=>{
 const root=fileURLToPath(new URL('../attack/',import.meta.url));
 for(const name of readdirSync(root).filter(n=>n.endsWith('.ts'))){const source=readFileSync(root+name,'utf8');expect(source).not.toMatch(/import[^;]*(?:ake1|ake2eg|ake4eg|ake5|experiment)/);expect(source).not.toMatch(/\b(?:setup|Context|Party|encSecret|signSecret)\b/)}
});
it('the public reply omits keys and cannot alias honest state',async()=>{
 const h=await honest(),w=wire(h.response);expect(Object.keys(w).sort()).toEqual(['cert','cipher','signature']);const original=h.response.cipher.box.data[0];w.cipher.box.data[0]^=1;expect(h.response.cipher.box.data[0]).toBe(original);
});
it('V1 opens a record authored by P under the key P accepted',async()=>{
 const r=await runVariation(1),e=r.evidence;expect(e.p.key).toBe(e.record!.chosenKey);expect(e.p.key).not.toBe(e.q.key);expect(e.record!.origin).toBe('P application record for nonce '+e.pWire.r);expect(e.record!.opened).toBe(e.record!.origin);
});
it('AKE1 later decryption-key leak recovers the authenticated recorded message',async()=>{
 const h=await honest(),record=await seal(h.p.key,bytes('private prior session'));
 const recovered=(await decrypt(h.ctx.p.encSecret,h.response.cipher)).slice(0,32);
 expect(new TextDecoder().decode(await open(recovered,record))).toBe('private prior session');
});
it('PFS leak oracle catches a session deliberately keyed with the signing secret',async()=>{
 const leaked=crypto.getRandomValues(new Uint8Array(32));const record=await seal(leaked,bytes('broken PFS'));
 const r=await signingLeak({u:new Uint8Array(32),v:new Uint8Array(32),signatureP:new Uint8Array(64),record},leaked);
 expect(r.opened).toBe(true);expect(r.probes[0].plaintext).toBe('broken PFS');
});
it('ephemeral alpha leak completes a new session accepted by honest Q',async()=>{
 const r=await ephemeralLeak();expect(r.accepted).toBe(true);expect(r.partner).toBe('P');expect(hex(r.v)).not.toBe(hex(r.oldV));expect(r.attackerKey).toEqual(r.qKey);
});
it('AKE4 forgery replays a genuine prior signature and is rejected on fresh DH values',async()=>{
 const r=await fabrication4();expect(r.originalValid).toBe(true);expect(r.forgedValid).toBe(false);expect(r.newU).not.toEqual(r.oldU);expect(r.newV).not.toEqual(r.oldV);
});
it('certificate and AEAD damage abort without partial session views',async()=>{
 const ctx=setup(),start=first(ctx.p),r=await respond(HONEST,start,ctx.q,ctx.ca);
 const cert=structuredClone(r);cert.cert.ca[0]^=1;await expect(finish(HONEST,start,cert,ctx.p,ctx.ca)).rejects.toThrow('certificate invalid');
 const damaged=structuredClone(r.cipher);damaged.box.data[0]^=1;await expect(decrypt(ctx.p.encSecret,damaged)).rejects.toThrow('decryption failed');
});
