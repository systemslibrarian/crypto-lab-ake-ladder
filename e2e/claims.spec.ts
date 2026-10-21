import {test,expect,type Page} from '@playwright/test';
import {binding,fingerprint,decrypt,ake1LeakedKey,tuple,unhex,sig,ake5Keys} from './reference';
async function run(page:Page,button:string,out:string){
 await page.locator(button).click();
 await expect.poll(()=>page.locator(out).innerText()).not.toMatch(/^(?:No session|No transcript|No identity|Select V|Recording|Generating|Running|Replaying)/);
 const text=await page.locator(out).innerText();expect(text).not.toMatch(/^(?:Abort|Experiment failed|Error|Attack failed)/);return text;
}
async function evidence(page:Page,id:string){const pre=page.locator(`[data-evidence="${id}"]`);expect(await pre.count()).toBe(1);return JSON.parse(await pre.textContent()||'null')}
function checkViews(e:any){for(const side of ['p','q']){expect(e[side].fingerprint).toBe(fingerprint(e[side].key));expect(e[side].binding).toBe(binding(e[side+'Wire']))}}
async function attack(page:Page,id:number){await page.locator('#rung').selectOption(String(id));const text=await run(page,'#attack-run','#ladder-out');const e=await evidence(page,'ladder-out');checkViews(e);return {text,e}}
test('honest binding and fingerprints derive from complete wire bytes',async({page})=>{
 await page.goto('./');const text=await run(page,'#honest-run','#honest-out'),e=await evidence(page,'honest-out');checkViews(e);expect(e.p.partner).toBe('Q');expect(e.q.partner).toBe('P');expect(e.p.key).toBe(e.q.key);expect(text).toContain('AGREED');
});
for(let id=1;id<=6;id++)test(`V${id} attack has independently checked evidence`,async({page})=>{
 await page.goto('./');const {text,e}=await attack(page,id);
 expect(text).toContain(id===1?'ALARM — KEY EXPOSED':[2,4,6].includes(id)?'ALARM — REPLAYED KEY':'ALARM — MISBOUND');
 if(id===1){expect(e.p.key).toBe(e.record.chosenKey);expect(e.p.key).not.toBe(e.q.key);expect(e.record.origin).toBe('P application record for nonce '+e.pWire.r);expect(decrypt(e.record.chosenKey,e.record).toString()).toBe(e.record.origin);expect(e.record.opened).toBe(e.record.origin)}
 if(id===2||id===4||id===6){expect(e.pWire.r).not.toBe(e.qWire.r);expect(decrypt(e.p.key,e.record).toString()).toBe('P recorded transfer '+e.qWire.r);expect(e.p.key).toBe(e.q.key)}
 if(id===3){expect(e.q.partner).toBe('R');expect(e.qWire.p).toBe('R');expect(e.p.partner).toBe('Q')}
 if(id===3||id===5){expect(e.p.key).toBe(e.q.key);expect(e.p.binding).not.toBe(e.q.binding);expect(e.p.partner).not.toBe(e.q.partner)}
 if(id===4||id===5||id===6)expect(e.p.partner).toBe('R');
 if(id===6){expect(unhex(e.pWire.data)[32]^unhex(e.qWire.data)[32]).toBe(Buffer.from('Q')[0]^Buffer.from('R')[0]);expect(e.cipher.before).toBe(unhex(e.qWire.data).subarray(32,33).toString('hex'));expect(e.cipher.after).toBe(unhex(e.pWire.data).subarray(32,33).toString('hex'))}
 const restored=await run(page,'#restore-run','#ladder-out');expect(restored).toMatch(/signature verification failed|decrypted identity|decryption failed|CTR ciphertext/);expect(restored).not.toContain('Unexpected accept');
});
test('AKE1 leaked scalar independently decrypts prior application record',async({page})=>{
 await page.goto('./');const text=await run(page,'#pfs-run','#pfs-out'),{ake1:a}=await evidence(page,'pfs-out');
 const key=ake1LeakedKey(a.leakedScalar,a.cipher);expect(a.key).toBe(key);expect(a.fingerprint).toBe(fingerprint(key));expect(decrypt(key,a.record).toString()).toBe('private prior session');expect(text).toContain('AUTHENTICATED — AND EXPOSED LATER');
});
test('AKE2 signing-key disclosure runs real rejected decryption probes',async({page})=>{
 await page.goto('./');const text=await run(page,'#pfs-run','#pfs-out'),{ake2:a}=await evidence(page,'pfs-out');
 expect(a.ephemeralErased).toBe(true);expect(a.p).toBe(fingerprint(a.key));expect(a.q).toBe(fingerprint(a.key));expect(decrypt(a.key,a.record).toString()).toBe('private prior session');
 expect(a.leak.probes).toHaveLength(3);expect(a.leak.probes[0].candidate).toBe(a.leak.leakedSigningKey);
 for(const probe of a.leak.probes){expect(()=>decrypt(probe.candidate,a.record)).toThrow();expect(probe.accepted).toBe(false)}
 expect(a.leak.opened).toBe(false);expect(text).toContain('SEALED — all leaked-key probes rejected');
});
test('ephemeral leak leads honest Q to accept a fresh adversary record',async({page})=>{
 await page.goto('./');await run(page,'#ephemeral-run','#pfs-out');const e=await evidence(page,'pfs-out');expect(e.accepted).toBe(true);expect(e.partner).toBe('P');expect(e.v).not.toBe(e.oldV);expect(e.qKey).toBe(e.attackerKey);
});
test('active fake responder is rejected before c2 is sent',async({page})=>{
 await page.goto('./');const text=await run(page,'#probe-run','#identity-out'),e=await evidence(page,'identity-out');expect(e.c1.data.length).toBeGreaterThan(0);expect(e.c2).toBeUndefined();expect(e.reason).toContain('certificate invalid');expect(text).toContain('sent no c2');
});
test('AKE4 fabrication rejects a valid signature replayed onto fresh DH values',async({page})=>{
 await page.goto('./');const text=await run(page,'#deniable-run','#deniable-out'),{ake4:a}=await evidence(page,'deniable-out');
 const verify=(u:string,v:string)=>sig(a.publicP,tuple('AKE4eg/P/sig',Buffer.from('2'),unhex(u),unhex(v)),a.signature);
 expect(verify(a.oldU,a.oldV)).toBe(true);expect(a.originalValid).toBe(true);expect(verify(a.newU,a.newV)).toBe(false);expect(a.forgedValid).toBe(false);expect(text).toContain('verifies: false');
});
test('AKE5 real and Q fabricated confirmations independently recompute',async({page})=>{
 await page.goto('./');const text=await run(page,'#deniable-run','#deniable-out'),{ake5:a}=await evidence(page,'deniable-out');
 for(const [i,e] of [a.real,a.fabricated].entries()){expect(e.key+e.k1+e.k2).toBe(ake5Keys(e));expect(a.fingerprints[i]).toBe(fingerprint(e.key))}
 expect(a.realPass).toBe(true);expect(a.fabricatedPass).toBe(true);expect(text).toMatch(/Q-made transcript .* checks PASS/);
});
// Retain the original end-to-end user flows, now checked against independent bytes.
test('every altered AKE1 definition yields an observed attack and restored AKE1 rejects it',async({page})=>{
 await page.goto('./');await run(page,'#honest-run','#honest-out');checkViews(await evidence(page,'honest-out'));
 for(let id=1;id<=6;id++){await attack(page,id);await page.locator('#rung').selectOption(String(id));expect(await page.locator('#ladder-out').innerText()).toContain('ALARM');const restored=await run(page,'#restore-run','#ladder-out');expect(restored).not.toContain('Unexpected accept');expect(restored).toMatch(/signature verification failed|decrypted identity|decryption failed|CTR ciphertext/)}
 await page.locator('#rung').selectOption('1');expect(await page.locator('#ladder-out').innerText()).toContain('Retired');expect(await page.locator('#ladder-out-evidence').count()).toBe(0);
});
test('a valid AKE1 handshake is exposed after later key compromise',async({page})=>{
 await page.goto('./');const text=await run(page,'#pfs-run','#pfs-out');expect(text).toContain('AUTHENTICATED — AND EXPOSED LATER');expect(text).toContain('certificate valid, signature valid, decryption valid');const {ake1:a}=await evidence(page,'pfs-out');expect(decrypt(ake1LeakedKey(a.leakedScalar,a.cipher),a.record).toString()).toBe('private prior session');
});
