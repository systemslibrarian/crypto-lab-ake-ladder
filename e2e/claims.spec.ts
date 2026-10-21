import {test,expect} from '@playwright/test';

test('every altered AKE1 definition yields an observed attack and restored AKE1 rejects it',async({page})=>{
 await page.goto('./');
 await page.getByRole('button',{name:'Step through AKE1'}).click();
 await expect(page.locator('#honest-out')).toContainText('AGREED');
 const honest=await page.locator('#honest-out').innerText();
 const p=honest.match(/P: key ([0-9a-f]+), partner Q, binding ([0-9a-f]+)…/),q=honest.match(/Q: key ([0-9a-f]+), partner P, binding ([0-9a-f]+)…/);
 expect(p&&q).toBeTruthy();expect(p![1]).toBe(q![1]);expect(p![2]).toBe(q![2]);
 for(let id=1;id<=6;id++){
  await page.locator('#rung').selectOption(String(id));
  await page.getByRole('button',{name:'Run the attack'}).click();
  const out=page.locator('#ladder-out');await expect(out).toContainText('ALARM');
  const text=await out.innerText();
  const pair=text.match(/P sees ([PQR]), key ([0-9a-f]+); Q sees ([PQR]), key ([0-9a-f]+)/);expect(pair).not.toBeNull();
  if(id===1)expect(pair![2]).not.toBe(pair![4]);
  if(id===3||id===5){expect(pair![2]).toBe(pair![4]);expect(pair![1]).not.toBe(pair![3]);expect(text).toContain('DIFFERENT CHANNEL BINDING')}
  if(id===6)expect(text).toContain('0x3'); // ASCII Q xor R = 0x03.
  await page.locator('#rung').selectOption(String(id));await expect(out).toContainText('ALARM'); // no-op guard
  await page.getByRole('button',{name:'Restore the field'}).click();await expect(out).toContainText('RESTORED FIELD');
  expect(await out.innerText()).toMatch(/signature verification failed|decrypted identity|decryption failed/);
 }
 await page.locator('#rung').selectOption('1');await expect(page.locator('#ladder-out')).toContainText('Retired');
});
test('a valid AKE1 handshake is exposed after later key compromise',async({page})=>{
 await page.goto('./');await page.getByRole('button',{name:'Record both and leak'}).click();
 const out=page.locator('#pfs-out');await expect(out).toContainText('AUTHENTICATED — AND EXPOSED LATER');
 const claim=await out.innerText();expect(claim).toContain('certificate valid, signature valid, decryption valid');expect(claim).toContain('private prior session');
 expect(claim.match(/AKE2eg: P and Q derived ([0-9a-f]+) = ([0-9a-f]+)/)?.[1]).toBe(claim.match(/AKE2eg: P and Q derived ([0-9a-f]+) = ([0-9a-f]+)/)?.[2]);
});
