import {expect,test} from '@playwright/test';
import {boot,scan,watchPageErrors,expectBaselineNotStale,reportCollected} from './gate';
// Adapted from the Schnorr reference: reachable AKE states at desktop and 320px.
for(const width of [1280,320])test(`WCAG reachable AKE states at ${width}px`,async({page})=>{
 test.setTimeout(900000);await page.setViewportSize({width,height:900});const errors=watchPageErrors(page);await boot(page,'dark');await scan(page,'arrival');
 await page.locator('#honest-run').click();await expect(page.locator('#honest-out-evidence')).toBeAttached();await scan(page,'honest result');
 await page.locator('#honest-out-evidence summary').click();await scan(page,'complete wire inspector open');
 for(let id=1;id<=6;id++){
  await page.locator('#rung').selectOption(String(id));await page.locator('#variant-honest').click();await expect(page.locator('#ladder-out')).toHaveClass('good');await scan(page,`V${id} honest`);
  await page.locator('#attack-run').click();await expect(page.locator('#ladder-out-evidence')).toBeAttached();await scan(page,`V${id} attack`);
  await page.locator('#ladder-out-evidence summary').click();await scan(page,`V${id} evidence`);
  await page.locator('#restore-run').click();await expect(page.locator('#ladder-out')).toHaveClass('good');await scan(page,`V${id} restored`);
 }
 for(const [button,output] of [['pfs-run','pfs-out'],['ephemeral-run','pfs-out'],['observe-run','identity-out'],['probe-run','identity-out'],['deniable-run','deniable-out']]){
  await page.locator('#'+button).click();await expect(page.locator('#'+output+'-evidence')).toBeAttached();await scan(page,button+' result');await page.locator('#'+output+'-evidence summary').click();await scan(page,button+' evidence');
 }
 await page.locator('section[aria-labelledby=limits] summary').click();await scan(page,'sources open');await page.locator('.cl-skip-link').focus();await scan(page,'focused skip link');
 expect(errors,errors.join('\n')).toEqual([]);expectBaselineNotStale();reportCollected();
});
