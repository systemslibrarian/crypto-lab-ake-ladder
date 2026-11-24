import {expect,it} from 'vitest';
import type {View} from '../ake/ake1';
import {sessionAgrees} from './evidence';

it('checks complete session keys and bindings even when displayed fingerprints match', () => {
  const p: View = {partner:'Q', key:new Uint8Array(32), fingerprint:'same displayed value', binding:'one session'};
  const q: View = {...p, partner:'P', key:p.key.slice()};
  expect(sessionAgrees(p,q)).toBe(true);
  expect(sessionAgrees(p,{...q,binding:'another session'})).toBe(false);
  q.key[31]=1;
  expect(sessionAgrees(p,q)).toBe(false);
});
