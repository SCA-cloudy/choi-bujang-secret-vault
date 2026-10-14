// 11단계 제작 1: 설치형 웹앱 설정(manifest), 기기 승인 상태 표시, 오프라인 안내(sw.js) 시험
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { test } from 'node:test';
import vm from 'node:vm';

const root = resolve(import.meta.dirname, '..');
const read = file => readFile(resolve(root, file), 'utf8');

test('manifest는 앱 이름·시작 주소·독립 창·아이콘을 갖고, 설치가 기기 승인이 아니라고 적는다', async () => {
  const manifest = JSON.parse(await read('public/manifest.webmanifest'));
  assert.equal(manifest.name, 'BYTE BACK 내 자료실');
  assert.ok(manifest.short_name);
  assert.equal(manifest.start_url, '/');
  assert.equal(manifest.scope, '/');
  assert.equal(manifest.display, 'standalone');
  assert.ok(Array.isArray(manifest.icons) && manifest.icons.length > 0);
  for (const icon of manifest.icons) await read(`public${icon.src}`); // 아이콘 파일이 실제로 있다
  assert.match(manifest.description, /기기 승인이 끝난 것은 아니며/);
  const text = JSON.stringify(manifest);
  for (const secret of ['token', 'key', 'Bearer', 'supabase']) assert.ok(!text.toLowerCase().includes(secret.toLowerCase()), secret);
});

test('화면은 manifest를 연결하고 기기 승인 상태를 "확인 전"으로 보이며, 설치가 승인이 아니라고 적는다', async () => {
  const html = await read('public/index.html');
  assert.match(html, /<link rel="manifest" href="\/manifest\.webmanifest">/);
  assert.match(html, /id="device-status">확인 전/);
  assert.match(html, /앱으로 설치\(홈 화면에 추가\)해도 기기 확인이 끝난 것은 아닙니다/);
  assert.match(html, /이 화면의 표시나 버튼만으로 권한이 생기지 않습니다/);
  assert.match(html, /navigator\.serviceWorker\.register\('\/sw\.js'\)/);
  // 제작 1은 기존 보호 요청을 바꾸지 않는다: 자료 요청은 여전히 우리 서버 함수로만, 출입증을 붙여 보낸다
  assert.match(html, /callApi\('GET', '\/api\/notes'\)/);
  assert.match(html, /Authorization: `Bearer \$\{session\.accessToken\}`/);
  assert.ok(!/supabase\.co|sb_publishable_|sb_secret_/u.test(html));
});

function loadWorker(fetchImpl) {
  const listeners = {};
  const self = { addEventListener: (type, fn) => { listeners[type] = fn; }, skipWaiting: async () => {}, clients: { claim: async () => {} } };
  const context = vm.createContext({ self, fetch: fetchImpl, Response, Promise });
  return read('public/sw.js').then(code => { vm.runInContext(code, context); return listeners; });
}

test('오프라인 안내: 네트워크가 끊기면 페이지 이동만 안내 화면(503)을 받고, 자료 요청은 가로채지 않으며 아무것도 저장하지 않는다', async () => {
  const code = await read('public/sw.js');
  for (const banned of ['caches.', 'localStorage', 'indexedDB', 'sessionStorage']) assert.ok(!code.includes(banned), banned);
  const listeners = await loadWorker(async () => { throw new TypeError('offline'); });
  let navigateResponse = null;
  listeners.fetch({ request: { mode: 'navigate', url: 'https://example.vercel.app/' }, respondWith: value => { navigateResponse = value; } });
  const response = await navigateResponse;
  assert.equal(response.status, 503);
  assert.match(await response.text(), /오프라인입니다/);
  let apiTouched = false;
  listeners.fetch({ request: { mode: 'cors', url: 'https://example.vercel.app/api/notes' }, respondWith: () => { apiTouched = true; } });
  assert.equal(apiTouched, false);
});

test('오프라인 안내: 네트워크가 되면 페이지 이동은 그대로 서버 응답을 받는다', async () => {
  const online = new Response('서버 화면', { status: 200 });
  const listeners = await loadWorker(async () => online);
  let result = null;
  listeners.fetch({ request: { mode: 'navigate', url: 'https://example.vercel.app/' }, respondWith: value => { result = value; } });
  assert.equal(await result, online);
});
