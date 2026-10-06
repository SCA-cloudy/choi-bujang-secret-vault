import assert from 'node:assert/strict';
import { test } from 'node:test';
import { deploymentIdentity } from '../scripts/deployment-identity.mjs';
import { runAttackChecks } from '../src/attack-check.mjs';

const config = {
  step: 1,
  judgeIssuer: 'https://aleph-judge-production.up.railway.app/defense/judge',
  sampleMarker: 'SAMPLE_NOTE_1',
  publicAppUrl: 'https://student-defense.vercel.app',
};
const env = {
  VERCEL_GIT_PROVIDER: 'github',
  VERCEL_GIT_REPO_OWNER: 'Student-A',
  VERCEL_GIT_REPO_SLUG: 'aleph-defense',
  VERCEL_GIT_COMMIT_SHA: 'a'.repeat(40),
  VERCEL_URL: 'student-defense-123.vercel.app',
};

test('build identity uses Vercel Git and deployment metadata', () => {
  assert.deepEqual(deploymentIdentity(env, config), {
    schema: 'aleph.defense.deployment.v1',
    step: 1,
    repoUrl: 'https://github.com/student-a/aleph-defense',
    commit: 'a'.repeat(40),
    publicAppUrl: 'https://student-defense-123.vercel.app',
    judgeIssuer: config.judgeIssuer,
    sampleMarker: config.sampleMarker,
  });
  assert.throws(() => deploymentIdentity({ ...env, VERCEL_GIT_PROVIDER: undefined }, config));
  assert.throws(() => deploymentIdentity({ ...env, VERCEL_GIT_COMMIT_SHA: 'short' }, config));
});

test('first attack check reads public data.json without credentials', async () => {
  const originalFetch = globalThis.fetch;
  let requestUrl;
  let options;
  try {
    globalThis.fetch = async (url, init) => {
      requestUrl = String(url);
      options = init;
      return new Response(JSON.stringify({ sampleMarker: 'SAMPLE_NOTE_1', notes: [{ title: '가상' }] }), {
        status: 200,
        headers: { 'content-type': 'application/json' },
      });
    };
    const [result] = await runAttackChecks(config);
    assert.equal(requestUrl, 'https://student-defense.vercel.app/data.json');
    assert.equal(options.redirect, 'error');
    assert.match(result.observed, /확인 표시가 보임/u);
    globalThis.fetch = async () => new Response('<html>not the data</html>', { status: 200 });
    const [failed] = await runAttackChecks(config);
    assert.match(failed.observed, /보이지 않음/u);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test('step 2 build identity keeps the config step and rejects an invalid step', () => {
  assert.equal(deploymentIdentity(env, { ...config, step: 2 }).step, 2);
  assert.throws(() => deploymentIdentity(env, { ...config, step: 0 }));
  assert.throws(() => deploymentIdentity(env, { ...config, step: 13 }));
  assert.throws(() => deploymentIdentity(env, { ...config, step: '2' }));
});

test('step 2 attack check records static data.json and /api/notes without note bodies', async () => {
  const originalFetch = globalThis.fetch;
  const requested = [];
  try {
    globalThis.fetch = async (url, init) => {
      requested.push(String(url));
      assert.equal(init.redirect, 'error');
      if (String(url).endsWith('/data.json')) return new Response('Not found', { status: 404 });
      return new Response(JSON.stringify({ notes: [{ title: 'a', content: 'secret-body' }, { title: 'b', content: 'c' }] }), {
        status: 200, headers: { 'content-type': 'application/json' },
      });
    };
    const results = await runAttackChecks({ ...config, step: 2 });
    assert.deepEqual(requested, [
      'https://student-defense.vercel.app/data.json',
      'https://student-defense.vercel.app/api/notes',
    ]);
    assert.deepEqual(results.map(item => item.attackId), ['static_data_json_read', 'anonymous_api_notes_read']);
    assert.match(results[0].observed, /HTTP 404, 가상 메모 0건/u);
    assert.match(results[1].observed, /HTTP 200, 가상 메모 2건/u);
    assert.ok(!JSON.stringify(results).includes('secret-body'));
    for (const item of results) {
      assert.deepEqual(Object.keys(item).sort(), ['attackId', 'expected', 'observed']);
      assert.ok(item.expected.length <= 300 && item.observed.length <= 300);
    }
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test('step 4 attack check sends only anonymous requests and records status codes without bodies', async () => {
  const originalFetch = globalThis.fetch;
  const requested = [];
  try {
    globalThis.fetch = async (url, init) => {
      requested.push(`${init.method ?? 'GET'} ${new URL(String(url)).pathname}`);
      assert.equal(init.redirect, 'error');
      assert.ok(!init.headers?.Authorization && !init.headers?.authorization);
      if (String(url).endsWith('/data.json')) return new Response('Not found', { status: 404 });
      return new Response(JSON.stringify({ error: 'LOGIN_REQUIRED' }), {
        status: 401, headers: { 'content-type': 'application/json' },
      });
    };
    const results = await runAttackChecks({ ...config, step: 4 });
    assert.deepEqual(requested, [
      'GET /data.json', 'GET /api/notes', 'POST /api/notes',
      'PUT /api/notes/00000000-0000-4000-8000-000000000000',
      'DELETE /api/notes/00000000-0000-4000-8000-000000000000',
    ]);
    assert.deepEqual(results.map(item => item.attackId), [
      'static_data_json_read', 'anonymous_notes_list_read', 'anonymous_note_create',
      'anonymous_note_update', 'anonymous_note_delete',
    ]);
    for (const item of results.slice(2)) assert.match(item.observed, /HTTP 401, 오류 문구 LOGIN_REQUIRED/u);
    for (const item of results) {
      assert.deepEqual(Object.keys(item).sort(), ['attackId', 'expected', 'observed']);
      assert.ok(item.expected.length <= 300 && item.observed.length <= 300);
    }
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test('step 3 attack check records rejected anonymous list and create requests without bodies', async () => {
  const originalFetch = globalThis.fetch;
  const requested = [];
  try {
    globalThis.fetch = async (url, init) => {
      requested.push(`${init.method ?? 'GET'} ${new URL(String(url)).pathname}`);
      assert.equal(init.redirect, 'error');
      assert.ok(!init.headers?.Authorization && !init.headers?.authorization);
      if (String(url).endsWith('/data.json')) return new Response('Not found', { status: 404 });
      return new Response(JSON.stringify({ error: 'LOGIN_REQUIRED' }), {
        status: 401, headers: { 'content-type': 'application/json' },
      });
    };
    const results = await runAttackChecks({ ...config, step: 3 });
    assert.deepEqual(requested, ['GET /data.json', 'GET /api/notes', 'POST /api/notes']);
    assert.deepEqual(results.map(item => item.attackId),
      ['static_data_json_read', 'anonymous_notes_list_read', 'anonymous_note_create']);
    assert.match(results[1].observed, /HTTP 401, 오류 문구 LOGIN_REQUIRED, 가상 메모 0건/u);
    assert.match(results[2].observed, /HTTP 401/u);
    for (const item of results) {
      assert.deepEqual(Object.keys(item).sort(), ['attackId', 'expected', 'observed']);
      assert.ok(item.expected.length <= 300 && item.observed.length <= 300);
    }
    // 서버가 잘못 열려 있어 메모 배열을 돌려줘도 본문 내용은 기록하지 않는다.
    globalThis.fetch = async url => (String(url).endsWith('/data.json')
      ? new Response('x', { status: 404 })
      : new Response(JSON.stringify([{ id: 'i', title: 'secret-title', body: 'secret-body' }]), { status: 200 }));
    const leaked = await runAttackChecks({ ...config, step: 3 });
    assert.match(leaked[1].observed, /HTTP 200, 오류 문구 없음, 가상 메모 1건/u);
    assert.ok(!JSON.stringify(leaked).includes('secret-'));
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test('build identity adds allowedRoutes only when the config lists them', () => {
  const routes = ['GET /api/notes', 'POST /api/notes'];
  assert.deepEqual(deploymentIdentity(env, { ...config, step: 5, allowedRoutes: routes }).allowedRoutes, routes);
  for (const bad of [undefined, null, [], [''], [1], 'GET /api/notes']) {
    assert.ok(!('allowedRoutes' in deploymentIdentity(env, { ...config, step: 5, allowedRoutes: bad })));
  }
});

test('step 5 attack check also reads the original API anonymously and never records the key', async () => {
  const originalFetch = globalThis.fetch;
  const originalKey = process.env.SUPABASE_PUBLISHABLE_KEY;
  const requested = [];
  const step5 = { ...config, step: 5, originalApiUrl: 'https://project-ref.supabase.co/rest/v1/notes' };
  try {
    globalThis.fetch = async (url, init) => {
      requested.push(`${init.method ?? 'GET'} ${String(url)}`);
      assert.equal(init.redirect, 'error');
      assert.ok(!init.headers?.Authorization && !init.headers?.authorization);
      if (String(url).endsWith('/data.json')) return new Response('Not found', { status: 404 });
      if (String(url).startsWith('https://project-ref.supabase.co/')) {
        return new Response(JSON.stringify({ code: '42501', message: 'permission denied for table notes' }), { status: 401 });
      }
      return new Response(JSON.stringify({ error: 'LOGIN_REQUIRED' }), { status: 401 });
    };
    delete process.env.SUPABASE_PUBLISHABLE_KEY;
    const results = await runAttackChecks(step5);
    assert.equal(requested.at(-1), 'GET https://project-ref.supabase.co/rest/v1/notes?select=id');
    assert.equal(results.length, 6);
    assert.equal(results[5].attackId, 'original_api_direct_read');
    assert.match(results[5].observed, /키 없이 보낸 요청에서 HTTP 401, 오류 문구 42501, 가상 메모 0건/u);

    process.env.SUPABASE_PUBLISHABLE_KEY = 'sb_publishable_test_value';
    const withKey = await runAttackChecks(step5);
    assert.match(withKey[5].observed, /공개 키를 붙여 보낸 요청에서 HTTP 401/u);
    assert.ok(!JSON.stringify(withKey).includes('sb_publishable_test_value'));
    for (const item of withKey) {
      assert.deepEqual(Object.keys(item).sort(), ['attackId', 'expected', 'observed']);
      assert.ok(item.expected.length <= 300 && item.observed.length <= 300);
    }
    await assert.rejects(runAttackChecks({ ...step5, originalApiUrl: null }));
    await assert.rejects(runAttackChecks({ ...step5, originalApiUrl: 'http://project-ref.supabase.co/rest/v1/notes' }));
  } finally {
    globalThis.fetch = originalFetch;
    if (originalKey === undefined) delete process.env.SUPABASE_PUBLISHABLE_KEY;
    else process.env.SUPABASE_PUBLISHABLE_KEY = originalKey;
  }
});

test('build identity publishes originalApiUrl only when it is a clean https address', () => {
  const url = 'https://project-ref.supabase.co/rest/v1/notes';
  assert.equal(deploymentIdentity(env, { ...config, step: 5, originalApiUrl: url }).originalApiUrl, url);
  for (const empty of [undefined, null]) {
    assert.ok(!('originalApiUrl' in deploymentIdentity(env, { ...config, step: 5, originalApiUrl: empty })));
  }
  for (const bad of ['', 'not a url', 'http://project-ref.supabase.co/rest/v1/notes',
    'https://project-ref.supabase.co/rest/v1/notes?apikey=x', 'https://user:pw@project-ref.supabase.co/rest/v1/notes', 5]) {
    assert.throws(() => deploymentIdentity(env, { ...config, step: 5, originalApiUrl: bad }));
  }
});
