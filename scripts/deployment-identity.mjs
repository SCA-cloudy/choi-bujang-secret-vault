const OWNER = /^[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?$/u;
const REPO = /^[A-Za-z0-9._-]{1,100}$/u;
const SHA = /^[a-f0-9]{40}$/iu;
const HOST = /^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.vercel\.app$/iu;

export function deploymentIdentity(env, config) {
  const owner = env.VERCEL_GIT_REPO_OWNER;
  const repo = env.VERCEL_GIT_REPO_SLUG;
  const commit = env.VERCEL_GIT_COMMIT_SHA;
  const host = env.VERCEL_URL;
  if (env.VERCEL_GIT_PROVIDER !== 'github' || !OWNER.test(owner || '')
      || !REPO.test(repo || '') || repo === '.' || repo === '..'
      || repo.toLowerCase().endsWith('.git') || !SHA.test(commit || '')
      || !HOST.test(host || '') || !Number.isInteger(config?.step)
      || config.step < 1 || config.step > 12
      || typeof config.judgeIssuer !== 'string'
      || !/^https:\/\/[a-z0-9-]+\.up\.railway\.app\/defense\/judge$/iu.test(config.judgeIssuer)
      || typeof config.sampleMarker !== 'string'
      || !/^[A-Z0-9_]{1,80}$/u.test(config.sampleMarker)) {
    throw new Error('배포 식별 정보를 확인할 수 없습니다. Vercel 시스템 환경변수와 aleph.config.json의 step을 확인하세요.');
  }
  const identity = {
    schema: 'aleph.defense.deployment.v1',
    step: config.step,
    repoUrl: `https://github.com/${owner.toLowerCase()}/${repo.toLowerCase()}`,
    commit: commit.toLowerCase(),
    publicAppUrl: `https://${host.toLowerCase()}`,
    judgeIssuer: config.judgeIssuer,
    sampleMarker: config.sampleMarker,
  };
  // 5단계: 이 앱이 열어 둔 서버 경로를 /aleph.json에도 알린다. 설정에 문자열 목록이 있을 때만 넣는다.
  const routes = config.allowedRoutes;
  if (Array.isArray(routes) && routes.length > 0 && routes.every(route => typeof route === 'string' && route)) {
    identity.allowedRoutes = [...routes];
  }
  // 5단계: 심판은 배포된 /aleph.json에서 데이터 원본의 HTTPS 주소를 읽는다.
  // 설정에 값이 있으면 쿼리·비밀값이 없는 https 주소인지 확인하고 넣는다. 잘못된 값이면 빌드를 멈춘다.
  const original = config.originalApiUrl;
  if (original !== null && original !== undefined) {
    let parsed;
    try { parsed = new URL(original); } catch { parsed = null; }
    if (typeof original !== 'string' || !parsed || parsed.protocol !== 'https:'
        || parsed.username || parsed.password || parsed.search || parsed.hash) {
      throw new Error('aleph.config.json의 originalApiUrl은 쿼리 없는 https 주소여야 합니다.');
    }
    identity.originalApiUrl = original;
  }
  return identity;
}
