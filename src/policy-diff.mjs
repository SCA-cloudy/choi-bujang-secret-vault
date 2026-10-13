// 10단계 제작 1: 침해 전에 검증한 안전 정책 사본과 "현재 시험 정책"의 차이만 계산합니다.
// - 이 파일은 파일 읽기·쓰기·네트워크를 하지 않는 순수 함수입니다. 실제 운영 정책(판정기·설정·DB)을 고치지 않습니다.
// - "정책"은 세 가지로 정의합니다: 판정기 규칙 이름(ruleIds), 허용 경로(allowedRoutes),
//   그리고 고정한 가상 요청에 판정기가 내는 결정(decisions). 메모 내용·토큰·실명은 정책에 넣지 않습니다.
// - 사본은 검증을 통과해야만 차이를 계산합니다. 모양이 틀리거나 지문(sha256)이 다르면 중단합니다.
import { createHash } from 'node:crypto';

export const POLICY_SCHEMA = 'aleph.policy.v1';
export const SNAPSHOT_SCHEMA = 'aleph.policy-snapshot.v1';

const DECISIONS = Object.freeze(['allow', 'deny', 'step_up']);
const RULE_NAME = /^[a-z][a-z_]{0,39}$/u;
const ROUTE = /^[A-Z]{3,7} \/[A-Za-z0-9_\-/:]{0,80}$/u;
const PROBE_NAME = /^[A-Za-z0-9_:. /-]{1,60}$/u;
const SHA256 = /^[0-9a-f]{64}$/u;
const COMMIT = /^[0-9a-f]{40}$/u;
const VERSION = /^safe-[0-9]{1,2}$/u;
const isPlain = value => value !== null && typeof value === 'object' && !Array.isArray(value);

// 키 순서와 상관없이 같은 값이면 같은 글자열이 되도록 정렬해서 JSON으로 만듭니다.
export function canonicalJson(value) {
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  if (isPlain(value)) {
    return `{${Object.keys(value).sort().map(key => `${JSON.stringify(key)}:${canonicalJson(value[key])}`).join(',')}}`;
  }
  return JSON.stringify(value);
}

export const policyDigest = policy => createHash('sha256').update(canonicalJson(policy)).digest('hex');

// 사본 검증: 통과하면 { ok: true }, 실패하면 { ok: false, reason } (reason은 짧은 코드)
export function verifySnapshot(snapshot, { expectedSha256 } = {}) {
  if (!isPlain(snapshot)) return { ok: false, reason: 'snapshot_not_object' };
  const keys = Object.keys(snapshot).sort().join(',');
  if (keys !== 'policy,schema,sha256,source,version') return { ok: false, reason: 'snapshot_keys_invalid' };
  if (snapshot.schema !== SNAPSHOT_SCHEMA) return { ok: false, reason: 'schema_mismatch' };
  if (typeof snapshot.version !== 'string' || !VERSION.test(snapshot.version)) return { ok: false, reason: 'version_invalid' };
  const { source } = snapshot;
  if (!isPlain(source) || !Number.isInteger(source.step) || typeof source.commit !== 'string' || !COMMIT.test(source.commit)
    || typeof source.basis !== 'string' || source.basis.length > 120 || Object.keys(source).length !== 3) {
    return { ok: false, reason: 'source_invalid' };
  }
  const { policy } = snapshot;
  const policyOk = isPlain(policy) && policy.schema === POLICY_SCHEMA
    && Object.keys(policy).sort().join(',') === 'allowedRoutes,decisions,ruleIds,schema'
    && Array.isArray(policy.ruleIds) && policy.ruleIds.every(id => typeof id === 'string' && RULE_NAME.test(id))
    && Array.isArray(policy.allowedRoutes) && policy.allowedRoutes.every(route => typeof route === 'string' && ROUTE.test(route))
    && isPlain(policy.decisions)
    && Object.entries(policy.decisions).every(([name, value]) => PROBE_NAME.test(name) && DECISIONS.includes(value));
  if (!policyOk) return { ok: false, reason: 'policy_invalid' };
  if (typeof snapshot.sha256 !== 'string' || !SHA256.test(snapshot.sha256) || snapshot.sha256 !== policyDigest(policy)) {
    return { ok: false, reason: 'digest_mismatch' };
  }
  // 바깥에서 따로 적어 둔 지문(선택)이 있으면 사본 안의 지문과도 같아야 합니다.
  if (expectedSha256 !== undefined && expectedSha256 !== snapshot.sha256) return { ok: false, reason: 'pin_mismatch' };
  return { ok: true };
}

// 현재 시험 정책을 모읍니다. 판정기는 바깥에서 받은 함수만 부르며, 고치지 않습니다.
export async function collectCurrentPolicy({ ruleIds, allowedRoutes, decide, baseRequest, anomalyRequest }) {
  const id = '11111111-2222-4333-8444-555555555555';
  const shapes = ['GET /notes', 'POST /notes', 'GET /notes/:id', 'PUT /notes/:id', 'DELETE /notes/:id',
    'GET /notices', 'GET /notices/:id', 'PUT /notices/:id'];
  const decisions = {};
  for (const shape of shapes) {
    const [method, route] = shape.split(' ');
    const answer = await decide({ ...baseRequest, method, route: shape, path: route.replace(':id', id) });
    decisions[shape] = answer.decision;
  }
  decisions['device:unregistered'] = (await decide({ ...baseRequest, deviceRegistered: false })).decision;
  decisions['anomaly:without_step_up'] = (await decide(anomalyRequest)).decision;
  decisions['anomaly:step_up_verified'] = (await decide({ ...anomalyRequest, stepUp: { verified: true, authAgeSeconds: 60 } })).decision;
  return {
    schema: POLICY_SCHEMA,
    ruleIds: [...ruleIds].sort(),
    allowedRoutes: [...allowedRoutes].sort(),
    decisions: Object.fromEntries(Object.entries(decisions).sort(([a], [b]) => a.localeCompare(b))),
  };
}

// 두 정책의 차이. 사본(safe)을 기준으로 "복원하면 무엇이 바뀌는지"를 목록으로 돌려줍니다.
// kind: 'restore_add' = 현재에 없어서 사본대로 다시 생김, 'restore_remove' = 현재에만 있어서 없어짐, 'restore_change' = 값이 다시 바뀜
export function diffPolicy(safe, current) {
  const changes = [];
  for (const area of ['ruleIds', 'allowedRoutes']) {
    for (const item of safe[area]) if (!current[area].includes(item)) changes.push({ area, item, kind: 'restore_add', safe: item, current: null });
    for (const item of current[area]) if (!safe[area].includes(item)) changes.push({ area, item, kind: 'restore_remove', safe: null, current: item });
  }
  const names = [...new Set([...Object.keys(safe.decisions), ...Object.keys(current.decisions)])].sort();
  for (const name of names) {
    const was = Object.hasOwn(safe.decisions, name) ? safe.decisions[name] : null;
    const now = Object.hasOwn(current.decisions, name) ? current.decisions[name] : null;
    if (was === now) continue;
    changes.push({ area: 'decisions', item: name, kind: was === null ? 'restore_remove' : now === null ? 'restore_add' : 'restore_change', safe: was, current: now });
  }
  return { same: changes.length === 0, changes };
}

// 실행 전에 보여 줄 요약 (읽기 전용)
export function describePlan(snapshot, diff) {
  return {
    version: snapshot.version,
    commit: snapshot.source.commit,
    sha256: snapshot.sha256,
    changeCount: diff.changes.length,
    areas: [...new Set(diff.changes.map(change => change.area))],
  };
}
