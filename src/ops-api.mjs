// 12단계 제작 1: 탈환 작전실 요약(GET /api/ops).
// - 로그인과 승인된 기기의 요청 서명이 있어야 응답합니다(작전실 정보도 보호 자료로 다룹니다).
// - 요청할 때마다 서버가 그 자리에서 확인한 값만 돌려주고, 항목마다 출처(source)를 붙입니다.
//     live_virtual: 서버가 지금 판정기·탐지 함수를 가상 요청·가상 사건으로 실행한 결과
//     live_db     : 서버가 지금 DB(devices, notes_backup)를 읽은 결과
//     live_file   : 서버가 지금 저장소 파일(정책 사본, 복원 훈련 기록)을 읽은 결과
//     not_run     : 이 저장소가 실행하거나 모으지 않는 것(예: 반 엔진의 실제 접속 사건)
//     unavailable : 읽으려 했지만 실패한 것(이유 코드만)
// - 메모 제목·본문은 응답에 넣지 않습니다. 기기 번호·메모 번호는 앞 4자리와 뒤 4자리만 남기고 가립니다.
// - 서버 기록에는 이유 코드만 남기고 사용자 ID·토큰·메모 내용은 남기지 않습니다.
import { randomUUID } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { RULE_IDS, decide } from './decider.mjs';
import { detect } from './detect.mjs';
import { requireDevice } from './device-auth.mjs';
import { checkBackupRow } from './note-backup.mjs';
import { createSupabaseStore, defaultVerifyAuthorization } from './notes-api.mjs';
import { fixtureRequests } from '../scripts/fixture-7.mjs';

export const mask = value => (typeof value === 'string' && value.length > 8 ? `${value.slice(0, 4)}…${value.slice(-4)}` : '…');
const log = text => console.error(`ops: ${text}`);

async function deciderSummary() {
  const { normal, suspicious } = fixtureRequests();
  const probes = [
    { name: '등록 기기의 평소 읽기', request: normal, expected: 'allow' },
    { name: '미등록 기기의 읽기', request: { ...normal, requestId: randomUUID(), deviceRegistered: false }, expected: 'deny' },
    { name: '복합 이상 접속(재확인 전)', request: suspicious, expected: 'step_up' },
    { name: '구역 밖 동작: 메모 삭제', request: { ...normal, requestId: randomUUID(), method: 'DELETE', route: 'DELETE /notes/:id', path: '/notes/demo' }, expected: 'deny' },
  ];
  const results = [];
  for (const probe of probes) {
    const answer = await decide(probe.request);
    results.push({ name: probe.name, expected: probe.expected, decision: answer.decision, reasonCode: answer.reasonCode, ruleIds: answer.ruleIds });
  }
  return { source: 'live_virtual', ruleIds: [...RULE_IDS], probes: results };
}

function detectionSummary(now) {
  const start = now - 15 * 60 * 1000;
  const reads = count => Array.from({ length: count }, (_, index) => ({
    at: new Date(start + index * 2000).toISOString(), method: 'GET', identity: { sub: 'learner_fixture' },
  }));
  const probes = [30, 121].map(count => {
    const answer = detect(reads(count));
    return { name: `같은 사용자의 가상 조회 ${count}건`, count, action: answer.action, reasonCode: answer.reasonCode ?? null };
  });
  return {
    source: 'live_virtual', probes,
    liveEvents: { source: 'not_run', reason: '반 엔진의 실제 접속 사건 전달과 회수는 이 저장소에 연결되어 있지 않아 실행하지 않음' },
  };
}

async function revocationSummary(store, ownerId) {
  try {
    const rows = await store.listDevices(ownerId);
    const counts = { approved: 0, pending: 0, revoked: 0 };
    for (const row of rows) if (row.status in counts) counts[row.status] += 1;
    return {
      source: 'live_db', total: rows.length, counts,
      records: rows.map(row => ({ device: mask(row.device_id), status: row.status })),
    };
  } catch (error) {
    log('기기 표를 읽지 못함=DEVICES_UNAVAILABLE');
    return { source: 'unavailable', reason: 'DEVICES_UNAVAILABLE' };
  }
}

async function recoverySummary(store, ownerId) {
  let policy;
  try {
    const snapshot = JSON.parse(readFileSync(new URL('../policy/safe-policy.json', import.meta.url), 'utf8'));
    policy = { source: 'live_file', version: snapshot.version, sha256Prefix: String(snapshot.sha256).slice(0, 12), sourceCommit: String(snapshot.source?.commit ?? '').slice(0, 7) };
  } catch { policy = { source: 'unavailable', reason: 'POLICY_SNAPSHOT_UNREADABLE' }; }
  let drill;
  try {
    const record = JSON.parse(readFileSync(new URL('../policy/restore-drill.json', import.meta.url), 'utf8'));
    const last = record.runs.at(-1);
    drill = last
      ? { source: 'live_file', runs: record.runs.length, lastAt: last.at, lastOk: last.ok, lastPassed: last.passed, lastTotal: last.total }
      : { source: 'not_run', reason: '복원 훈련 기록이 없음' };
  } catch { drill = { source: 'unavailable', reason: 'DRILL_RECORD_UNREADABLE' }; }
  let backups;
  try {
    const rows = await store.listBackups(ownerId);
    let invalid = 0;
    const records = rows.map(row => {
      const ok = checkBackupRow(row, { id: row.id, ownerId }).ok;
      if (!ok) invalid += 1;
      return { note: mask(row.id), verified: ok };
    });
    backups = { source: 'live_db', count: rows.length, invalid, records };
  } catch {
    log('사본 표를 읽지 못함=BACKUPS_UNAVAILABLE');
    backups = { source: 'unavailable', reason: 'BACKUPS_UNAVAILABLE' };
  }
  return { policy, drill, backups };
}

export function createOpsHandler({ verifyAuthorization, store, now = () => Date.now(),
  deviceCheck = (request, response, identity) => requireDevice(request, response, identity, { store, now }) }) {
  return async function ops(request, response) {
    response.setHeader('Cache-Control', 'no-store');
    response.setHeader('Vary', 'Authorization');
    if (request.method !== 'GET') {
      response.setHeader('Allow', 'GET');
      return response.status(405).json({ error: 'METHOD_NOT_ALLOWED' });
    }
    let identity = null;
    try { identity = await verifyAuthorization(request.headers?.authorization); } catch { log('로그인 검사를 끝내지 못했습니다.'); }
    if (!identity) {
      response.setHeader('WWW-Authenticate', 'Bearer');
      return response.status(401).json({ error: 'LOGIN_REQUIRED' });
    }
    if (!(await deviceCheck(request, response, identity))) return;
    const at = now();
    try {
      const body = {
        schema: 'aleph.ops.v1',
        requestId: randomUUID(),
        checkedAt: new Date(at).toISOString(),
        decider: await deciderSummary(),
        detection: detectionSummary(at),
        revocation: await revocationSummary(store, identity.userId),
        recovery: await recoverySummary(store, identity.userId),
      };
      log('작전실 요약=ok');
      return response.status(200).json(body);
    } catch (error) {
      log(`처리하지 못했습니다. ${String(error?.message ?? '').slice(0, 40)}`);
      return response.status(500).json({ error: 'OPS_UNAVAILABLE' });
    }
  };
}

let defaultHandler;
export function defaultOpsHandler() {
  defaultHandler ??= createOpsHandler({ verifyAuthorization: defaultVerifyAuthorization, store: createSupabaseStore() });
  return defaultHandler;
}
