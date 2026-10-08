// 보너스 XDR-02 제작 4: 판단 결과를 알림과 차단 규칙으로 바꾸는 연결 파일입니다.
// - decide.mjs 는 판단 결과만 돌려줍니다. 파일 쓰기와 규칙 만들기는 이 파일만 합니다.
// - 차단(block) 후보만 거부 규칙이 됩니다. 규칙에는 만료 시각과 근거 경보 번호가 붙습니다.
// - 규칙의 대상은 출발 주소뿐입니다. 계정(사용자)을 막는 규칙은 만들지 않습니다.
//   같은 주소가 정상(record) 이벤트에도 나타나면 그 주소는 규칙에서 뺍니다.
// - 알림(alert)과 차단(block)은 xdr/alerts.log 에 한 줄씩 쌓습니다. 정상(record)은 남기지 않습니다.
// - 판정기(src/decider.mjs)의 요청 계약에는 출발 주소가 없어서, 이 파일은 판정기 코드를 고치지 않습니다.
//   판정기에 연결할 때 쓸 규칙 목록(rules)과 isDenied(rules, srcip, now) 를 내보냅니다.
import { appendFile, mkdir, readFile } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import { isIP } from 'node:net';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { decide as defaultDecide } from './decide.mjs';
import { maskSecrets, pickAlert } from './read-alerts.mjs';

const HERE = dirname(fileURLToPath(import.meta.url));
export const DEFAULT_LOG_PATH = join(HERE, '..', 'alerts.log');
export const DENY_TTL_MINUTES = 30;
export const RULE_REASON_CODE = 'web_injection_blocked';

const oneLine = text => maskSecrets(String(text ?? '')).replace(/[\r\n|]+/gu, ' ').trim();

// 차단 후보(block)에서 거부 규칙을 만든다. 같은 주소는 규칙 하나에 근거 경보 번호를 모은다.
export function buildDenyRules(items, { now = new Date(), ttlMinutes = DENY_TTL_MINUTES } = {}) {
  const normalAddresses = new Set(items.filter(item => item.decision.action === 'record' && item.row.srcip).map(item => item.row.srcip));
  const bySource = new Map();
  for (const item of items) {
    const { alertId, decision, row } = item;
    if (decision.action !== 'block') continue;
    if (!row.srcip || !isIP(row.srcip)) continue; // 주소 모양이 아니면 규칙으로 만들지 않는다.
    if (normalAddresses.has(row.srcip)) continue; // 정상 이벤트와 같은 주소는 막지 않는다.
    const rule = bySource.get(row.srcip) ?? {
      id: `xdr.web-injection.deny.${row.srcip}`,
      action: 'deny',
      reasonCode: RULE_REASON_CODE,
      srcip: row.srcip,
      createdAt: now.toISOString(),
      expiresAt: new Date(now.getTime() + ttlMinutes * 60_000).toISOString(),
      evidenceAlertIds: [],
      reason: decision.reason,
    };
    if (alertId) rule.evidenceAlertIds.push(alertId);
    bySource.set(row.srcip, rule);
  }
  return [...bySource.values()];
}

// 이 주소가 지금(now) 막혀 있는지 확인한다. 만료된 규칙은 무시한다. 막혀 있으면 그 규칙을, 아니면 null.
export function isDenied(rules, srcip, now = new Date()) {
  if (typeof srcip !== 'string') return null;
  return rules.find(rule => rule.srcip === srcip && Date.parse(rule.expiresAt) > now.getTime()) ?? null;
}

export function formatLogLine({ alertId, decision, row }, now = new Date()) {
  return [
    now.toISOString(), decision.action, oneLine(alertId) || '-', oneLine(row.srcip) || '-', oneLine(row.user) || '-',
    `확신도 ${decision.confidence}`, oneLine(decision.reason),
  ].join(' | ');
}

// 경보를 판단하고, 알림 줄을 로그에 쌓고, 차단 후보에서 거부 규칙을 만든다.
export async function respondToAlerts(alerts, { decide = defaultDecide, now = new Date(), logPath = DEFAULT_LOG_PATH, ttlMinutes } = {}) {
  const items = [];
  for (const alert of alerts) {
    const decision = await decide(alert);
    items.push({ alertId: typeof alert?.id === 'string' ? alert.id : '', decision, row: pickAlert(alert) });
  }
  const lines = items.filter(item => item.decision.action !== 'record').map(item => formatLogLine(item, now));
  if (lines.length > 0) {
    await mkdir(dirname(logPath), { recursive: true });
    await appendFile(logPath, `${lines.join('\n')}\n`, 'utf8');
  }
  const rules = buildDenyRules(items, { now, ttlMinutes });
  return { items, rules, logged: lines.length };
}

// 직접 실행하면 시험 경보를 흘려 보고 결과를 보여 준다:  node xdr/web-injection/respond.mjs
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  try {
    const fixturePath = join(HERE, '..', 'fixtures', 'web-injection.json');
    const alerts = JSON.parse(await readFile(fixturePath, 'utf8')).alerts;
    const now = new Date();
    const { items, rules, logged } = await respondToAlerts(alerts, { now });
    const blocked = items.filter(item => item.decision.action === 'block');
    const others = items.filter(item => item.decision.action !== 'block');
    const blockedOk = blocked.filter(item => isDenied(rules, item.row.srcip, now)).length;
    const othersPassed = others.filter(item => !isDenied(rules, item.row.srcip, now)).length;
    console.log(`거부 규칙 ${rules.length}개 (만료 ${DENY_TTL_MINUTES}분 뒤), 알림 로그 ${logged}줄 → xdr/alerts.log`);
    for (const rule of rules) console.log(`  ${rule.srcip} | 만료 ${rule.expiresAt} | 근거 ${rule.evidenceAlertIds.join(',')}`);
    console.log(`명확한 공격 ${blocked.length}건 중 막힘 ${blockedOk}건`);
    console.log(`알림·정상 ${others.length}건 중 통과 ${othersPassed}건`);
    console.log(`경보 ${alerts.length}건 처리 완료`);
    if (blockedOk !== blocked.length || othersPassed !== others.length) process.exitCode = 1;
  } catch (error) {
    console.error(error instanceof Error ? error.message : '실행 오류');
    process.exitCode = 1;
  }
}
