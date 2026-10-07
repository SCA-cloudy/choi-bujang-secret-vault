// 보너스 XDR-01 제작 3: 경보 하나를 block / alert / record 중 하나로 가르는 판단 모듈입니다.
// - 먼저 patterns.json 의 기준으로 경보를 패턴과 맞춰 봅니다.
//   · 명확한 공격(기준 이상)  -> Jev 에게 묻지 않고 block
//   · 정상 이벤트(패턴 없음)  -> Jev 에게 묻지 않고 record
//   · 애매한 건만            -> Jev 에게 확신도(0~1)를 묻습니다.
// - 확신도 0.85 이상 block, 0.5 이상 alert, 그 아래 record. Jev 가 응답하지 않거나 값이 이상하면 alert 입니다.
// - Jev 에게는 pickAlert 로 뽑은 다섯 값(비밀값처럼 보이는 값은 가림)과 패턴 이름만 보냅니다. 원본 경보는 고치지 않습니다.
// - Jev 연결 방법은 이 저장소에 없습니다. 연결하면 createDecide({ askJev }) 로 넣습니다. 연결 전에는 애매한 경보가 alert 입니다.
import { readFile } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { pickAlert } from './read-alerts.mjs';

const HERE = dirname(fileURLToPath(import.meta.url));
const patternFile = JSON.parse(await readFile(join(HERE, 'patterns.json'), 'utf8'));
const PATTERNS = new Map(patternFile.patterns.map(pattern => [pattern.name, pattern]));
const BURST = PATTERNS.get('same-source-failure-burst');
const SPRAY = PATTERNS.get('one-password-many-accounts');

export const BLOCK_AT = 0.85;
export const ALERT_AT = 0.5;
const JEV_TIMEOUT_MS = 5000;
const NO_PATTERN = 'no-pattern';

function actionFor(confidence) {
  if (confidence >= BLOCK_AT) return 'block';
  if (confidence >= ALERT_AT) return 'alert';
  return 'record';
}

// 경보에서 판단에 쓸 값만 계산한다. (읽기만 하고 고치지 않는다.)
function features(alert) {
  const description = typeof alert?.rule?.description === 'string' ? alert.rule.description : '';
  const data = alert?.data ?? {};
  const mitre = Array.isArray(alert?.rule?.mitre) ? alert.rule.mitre : [];
  const accountList = typeof data.accounts === 'string' ? data.accounts.split(',').filter(Boolean).length : 0;
  const accountText = Number((description.match(/계정\s*(\d+)\s*개/u) ?? [])[1]);
  const accounts = accountList || (Number.isFinite(accountText) ? accountText : 0);
  const count = Number(data.count);
  // "계정 N개" 경보의 count 는 계정 수이므로, 그때는 실패 건수로 쓰지 않는다.
  const failures = Number.isFinite(count) && !accounts ? count : 0;
  const noSuccess = /성공(?:은|이)?\s*없/u.test(description);
  const hasSuccess = !noSuccess && /성공/u.test(description);
  return { failures, accounts, hasSuccess, tagged: mitre.includes('T1110') };
}

// 패턴과 맞춰 본다: 'clear'(명확) / 'unclear'(애매) / 'none'(정상)
export function matchPattern(alert) {
  const f = features(alert);
  if (f.accounts >= SPRAY.condition.clearAt.accounts && !f.hasSuccess) return { kind: 'clear', pattern: SPRAY };
  if (f.failures >= BURST.condition.clearAt.failures && !f.hasSuccess) return { kind: 'clear', pattern: BURST };
  const spraySuspicious = f.accounts >= SPRAY.condition.suspiciousAt.accounts;
  const burstSuspicious = f.failures >= BURST.condition.suspiciousAt.failures;
  if (spraySuspicious || burstSuspicious || f.tagged) {
    return { kind: 'unclear', pattern: f.accounts > 0 ? SPRAY : BURST };
  }
  return { kind: 'none', pattern: null };
}

// Jev 의 답에서 0~1 확신도만 꺼낸다. 숫자 또는 { confidence } 만 인정하고, 나머지는 응답 없음으로 본다.
function readConfidence(answer) {
  const value = typeof answer === 'number' ? answer : answer?.confidence;
  return typeof value === 'number' && Number.isFinite(value) && value >= 0 && value <= 1 ? value : null;
}

async function askWithTimeout(askJev, question, timeoutMs) {
  let timer;
  try {
    const timeout = new Promise((_, reject) => { timer = setTimeout(() => reject(new Error('timeout')), timeoutMs); });
    return readConfidence(await Promise.race([Promise.resolve(askJev(question)), timeout]));
  } catch {
    return null;
  } finally {
    clearTimeout(timer);
  }
}

export function createDecide({ askJev = null, timeoutMs = JEV_TIMEOUT_MS } = {}) {
  return async function decide(alert) {
    const { kind, pattern } = matchPattern(alert);
    if (kind === 'clear') {
      return { action: 'block', confidence: 0.95, reason: `${pattern.name}: 기준 이상의 명확한 공격` };
    }
    if (kind === 'none') {
      return { action: 'record', confidence: 0.1, reason: `${NO_PATTERN}: 로그인 공격 패턴과 맞지 않는 정상 이벤트` };
    }
    // 애매한 경보: Jev 에게 묻는다. 응답이 없으면 alert 로 떨어진다.
    const confidence = typeof askJev === 'function'
      ? await askWithTimeout(askJev, { alert: pickAlert(alert), pattern: pattern.name }, timeoutMs)
      : null;
    if (confidence === null) {
      return { action: 'alert', confidence: ALERT_AT, reason: `${pattern.name}: 애매한 시도, Jev 응답 없어 알림으로 남김` };
    }
    return { action: actionFor(confidence), confidence, reason: `${pattern.name}: 애매한 시도, Jev 확신도 ${confidence}` };
  };
}

// 실행기(scripts/xdr-run.mjs)가 부르는 기본 판단. Jev 를 연결하기 전이라 애매한 경보는 alert 입니다.
export const decide = createDecide();
