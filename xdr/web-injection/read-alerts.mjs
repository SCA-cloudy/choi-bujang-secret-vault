// 보너스 XDR-02 제작 1: Wazuh 경보에서 필요한 다섯 값만 뽑는 읽기 전용 모듈입니다.
// - 뽑는 값: 시각(time), 출발 주소(srcip), 계정(user), 규칙 수준(level), 설명(description)
// - 요청 주소(url)처럼 공격 표기가 들어 있을 수 있는 값은 뽑지 않습니다.
// - 원본 경보 파일은 읽기만 하고 고치지 않습니다. 네트워크도 쓰지 않습니다.
// - 비밀값처럼 보이는 문자열은 '[가림]'으로 바꿔 출력합니다.
// - 확인용 모듈입니다. 심판이 한 파일만 불러오는 decide.mjs 는 이 파일을 불러오지 않습니다.
import { readFile } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const HERE = dirname(fileURLToPath(import.meta.url));
const DEFAULT_FIXTURE = join(HERE, '..', 'fixtures', 'web-injection.json');
const MASK = '[가림]';

// 비밀값처럼 보이는 모양: 이름=값 꼴의 비밀번호·토큰·키, 접두사가 붙은 키, JWT, 길게 이어진 영문·숫자.
const SECRET_PATTERNS = [
  /\b(?:password|passwd|pwd|secret|token|api[_-]?key|apikey|authorization)\s*[:=]\s*\S+/giu,
  /\bBearer\s+[A-Za-z0-9._~+/=-]{8,}/gu,
  /\beyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]*/gu,
  /\b(?:sb_(?:publishable|secret)|sk|pk|ghp|gho|xox[abp])[_-][A-Za-z0-9_-]{8,}/gu,
  /\b[A-Za-z0-9+/_-]{32,}={0,2}/gu,
];

export function maskSecrets(text) {
  let out = String(text ?? '');
  for (const pattern of SECRET_PATTERNS) out = out.replace(pattern, MASK);
  return out;
}

function textOrEmpty(value) {
  return typeof value === 'string' ? maskSecrets(value) : '';
}

// 경보 하나에서 다섯 값만 꺼낸다. 없는 값은 빈 문자열(규칙 수준은 null)로 둔다.
export function pickAlert(alert) {
  return {
    time: textOrEmpty(alert?.timestamp),
    srcip: textOrEmpty(alert?.data?.srcip),
    user: textOrEmpty(alert?.data?.srcuser),
    level: Number.isFinite(alert?.rule?.level) ? alert.rule.level : null,
    description: textOrEmpty(alert?.rule?.description),
  };
}

// 경보 파일을 읽어 { total, rows } 를 돌려준다. 경보 건수(total)와 뽑은 줄 수(rows.length)는 같다.
export async function readAlerts(path = DEFAULT_FIXTURE) {
  const fixture = JSON.parse(await readFile(path, 'utf8'));
  if (!Array.isArray(fixture?.alerts)) throw new Error('경보 묶음 형식이 아닙니다.');
  const rows = fixture.alerts.map(pickAlert);
  return { total: fixture.alerts.length, rows };
}

export function formatRow(row) {
  return [row.time, row.srcip || '-', row.user || '-', `수준 ${row.level ?? '-'}`, row.description].join(' | ');
}

// 직접 실행하면 뽑은 줄과 건수를 보여 준다:  node xdr/web-injection/read-alerts.mjs
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const { total, rows } = await readAlerts();
  for (const row of rows) console.log(formatRow(row));
  console.log(`경보 ${total}건, 뽑은 줄 ${rows.length}줄: ${total === rows.length ? '같음' : '다름'}`);
}
