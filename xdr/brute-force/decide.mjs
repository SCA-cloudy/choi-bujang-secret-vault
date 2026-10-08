// 보너스 XDR-01 제작 3: 경보 하나를 block / alert / record 중 하나로 가르는 판단 모듈입니다.
// 심판은 인터넷 없이 이 파일 한 개만 불러와 경보마다 바로 답을 받습니다. 그래서 이 파일은
// 다른 파일·패키지를 불러오지 않고, 파일을 읽거나 쓰지 않고, 바깥에 묻지 않고 혼자 계산합니다.
// 아래 MITRE 와 PATTERNS 는 xdr/brute-force/patterns.json 의 내용을 그대로 옮겨 적은 상수입니다.
const MITRE = { id: 'T1110', name: 'Brute Force (무차별 대입)', url: 'https://attack.mitre.org/techniques/T1110/' };

const PATTERNS = [
  {
    name: 'same-source-failure-burst',
    title: '같은 주소의 로그인 실패 연속',
    mitre: 'T1110.001',
    condition: {
      summary: '짧은 시간(몇 분 안)에 같은 출발 주소에서 로그인 실패가 연달아 쌓이고, 그 사이 성공이 없다.',
      signals: ['같은 출발 주소', '짧은 시간', '로그인 실패 연속', '성공 없음'],
      clearAt: { failures: 30 },
      suspiciousAt: { failures: 5 },
    },
    evidence: 'MITRE ATT&CK T1110.001(Password Guessing): 공격자가 계정 하나에 비밀번호를 반복해 넣어 보므로, 짧은 시간의 실패 연속이 대표 신호다.',
  },
  {
    name: 'one-password-many-accounts',
    title: '여러 계정에 같은 비밀번호 대입',
    mitre: 'T1110.003',
    condition: {
      summary: '같은 출발 주소가 서로 다른 여러 계정에 같은 비밀번호로 실패를 넣는다. 계정마다 시도 횟수는 적어도 잠금을 피하려는 형태다.',
      signals: ['같은 출발 주소', '서로 다른 여러 계정', '같은 비밀번호', '계정마다 적은 시도'],
      clearAt: { accounts: 8 },
      suspiciousAt: { accounts: 3 },
    },
    evidence: 'MITRE ATT&CK T1110.003(Password Spraying): 흔한 비밀번호 하나를 많은 계정에 차례로 넣어 계정 잠금을 피하므로, 여러 계정에 같은 비밀번호 실패가 이어지면 이 형태다.',
  },
];

const BURST = PATTERNS[0];
const SPRAY = PATTERNS[1];
const NO_PATTERN = 'no-pattern';
const BLOCK_AT = 0.85;
const ALERT_AT = 0.5;

// 경보에서 판단에 쓸 값만 계산한다. (경보 원본은 읽기만 하고 고치지 않는다.)
function features(alert) {
  const description = typeof alert?.rule?.description === 'string' ? alert.rule.description : '';
  const data = alert?.data && typeof alert.data === 'object' ? alert.data : {};
  const mitre = Array.isArray(alert?.rule?.mitre) ? alert.rule.mitre : [];
  const accountList = typeof data.accounts === 'string' ? data.accounts.split(',').filter(Boolean).length : 0;
  const accountText = Number((description.match(/계정\s*(\d+)\s*개/u) ?? [])[1]);
  const accounts = accountList || (Number.isFinite(accountText) ? accountText : 0);
  // 실패 건수: data.count 가 있으면 그 값, 없으면 설명 문장의 "실패 N건"에서 읽는다.
  const count = data.count === undefined || data.count === null || data.count === '' ? NaN : Number(data.count);
  const failureText = Number((description.match(/실패(?:가|는)?\s*(\d+)\s*건/u) ?? [])[1]);
  const failureCount = Number.isFinite(count) ? count : failureText;
  // "계정 N개" 경보의 count 는 계정 수이므로, 그때는 실패 건수로 쓰지 않는다.
  const failures = Number.isFinite(failureCount) && !accounts ? failureCount : 0;
  const noSuccess = /성공(?:은|이)?\s*없/u.test(description);
  const hasSuccess = !noSuccess && /성공/u.test(description);
  return { failures, accounts, hasSuccess, tagged: mitre.includes(MITRE.id) };
}

// 값이 기준에 얼마나 가까운지로 0~1 확신도를 만든다.
//  기준(clearAt) 이상: 0.90 ~ 0.99 (많을수록 뚜렷)
//  의심(suspiciousAt) 이상 기준 미만: 0.50 ~ 0.84 (기준에 가까울수록 높음)
//  그 아래: 0
function closeness(value, clearAt, suspiciousAt) {
  if (value >= clearAt) return Math.min(0.99, 0.9 + 0.09 * ((value - clearAt) / clearAt));
  if (value >= suspiciousAt) return 0.5 + 0.34 * ((value - suspiciousAt) / (clearAt - suspiciousAt));
  return 0;
}

function actionFor(confidence) {
  if (confidence >= BLOCK_AT) return 'block';
  if (confidence >= ALERT_AT) return 'alert';
  return 'record';
}

export function decide(alert) {
  const f = features(alert);
  const burst = closeness(f.failures, BURST.condition.clearAt.failures, BURST.condition.suspiciousAt.failures);
  const spray = closeness(f.accounts, SPRAY.condition.clearAt.accounts, SPRAY.condition.suspiciousAt.accounts);
  let pattern = spray > burst ? SPRAY : BURST;
  let confidence = Math.max(burst, spray);

  // T1110 표시가 있는데 수치로는 뚜렷하지 않으면 애매한 시도(알림 선)로 본다.
  if (f.tagged && confidence < ALERT_AT) {
    confidence = ALERT_AT;
    pattern = f.accounts > 0 ? SPRAY : BURST;
  }
  // 실패 뒤에 성공이 있으면 공격이 뚜렷하다고 단정하지 않는다. (block 선 아래로 제한)
  if (f.hasSuccess && confidence >= BLOCK_AT) confidence = 0.7;

  if (confidence < ALERT_AT) {
    return { action: 'record', confidence: 0.1, reason: `${NO_PATTERN}: 로그인 공격 패턴과 맞지 않는 정상 이벤트` };
  }
  const action = actionFor(confidence);
  const note = action === 'block' ? '기준 이상의 명확한 공격' : '애매한 시도';
  return { action, confidence: Math.round(confidence * 100) / 100, reason: `${pattern.name}: ${note}` };
}
