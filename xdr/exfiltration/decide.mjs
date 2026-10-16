// 보너스 XDR-06 제작 3: 경보 하나를 block / alert / record 중 하나로 가르는 판단 모듈입니다.
// 심판은 인터넷 없이 이 파일 한 개만 불러와 경보마다 바로 답을 받습니다. 그래서 이 파일은
// 다른 파일·패키지를 불러오지 않고, 파일을 읽거나 쓰지 않고, 바깥에 묻지 않고 혼자 계산합니다.
// 아래 MITRE 와 PATTERNS 는 xdr/exfiltration/patterns.json 의 내용을 그대로 옮겨 적은 상수입니다.
const MITRE = [
  { id: 'T1041', name: 'Exfiltration Over C2 Channel (명령 통로로 유출)', url: 'https://attack.mitre.org/techniques/T1041/' },
  { id: 'T1048', name: 'Exfiltration Over Alternative Protocol (다른 프로토콜로 유출)', url: 'https://attack.mitre.org/techniques/T1048/' },
];

const PATTERNS = [
  {
    name: 'unfamiliar-destination-bulk-transfer',
    title: '처음 보는 목적지로 대용량 전송',
    mitre: 'T1048',
    condition: {
      summary: '처음 보는 목적지로 한 번에 대용량 자료나 많은 파일 수가 나간다. 평소 쓰던 목적지로 보통 크기의 자료가 나간 것은 해당하지 않는다.',
      signals: ['처음 보는 목적지', '대용량 전송', '많은 파일 수'],
    },
    evidence: '서울신문("카드사 고객정보 1억400만건 유출...사상최대"): 카드사 시스템 구축을 맡아 파견된 차장은 처음 보는 외부 경로로 KB국민카드 5,300만 건 등 1억 400만여 건의 고객정보를 옮겨 유출했다 — MITRE ATT&CK T1048(Exfiltration Over Alternative Protocol).',
  },
  {
    name: 'after-hours-archive-exfil',
    title: '업무 시간 밖 압축 파일 반출',
    mitre: 'T1048',
    condition: {
      summary: '업무처럼 보이지 않는 시각(수업 시간 밖)에 압축 파일이 외부로 나간다. 압축만 만들고 외부 전송은 아직 없는 경우는 해당하지 않는다.',
      signals: ['업무 시간 밖', '압축 파일 반출'],
    },
    evidence: '한국일보("카드사 보안망 뻥... 고객 정보 1억건 털렸다"): 파견 근무자는 2012년 10월부터 2013년 12월까지 업무 시간 안팎을 가리지 않고 고객정보를 압축해 USB로 옮겨 반출했다 — MITRE ATT&CK T1048(Exfiltration Over Alternative Protocol).',
  },
  {
    name: 'repeated-destination-transfer',
    title: '같은 목적지로 반복되는 전송',
    mitre: 'T1041',
    condition: {
      summary: '같은 목적지나 통로로 전송이 여러 번(반복 횟수 많음) 이어진다. 전송량이 한 번만 높아졌거나 목적지가 바뀌며 한 번만 일어난 것은 해당하지 않는다.',
      signals: ['같은 목적지 반복 전송', '명령 통로를 통한 반복 전송'],
    },
    evidence: '서울신문("카드사 고객정보 1억400만건 유출...사상최대"): 유출은 한 번이 아니라 2012년 10월부터 2013년 12월까지 반복된 작업으로 이뤄져, 같은 통로로 대량의 자료가 여러 차례 옮겨졌다 — MITRE ATT&CK T1041(Exfiltration Over C2 Channel).',
  },
];

const NO_PATTERN = 'no-pattern';
const BLOCK_AT = 0.85;
const ALERT_AT = 0.5;

// 설명이 "명확한 공격"으로 볼 만한 낱말을 담고 있는지. "외부 전송은 아직 없다", "실패로 끝났다",
// "일부만", "작은 파일", "평소 목적지"처럼 아직 끝나지 않았거나 평소 범위인 시도는 넣지 않는다
// (뚜렷하게 이어진 전송만 넣는다).
const STRONG_WORD = /자료\s*\d+건이 처음 보는 목적지로|수업 시간 밖에[\s\S]*처음 보는 주소로|대용량 전송이 \d+번 반복|쓰지 않던 포트로[\s\S]*연속 전송|처음 보는 목적지로 메모 묶음|업무 시간 밖에 같은 목적지로 전송이 \d+번|연속으로 처음 보는 주소에|자료실 전체가 외부 주소로 복사|명령 통로로 큰 파일이 처음 보는 목적지에 반복 전송|처음 보는 목적지 두 곳으로/u;

// mitre 꼬리표가 붙었어도 뜻이 뚜렷하게 정상인 경보(예: 평소 수업 자료 주소로의 작은 동기화)는
// 애매한 시도로도 넣지 않는다.
const NORMAL_WORD = /작은 동기화가 끝났습니다/u;

const MENTIONS_REPEAT = /반복|연속|\d+번/u;
const MENTIONS_AFTER_HOURS = /업무 시간 밖|수업 시간 밖/u;

// 경보에서 판단에 쓸 값만 계산한다. (경보 원본은 읽기만 하고 고치지 않는다.)
function features(alert) {
  const data = alert?.data && typeof alert.data === 'object' ? alert.data : {};
  const description = typeof alert?.rule?.description === 'string' ? alert.rule.description : '';
  const mitreTags = Array.isArray(alert?.rule?.mitre) ? alert.rule.mitre : [];
  const count = data.count === undefined || data.count === null || data.count === '' ? NaN : Number(data.count);
  const repeats = Number.isFinite(count) && count > 0 ? count : 1;
  const normal = NORMAL_WORD.test(description);

  return {
    strong: STRONG_WORD.test(description),
    mitreTagged: mitreTags.length >= 1 && !normal,
    afterHours: MENTIONS_AFTER_HOURS.test(description),
    repeat: MENTIONS_REPEAT.test(description),
    repeats,
  };
}

// 설명이 가리키는 패턴을 고른다: 반복 전송 > 업무 시간 밖 > 처음 보는 목적지 순.
function patternFor(f) {
  if (f.repeat) return PATTERNS[2];
  if (f.afterHours) return PATTERNS[1];
  return PATTERNS[0];
}

// 한 번만 뚜렷해도 기준(block) 이상이므로 0.90 에서 시작해, 반복 횟수(전송·접속 횟수)가
// 늘수록 0.99 까지 올라간다.
function clearConfidence(repeats) {
  const base = 0.9 + 0.01 * Math.max(0, repeats - 1);
  return Math.min(0.99, base);
}

// 애매한 시도: suspiciousAt(0.5) 위에서 조금 움직이되, 뚜렷한 낱말이 없으므로 block 기준을 넘지 않는다.
function suspiciousConfidence(repeats) {
  return Math.min(0.75, ALERT_AT + 0.05 * Math.max(0, repeats - 1));
}

function actionFor(confidence) {
  if (confidence >= BLOCK_AT) return 'block';
  if (confidence >= ALERT_AT) return 'alert';
  return 'record';
}

export function decide(alert) {
  const f = features(alert);

  if (f.strong) {
    const pattern = patternFor(f);
    const confidence = clearConfidence(f.repeats);
    const action = actionFor(confidence);
    return { action, confidence: Math.round(confidence * 100) / 100, reason: `${pattern.name}: 기준 이상의 명확한 공격` };
  }

  if (f.mitreTagged) {
    const pattern = patternFor(f);
    const confidence = suspiciousConfidence(f.repeats);
    const action = actionFor(confidence);
    return { action, confidence: Math.round(confidence * 100) / 100, reason: `${pattern.name}: 애매한 시도` };
  }

  return { action: 'record', confidence: 0.1, reason: `${NO_PATTERN}: 자료 빼돌리기 패턴과 맞지 않는 정상 이벤트` };
}
