// 보너스 XDR-05 제작 3: 경보 하나를 block / alert / record 중 하나로 가르는 판단 모듈입니다.
// 심판은 인터넷 없이 이 파일 한 개만 불러와 경보마다 바로 답을 받습니다. 그래서 이 파일은
// 다른 파일·패키지를 불러오지 않고, 파일을 읽거나 쓰지 않고, 바깥에 묻지 않고 혼자 계산합니다.
// 아래 MITRE 와 PATTERNS 는 xdr/privilege/patterns.json 의 내용을 그대로 옮겨 적은 상수입니다.
const MITRE = [
  { id: 'T1068', name: 'Exploitation for Privilege Escalation (권한 상승 악용)', url: 'https://attack.mitre.org/techniques/T1068/' },
  { id: 'T1078', name: 'Valid Accounts (정상 계정 도용)', url: 'https://attack.mitre.org/techniques/T1078/' },
];

const PATTERNS = [
  {
    name: 'admin-group-addition',
    title: '평범한 계정의 관리자 그룹 추가',
    mitre: 'T1078',
    condition: {
      summary: '평범한 계정이 관리자 그룹에 새로 들어가고, 곧바로 또는 같은 흐름에서 관리자 명령이 이어진다. 그룹 설명만 바뀌거나 과제 그룹처럼 관리자가 아닌 그룹에 추가되는 것은 해당하지 않는다.',
      signals: ['관리자 그룹 추가', '평범한 계정', '추가 직후 관리자 명령'],
    },
    evidence: 'Microsoft Security Blog("Midnight Blizzard: Guidance for responders on nation-state attack"): 공격자는 2단계 인증 없는 오래된 테스트 계정을 뚫은 뒤, 회사 환경에 남아 있던 OAuth 앱의 높은 권한을 장악해 관리자급 접근을 얻었다 — MITRE ATT&CK T1078(Valid Accounts).',
  },
  {
    name: 'unfamiliar-admin-command',
    title: '처음 보는 주소·계정의 관리자 명령',
    mitre: 'T1068',
    condition: {
      summary: '방금 권한이 바뀌었거나 평소 쓰지 않던 주소·계정에서 관리자 명령이 실행된다. 평소 주소에서 실행된 관리자 명령 한 건은 해당하지 않는다.',
      signals: ['처음 보는 관리자 명령', '방금 바뀐 권한', '낯선 주소·계정'],
    },
    evidence: '머니S("마이크로소프트 고위 직원, 러시아 단체로부터 이메일 해킹...담당 직원 계좌 등 포함"): 공격자는 장악한 권한으로 새 앱을 만들어 Exchange Online 메일에 접근하는 등, 평소 쓰지 않던 권한을 곧바로 행사했다 — MITRE ATT&CK T1068(Exploitation for Privilege Escalation).',
  },
  {
    name: 'after-hours-privilege-use',
    title: '업무 시간 밖 권한 사용',
    mitre: 'T1078',
    condition: {
      summary: '업무처럼 보이지 않는 시각에 권한 상승과 관리자 명령이 함께 일어난다. 수업(업무) 시간 안에서 뜨고 취소된 상승 창 하나는 해당하지 않는다.',
      signals: ['업무 시간 밖 권한 사용', '권한 상승과 명령이 함께 발생'],
    },
    evidence: 'Microsoft Security Blog("Midnight Blizzard: Guidance for responders on nation-state attack"): 공격자는 평소 쓰지 않는 오래된 테스트 계정을 평소와 다른 흐름으로 움직여 들키지 않고 오래 머물렀다 — MITRE ATT&CK T1078(Valid Accounts).',
  },
];

const NO_PATTERN = 'no-pattern';
const BLOCK_AT = 0.85;
const ALERT_AT = 0.5;

// 설명이 "명확한 공격"으로 볼 만한 낱말을 담고 있는지. "창이 떴다가 취소", "변경은 없다", "실패로 끝났다"
// 처럼 되돌려지거나 끝나지 않은 시도는 넣지 않는다(뚜렷하게 이어진 것만 넣는다).
const STRONG_WORD = /관리자 그룹.{0,3}(추가|들어가)|방금 관리자가 된|관리자 권한으로 바뀌었고|처음 보는 주소|다른 계정의 권한으로|업무처럼 보이지 않는 시각|빠진 계정이[\s\S]*다시 관리자로/u;

const MENTIONS_AFTER_HOURS = /업무처럼 보이지 않는 시각|수업 시간 밖/u;
const MENTIONS_GROUP = /관리자 그룹|다시 관리자로/u;

// 경보에서 판단에 쓸 값만 계산한다. (경보 원본은 읽기만 하고 고치지 않는다.)
function features(alert) {
  const data = alert?.data && typeof alert.data === 'object' ? alert.data : {};
  const description = typeof alert?.rule?.description === 'string' ? alert.rule.description : '';
  const mitreTags = Array.isArray(alert?.rule?.mitre) ? alert.rule.mitre : [];
  const count = data.count === undefined || data.count === null || data.count === '' ? NaN : Number(data.count);
  const repeats = Number.isFinite(count) && count > 0 ? count : 1;

  return {
    strong: STRONG_WORD.test(description),
    mitreTagged: mitreTags.length >= 1,
    both: mitreTags.length >= 2,
    afterHours: MENTIONS_AFTER_HOURS.test(description),
    group: MENTIONS_GROUP.test(description),
    repeats,
  };
}

// 설명이 가리키는 패턴을 고른다: 업무 시간 밖 > 관리자 그룹 추가 > 관리자 명령 순.
function patternFor(f) {
  if (f.afterHours) return PATTERNS[2];
  if (f.group) return PATTERNS[0];
  return PATTERNS[1];
}

// 한 번만 뚜렷해도 기준(block) 이상이므로 0.90 에서 시작해, 반복 횟수(같은 주소의 계정 수 등)와
// 서로 다른 MITRE 기법 두 가지가 함께 표시될수록 0.99 까지 올라간다.
function clearConfidence(repeats, both) {
  const base = 0.9 + 0.01 * Math.max(0, repeats - 1) + (both ? 0.03 : 0);
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
    const confidence = clearConfidence(f.repeats, f.both);
    const action = actionFor(confidence);
    return { action, confidence: Math.round(confidence * 100) / 100, reason: `${pattern.name}: 기준 이상의 명확한 공격` };
  }

  if (f.mitreTagged) {
    const pattern = patternFor(f);
    const confidence = suspiciousConfidence(f.repeats);
    const action = actionFor(confidence);
    return { action, confidence: Math.round(confidence * 100) / 100, reason: `${pattern.name}: 애매한 시도` };
  }

  return { action: 'record', confidence: 0.1, reason: `${NO_PATTERN}: 권한 가로채기 패턴과 맞지 않는 정상 이벤트` };
}
