// 보너스 XDR-04 제작 3: 경보 하나를 block / alert / record 중 하나로 가르는 판단 모듈입니다.
// 심판은 인터넷 없이 이 파일 한 개만 불러와 경보마다 바로 답을 받습니다. 그래서 이 파일은
// 다른 파일·패키지를 불러오지 않고, 파일을 읽거나 쓰지 않고, 바깥에 묻지 않고 혼자 계산합니다.
// 아래 MITRE 와 PATTERNS 는 xdr/persistence/patterns.json 의 내용을 그대로 옮겨 적은 상수입니다.
const MITRE = [
  { id: 'T1543', name: 'Create or Modify System Process (시스템 프로세스 생성·변경)', url: 'https://attack.mitre.org/techniques/T1543/' },
  { id: 'T1053', name: 'Scheduled Task/Job (예약 작업)', url: 'https://attack.mitre.org/techniques/T1053/' },
];

const PATTERNS = [
  {
    name: 'unsigned-new-service-registration',
    title: '서명 없는 새 서비스 등록',
    mitre: 'T1543',
    condition: {
      summary: '평소 목록에 없던 서비스가 서명 없이 새로 등록되고, 임시 폴더 같은 낯선 위치의 실행 파일을 가리킨다. 기존 서비스의 설명만 바뀌는 것은 해당하지 않는다.',
      signals: ['서명 없는 새 서비스 등록', '낯선 위치(임시 폴더 등)의 실행 파일', '평소 목록에 없음'],
    },
    evidence: 'Mandiant("Highly Evasive Attacker Leverages SolarWinds Supply Chain to Compromise Multiple Global Victims With SUNBURST Backdoor"): SUNBURST는 정상 서명된 오리온 업데이트에 실려 들어온 뒤 별도의 악성 서비스로 오래 머물렀다 — MITRE ATT&CK T1543(Create or Modify System Process).',
  },
  {
    name: 'unfamiliar-scheduled-task',
    title: '낯선 예약 작업',
    mitre: 'T1053',
    condition: {
      summary: '처음 보는 예약 작업이 수업 시간 밖에, 또는 임의 문자열에 가까운 이름으로 임시 폴더의 프로그램을 실행한다. 수업 중 평범하게 만든 예약 작업 하나는 해당하지 않는다.',
      signals: ['처음 보는 예약 작업', '수업 시간 밖 실행', '임시 폴더 프로그램 실행'],
    },
    evidence: '전자신문("솔라윈즈 백도어에 MS도 당했다...MS \'글로벌 보안 대응 촉구\'"): 공격자는 예약 작업을 잠깐 바꿨다 되돌리는 식으로 명령을 받고 오래 머물렀다고 보도 — MITRE ATT&CK T1053(Scheduled Task/Job).',
  },
  {
    name: 'startup-folder-change',
    title: '시작 폴더(자동 실행 목록) 변경',
    mitre: 'T1543',
    condition: {
      summary: '시작 폴더 또는 시작 프로그램 목록에 평소 없던 항목이 새로 추가된다. 시작 프로그램 목록을 읽기만 한 것은 해당하지 않는다.',
      signals: ['시작 폴더 변경', '평소 목록에 없는 항목 추가'],
    },
    evidence: 'Mandiant 보고서: 공격자는 정상 소프트웨어처럼 보이는 자동 실행 경로에 심어 다시 켜도 살아남으려 했다 — MITRE ATT&CK T1543(Create or Modify System Process)이 다루는 자동 실행 메커니즘 변경에 해당.',
  },
];

const NO_PATTERN = 'no-pattern';
const BLOCK_AT = 0.85;
const ALERT_AT = 0.5;

// 설명이 "명확한 공격"으로 볼 만한 낱말을 담고 있는지. 서명이 "확인되지 않았다"/"아직 모른다"처럼
// 애매하게 표현된 것은 넣지 않는다(명확히 "없다"고 한 것만 넣는다).
const STRONG_WORD = /서명 없|서명이 없|처음 보는|평소 목록에 없는|임의 문자열|다시 켜도 남도록|연속으로/u;
// 정상 사용으로 못 박는 표현. 이 표현이 있으면 서비스·예약 작업 낱말이나 MITRE 표시가 있어도 정상(record)으로 둔다.
const NORMAL_WORD = /서명된 채로|평소 시각에 그대로|읽기만 했습니다|평소 저장소에서 끝났습니다|수업 자료 복사를 마쳤습니다|로그인했습니다|로그아웃했습니다|자료실 화면이 열렸습니다/u;

const MENTIONS_SERVICE = /서비스/u;
const MENTIONS_TASK = /예약 작업/u;
const MENTIONS_STARTUP = /시작 폴더|시작 프로그램|시작 항목/u;

// 경보에서 판단에 쓸 값만 계산한다. (경보 원본은 읽기만 하고 고치지 않는다.)
function features(alert) {
  const data = alert?.data && typeof alert.data === 'object' ? alert.data : {};
  const description = typeof alert?.rule?.description === 'string' ? alert.rule.description : '';
  const mitreTags = Array.isArray(alert?.rule?.mitre) ? alert.rule.mitre : [];
  const count = data.count === undefined || data.count === null || data.count === '' ? NaN : Number(data.count);
  const repeats = Number.isFinite(count) && count > 0 ? count : 1;

  const mentionsStartup = MENTIONS_STARTUP.test(description);
  const mentionsTask = MENTIONS_TASK.test(description);
  const mentionsService = MENTIONS_SERVICE.test(description);

  return {
    normal: NORMAL_WORD.test(description),
    // 서로 다른 지속성 수법 두 가지(서비스+예약 작업 등)가 한 경보에 함께 나타나면,
    // 글자로 "서명 없음"이라 적혀 있지 않아도 그 자체가 뚜렷한 신호다.
    strong: STRONG_WORD.test(description) || mitreTags.length >= 2,
    mitreTagged: mitreTags.length >= 1,
    mentionsStartup,
    mentionsTask,
    mentionsService,
    both: mentionsStartup && mentionsTask,
    repeats,
  };
}

// 설명이 가리키는 패턴을 고른다: 시작 폴더 > 예약 작업 > 서비스 순. 아무 낱말도 없으면 서비스 패턴을 기본으로 쓴다.
function patternFor(f) {
  if (f.mentionsStartup) return PATTERNS[2];
  if (f.mentionsTask) return PATTERNS[1];
  return PATTERNS[0];
}

// jndi 구문과 달리 반복 횟수(count)만 있고 기준(clearAt)은 "한 번만 있어도 뚜렷함" 이므로
// 0.90 에서 시작해 반복이 많을수록, 수법이 두 가지 겹칠수록 0.99 까지 올라간다.
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

  // 정상으로 못 박는 표현이 있으면, 서비스·예약 작업 낱말이나 MITRE 표시가 섞여 있어도 정상이다.
  if (f.normal) {
    return { action: 'record', confidence: 0.1, reason: `${NO_PATTERN}: 몰래 심은 프로그램 패턴과 맞지 않는 정상 이벤트` };
  }

  if (f.strong) {
    const pattern = patternFor(f);
    const confidence = clearConfidence(f.repeats, f.both);
    const action = actionFor(confidence);
    return { action, confidence: Math.round(confidence * 100) / 100, reason: `${pattern.name}: 기준 이상의 명확한 공격` };
  }

  if (f.mitreTagged && (f.mentionsService || f.mentionsTask || f.mentionsStartup)) {
    const pattern = patternFor(f);
    const confidence = suspiciousConfidence(f.repeats);
    const action = actionFor(confidence);
    return { action, confidence: Math.round(confidence * 100) / 100, reason: `${pattern.name}: 애매한 시도` };
  }

  return { action: 'record', confidence: 0.1, reason: `${NO_PATTERN}: 몰래 심은 프로그램 패턴과 맞지 않는 정상 이벤트` };
}
