// 보너스 XDR-02 제작 3: 경보 하나를 block / alert / record 중 하나로 가르는 판단 모듈입니다.
// 심판은 인터넷 없이 이 파일 한 개만 불러와 경보마다 바로 답을 받습니다. 그래서 이 파일은
// 다른 파일·패키지를 불러오지 않고, 파일을 읽거나 쓰지 않고, 바깥에 묻지 않고 혼자 계산합니다.
// 아래 MITRE 와 PATTERNS 는 xdr/web-injection/patterns.json 의 내용을 그대로 옮겨 적은 상수입니다.
const MITRE = { id: 'T1190', name: 'Exploit Public-Facing Application (외부 공개 앱 악용)', url: 'https://attack.mitre.org/techniques/T1190/' };

const PATTERNS = [
  {
    name: 'sql-in-request-parameter',
    title: '요청 인자 안의 SQL 구문',
    mitre: 'T1190',
    condition: {
      summary: '같은 출발 주소가 요청 인자에 SQL 구문(조회를 이어 붙이는 표기)을 여러 번 반복해 넣는다. 한 번뿐인 수업 단어나 일반 검색어는 해당하지 않는다.',
      signals: ['같은 출발 주소', '요청 인자 안의 SQL 구문', '조회를 이어 붙이는 표기', '반복'],
      clearAt: { repeats: 8 },
      suspiciousAt: { repeats: 1 },
    },
    evidence: 'MITRE ATT&CK T1190(Exploit Public-Facing Application): 공개 앱의 요청 인자에 SQL 구문을 끼워 데이터베이스를 조작하는 것이 대표 수법이며, MOVEit(CVE-2023-34362)도 SQL 주입에서 시작했다(CISA AA23-158A).',
  },
  {
    name: 'script-tag-in-request-parameter',
    title: '요청 인자 안의 스크립트 태그',
    mitre: 'T1190',
    condition: {
      summary: '같은 출발 주소가 요청 인자에 스크립트 태그(삽입 표식)를 여러 번 반복해 넣는다. 수업 단어 \'스크립트\'가 한 번 있는 것은 해당하지 않는다.',
      signals: ['같은 출발 주소', '요청 인자 안의 스크립트 태그', '삽입 표식', '반복'],
      clearAt: { repeats: 8 },
      suspiciousAt: { repeats: 1 },
    },
    evidence: 'MITRE ATT&CK T1190(Exploit Public-Facing Application): 공개 앱이 입력값을 거르지 못하는 약점을 노려 요청 인자에 스크립트 태그를 심는 형태다.',
  },
  {
    name: 'path-traversal-repeat',
    title: '경로 거슬러 올라가기(../) 반복',
    mitre: 'T1190',
    condition: {
      summary: '같은 출발 주소가 경로를 거슬러 올라가는 표기(../)를 여러 단계, 여러 번 반복한다. 경로에 \'up\' 같은 글자가 한 번 있는 것은 해당하지 않는다.',
      signals: ['같은 출발 주소', '경로 거슬러 올라가기(../)', '여러 단계', '반복'],
      clearAt: { repeats: 8 },
      suspiciousAt: { repeats: 1 },
    },
    evidence: 'MITRE ATT&CK T1190(Exploit Public-Facing Application): 경로를 거슬러 올라가는 표기(../)를 반복해 공개 앱이 허용한 폴더 밖의 파일에 닿으려는 형태다.',
  },
  {
    name: 'command-separator-in-request',
    title: '요청 인자 안의 명령 구분자',
    mitre: 'T1190',
    condition: {
      summary: '같은 출발 주소가 연속된 요청 인자에 명령 구분자 표기를 반복해 넣는다. 이름 검색의 구분 문자 한 건은 해당하지 않는다.',
      signals: ['같은 출발 주소', '요청 인자 안의 명령 구분자', '연속 요청', '반복'],
      clearAt: { repeats: 8 },
      suspiciousAt: { repeats: 1 },
    },
    evidence: 'MITRE ATT&CK T1190(Exploit Public-Facing Application): 요청 인자에 명령 구분자를 끼워 공개 앱이 서버 명령을 이어서 실행하게 만들려는 형태다.',
  },
];

const NO_PATTERN = 'no-pattern';
const BLOCK_AT = 0.85;
const ALERT_AT = 0.5;

// 설명 문장에서 어느 패턴을 말하는지 찾는 단어. PATTERNS 와 같은 순서입니다.
const KEYWORDS = [
  /SQL|select|데이터베이스|조회를 이어/iu,
  /스크립트|삽입 표식|삽입 표기/u,
  /경로|거슬러|이탈|\.\.\//u,
  /명령 구분자|구분 문자/u,
];

// 경보에서 판단에 쓸 값만 계산한다. (경보 원본은 읽기만 하고 고치지 않는다.)
function features(alert) {
  const description = typeof alert?.rule?.description === 'string' ? alert.rule.description : '';
  const data = alert?.data && typeof alert.data === 'object' ? alert.data : {};
  const mitre = Array.isArray(alert?.rule?.mitre) ? alert.rule.mitre : [];
  // 반복 횟수: data.count 가 있으면 그 값, 없으면 설명 문장의 "N번"에서 읽는다.
  const count = data.count === undefined || data.count === null || data.count === '' ? NaN : Number(data.count);
  const textCount = Number((description.match(/(\d+)\s*번/u) ?? [])[1]);
  const repeats = Number.isFinite(count) ? count : Number.isFinite(textCount) ? textCount : 0;
  const index = KEYWORDS.findIndex(word => word.test(description));
  return { repeats, index, tagged: mitre.includes(MITRE.id) };
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
  // T1190 표시도 없고 공격 표기 단어도 없으면 패턴과 맞지 않는 정상 이벤트다.
  if (!f.tagged && f.index < 0) {
    return { action: 'record', confidence: 0.1, reason: `${NO_PATTERN}: 웹 입력 공격 패턴과 맞지 않는 정상 이벤트` };
  }
  const pattern = PATTERNS[f.index >= 0 ? f.index : 0];
  let confidence = closeness(f.repeats, pattern.condition.clearAt.repeats, pattern.condition.suspiciousAt.repeats);
  // T1190 표시가 있는데 수치로는 뚜렷하지 않으면 애매한 시도(알림 선)로 본다.
  if (f.tagged && confidence < ALERT_AT) confidence = ALERT_AT;

  if (confidence < ALERT_AT) {
    return { action: 'record', confidence: 0.1, reason: `${NO_PATTERN}: 웹 입력 공격 패턴과 맞지 않는 정상 이벤트` };
  }
  const action = actionFor(confidence);
  const note = action === 'block' ? '기준 이상의 명확한 공격' : '애매한 시도';
  return { action, confidence: Math.round(confidence * 100) / 100, reason: `${pattern.name}: ${note}` };
}
