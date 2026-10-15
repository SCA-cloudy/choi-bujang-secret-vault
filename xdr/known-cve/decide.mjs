// 보너스 XDR-03 제작 3: 경보 하나를 block / alert / record 중 하나로 가르는 판단 모듈입니다.
// 심판은 인터넷 없이 이 파일 한 개만 불러와 경보마다 바로 답을 받습니다. 그래서 이 파일은
// 다른 파일·패키지를 불러오지 않고, 파일을 읽거나 쓰지 않고, 바깥에 묻지 않고 혼자 계산합니다.
// 아래 MITRE 와 PATTERNS 는 xdr/known-cve/patterns.json 의 내용을 그대로 옮겨 적은 상수입니다.
const MITRE = { id: 'T1190', name: 'Exploit Public-Facing Application (외부 공개 앱 악용)', url: 'https://attack.mitre.org/techniques/T1190/' };

const PATTERNS = [
  {
    name: 'jndi-lookup-in-header',
    title: '요청 머리글 안의 원격 조회 구문(jndi 형태)',
    mitre: 'T1190',
    condition: {
      summary: '요청 머리글(예: User-Agent)에 ${jndi:...} 형태의 원격 조회 구문이 한 번이라도 있다. 중괄호나 \'jndi\'라는 글자가 구문 없이 섞인 것은 해당하지 않는다.',
      signals: ['요청 머리글 값', 'jndi 원격 조회 구문(${jndi:...})'],
      clearAt: { occurrences: 1 },
    },
    evidence: 'CVE-2021-44228 Detail(NVD): 아파치 로그4j는 기록되는 문자열에 ${jndi:...} 구문이 있으면 그 주소로 원격 조회를 시도하며, 공격자는 User-Agent 같은 요청 머리글에 이 구문을 심어 서버가 기록하게 만든다.',
  },
  {
    name: 'jndi-lookup-in-parameter',
    title: '요청 인자 안의 원격 조회 구문(jndi 형태)',
    mitre: 'T1190',
    condition: {
      summary: '요청 주소의 인자(예: ?q=, ?next=)에 ${jndi:...} 형태의 원격 조회 구문이 한 번이라도 있다. \'CVE-2021-44228\'이나 \'jndi\' 같은 글자만 있고 구문이 없는 것은 해당하지 않는다.',
      signals: ['요청 주소 인자 값', 'jndi 원격 조회 구문(${jndi:...})'],
      clearAt: { occurrences: 1 },
    },
    evidence: 'CVE-2021-44228 Detail(NVD): 로그4j가 기록하는 입력값(요청 인자 포함)에 ${jndi:...} 구문이 있으면 그 자리에서 원격 조회가 일어나 외부 코드 실행으로 이어질 수 있다.',
  },
  {
    name: 'known-vulnerability-scan-trace',
    title: '알려진 취약점 점검 도구의 흔적',
    mitre: 'T1190',
    condition: {
      summary: '원격 조회 구문은 없지만, 점검 도구 이름과 비슷한 요청 경로나 이 취약점 이름(CVE-2021-44228)에 대한 검색처럼 공개 직후 흔한 사전 탐색 흔적이 있다. 구문 없이 단어가 한 번 스치는 것만으로는 이 신호 하나로 공격 단정은 하지 않는다.',
      signals: ['jndi 구문은 없음', '점검 도구와 비슷한 요청 경로', '취약점 이름 검색'],
      suspiciousAt: { occurrences: 1 },
    },
    evidence: '"악성코드 위험 \'아파치 로그4j\' 긴급조치"(경향신문): CVE-2021-44228 공개 직후 전 세계에서 즉시 대규모 악용·점검 시도가 벌어졌다고 보도했으며, 점검 도구 흔적은 이런 사전 탐색 신호에 해당한다.',
  },
];

const NO_PATTERN = 'no-pattern';
const BLOCK_AT = 0.85;
const ALERT_AT = 0.5;

// jndi 원격 조회 구문: ${jndi: 로 시작하는 표기. 중괄호나 'jndi' 글자만 있는 것과 구분한다.
const JNDI_LOOKUP = /\$\{jndi:/iu;
// 원격 조회 구문 없이도 알려진 취약점을 가리키는 낱말들. 일반 CRUD 동작에 흔한 '조회했습니다'는 넣지 않는다.
const SCAN_TRACE_WORD = /CVE-2021-44228|jndi|점검|취약점|라이브러리|원격 조회|조회 구문|조회 형태/iu;

// 경보에서 판단에 쓸 값만 계산한다. (경보 원본은 읽기만 하고 고치지 않는다.)
function features(alert) {
  const data = alert?.data && typeof alert.data === 'object' ? alert.data : {};
  const description = typeof alert?.rule?.description === 'string' ? alert.rule.description : '';
  const useragent = typeof data.useragent === 'string' ? data.useragent : '';
  const url = typeof data.url === 'string' ? data.url : '';
  const count = data.count === undefined || data.count === null || data.count === '' ? NaN : Number(data.count);
  const repeats = Number.isFinite(count) && count > 0 ? count : 1;

  return {
    jndiInHeader: JNDI_LOOKUP.test(useragent),
    jndiInParam: JNDI_LOOKUP.test(url),
    scanTrace: SCAN_TRACE_WORD.test(description) || SCAN_TRACE_WORD.test(useragent) || SCAN_TRACE_WORD.test(url),
    repeats,
  };
}

// jndi 구문이 실제로 있는 경우: 1건만으로 이미 기준(clearAt) 이상이므로 0.90 에서 시작해
// 반복 횟수가 많을수록 0.99 까지 올라간다.
function clearConfidence(repeats, both) {
  const base = 0.9 + 0.01 * Math.max(0, repeats - 1) + (both ? 0.03 : 0);
  return Math.min(0.99, base);
}

// jndi 구문 없이 점검 흔적만 있는 경우: suspiciousAt(0.5) 위에서 조금 움직이되,
// 구문이 없으므로 절대 block 기준(0.85)을 넘지 않는다.
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

  if (f.jndiInHeader || f.jndiInParam) {
    const pattern = f.jndiInHeader ? PATTERNS[0] : PATTERNS[1];
    const confidence = clearConfidence(f.repeats, f.jndiInHeader && f.jndiInParam);
    const action = actionFor(confidence);
    return { action, confidence: Math.round(confidence * 100) / 100, reason: `${pattern.name}: 기준 이상의 명확한 공격` };
  }

  if (f.scanTrace) {
    const pattern = PATTERNS[2];
    const confidence = suspiciousConfidence(f.repeats);
    const action = actionFor(confidence);
    return { action, confidence: Math.round(confidence * 100) / 100, reason: `${pattern.name}: 애매한 시도` };
  }

  return { action: 'record', confidence: 0.1, reason: `${NO_PATTERN}: 알려진 취약점 악용 패턴과 맞지 않는 정상 이벤트` };
}
