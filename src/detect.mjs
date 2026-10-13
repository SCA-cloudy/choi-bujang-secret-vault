// 9단계에서 학생이 채우는 탐지 함수입니다. 아직 어떤 접속도 회수하지 않습니다.
// 반 엔진이 검증한 사건만 전달해야 하며, 브라우저가 보낸 사용자 번호는 받지 않습니다.
//
// 9단계 제작 1 입력 처리: docs/DETECT_EVENTS.md 가 정한 세 값만 읽습니다.
// - at(UTC ISO 시각), method(요청 종류), identity.sub(엔진이 확인한 가명 사용자)
// - 사건에 토큰·본문·이름·헤더·기기 값 같은 다른 이름이 덧붙어 있어도 읽지도, 복사하지도, 출력하지도 않습니다.
// - 모양이 맞지 않는 사건은 버리고, 값을 대신 채워 넣지 않습니다.
// - 오류 문구에는 사건의 내용을 담지 않습니다.
const MAX_EVENTS = 100000;
const ISO_UTC = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,3})?Z$/u;
const METHOD = /^[A-Z]{3,7}$/u;
const SUBJECT = /^[A-Za-z0-9_.-]{1,64}$/u;
const isPlain = value => value !== null && typeof value === 'object' && !Array.isArray(value);

export function readDetectionEvents(events) {
  if (!Array.isArray(events)) throw new TypeError('invalid_detection_events');
  const read = [];
  for (const event of events.slice(0, MAX_EVENTS)) {
    if (!isPlain(event) || !isPlain(event.identity)) continue;
    const { at, method } = event;
    const { sub } = event.identity;
    if (typeof at !== 'string' || !ISO_UTC.test(at) || typeof method !== 'string' || !METHOD.test(method)
        || typeof sub !== 'string' || !SUBJECT.test(sub)) continue;
    const atMs = Date.parse(at);
    if (!Number.isFinite(atMs)) continue;
    read.push({ atMs, method, sub });
  }
  return read;
}

export function detect(events) {
  readDetectionEvents(events);
  return { action: 'observe' };
}
