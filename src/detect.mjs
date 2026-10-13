// 9단계에서 학생이 채우는 탐지 함수입니다. 회수 제안만 돌려주며 어떤 접속도 직접 회수하지 않습니다.
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

// 9단계 제작 2 탐지 규칙 burst_read (docs/DETECT_EVENTS.md 의 규칙):
// - 같은 identity.sub 의 GET 사건이 어느 10분(600초) 구간에서든 120건을 넘을 때만 회수 제안을 냅니다.
//   정확히 120건은 제안하지 않습니다. 다른 사용자의 사건은 합산하지 않고, 10분 밖의 사건은 같은 묶음으로 세지 않습니다.
// - 구간은 처음 사건과 마지막 사건의 시각 차이가 600초 이하인 묶음입니다. (입력 순서는 상관없이 시각으로 정렬합니다.)
// - 지역·네트워크처럼 계약에 없는 값은 읽지 않으므로, 그런 값 하나만으로 확정하거나 막지 않습니다.
// - 여러 사용자가 동시에 넘으면 먼저 넘은 사용자 한 명만 제안합니다.
// - 이 함수는 제안만 돌려줍니다. 실제 회수는 하지 않고, 회수 API도 부르지 않습니다.
const BURST = Object.freeze({ windowMs: 10 * 60 * 1000, maxCount: 120 });

export function detect(events) {
  const bySubject = new Map();
  for (const event of readDetectionEvents(events)) {
    if (event.method !== 'GET') continue;
    if (!bySubject.has(event.sub)) bySubject.set(event.sub, []);
    bySubject.get(event.sub).push(event.atMs);
  }
  let found = null;
  for (const [sub, times] of bySubject) {
    times.sort((a, b) => a - b);
    let start = 0;
    for (let end = 0; end < times.length; end += 1) {
      while (times[end] - times[start] > BURST.windowMs) start += 1;
      if (end - start + 1 > BURST.maxCount) {
        if (!found || times[end] < found.at || (times[end] === found.at && sub < found.sub)) found = { sub, at: times[end] };
        break;
      }
    }
  }
  if (!found) return { action: 'observe' };
  return { action: 'propose_revocation', reasonCode: 'burst_read', subject: found.sub };
}
