// 10단계 제작 2: 검증한 안전 정책 사본으로 시험 정책을 되돌릴 때 "무엇을 어디까지" 바꾸는지 정합니다.
// - 파일 읽기·쓰기를 하지 않는 순수 함수입니다. 실제로 쓰는 일은 scripts/policy-restore.mjs가 합니다.
// - 되돌리는 대상은 정책 파일 세 곳뿐입니다. 그 밖의 서비스 규칙, 감사 기록, 자료는 건드리지 않습니다.
//   · ruleIds·decisions 가 달라졌으면 판정기 파일(src/decider.mjs, src/resources.mjs)을 사본 커밋 시점 내용으로
//   · allowedRoutes 가 달라졌으면 aleph.config.json 의 allowedRoutes 항목 하나만(step, judgeIssuer, restoreRoute 등은 그대로)

const DECIDER_FILES = Object.freeze(['src/decider.mjs', 'src/resources.mjs']);
const CONFIG_FILE = 'aleph.config.json';

// diff(diffPolicy의 결과)로부터 바뀔 대상을 고릅니다. 변경이 없으면 빈 목록입니다.
export function planRestore(diff) {
  const areas = new Set(diff.changes.map(change => change.area));
  const targets = [];
  if (areas.has('ruleIds') || areas.has('decisions')) {
    for (const file of DECIDER_FILES) targets.push({ kind: 'file', file, field: null });
  }
  if (areas.has('allowedRoutes')) targets.push({ kind: 'field', file: CONFIG_FILE, field: 'allowedRoutes' });
  return targets;
}

// 현재 순서를 최대한 지키면서, 사본에 없는 경로는 빼고 빠진 경로는 사본 순서대로 뒤에 붙입니다.
export function mergeRoutes(currentRoutes, safeRoutes) {
  const keep = (Array.isArray(currentRoutes) ? currentRoutes : []).filter(route => safeRoutes.includes(route));
  return [...keep, ...safeRoutes.filter(route => !keep.includes(route))];
}

// 줄바꿈 방식(LF/CRLF)을 기존 파일에 맞춥니다.
export function matchEol(text, like) {
  const plain = text.replace(/\r\n/gu, '\n');
  return like.includes('\r\n') ? plain.replace(/\n/gu, '\r\n') : plain;
}

// 설정 파일에서 allowedRoutes 하나만 사본 값으로 바꾼 새 글자열을 돌려줍니다. 다른 값과 줄바꿈 방식은 그대로입니다.
export function setAllowedRoutes(configText, safeRoutes) {
  const config = JSON.parse(configText);
  config.allowedRoutes = mergeRoutes(config.allowedRoutes, safeRoutes);
  return matchEol(`${JSON.stringify(config, null, 2)}\n`, configText);
}
