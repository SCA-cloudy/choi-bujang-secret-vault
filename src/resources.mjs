// 8단계 제작 1: 자료를 종류별 "자원 ID"로 나눕니다. 이번 단계는 표시만 하며 허용·거부는 하지 않습니다.
// - 자원 ID는 요청의 경로 모양(route)에서만 정해집니다. 쿼리, 요청 본문, 화면 메뉴, role 같은 값은 읽지 않습니다.
// - 표에 없는 경로는 null(알 수 없음)입니다. 알 수 없는 경로를 어느 자원으로 추측해 채우지 않습니다.
// - 기존 주소와 allowedRoutes는 그대로입니다. 강사 공지 경로는 아직 서비스하지 않으며, 이름만 미리 정해 둡니다.
export const RESOURCE_IDS = Object.freeze({
  ownNote: 'note.own',                 // 내 자료실의 메모 (소유자 본인 구역)
  instructorNotice: 'notice.instructor', // 강사 공지 (강사만 고칠 수 있는 구역)
});

const ROUTE_RESOURCES = Object.freeze({
  'GET /notes': RESOURCE_IDS.ownNote,
  'POST /notes': RESOURCE_IDS.ownNote,
  'GET /notes/:id': RESOURCE_IDS.ownNote,
  'PUT /notes/:id': RESOURCE_IDS.ownNote,
  'DELETE /notes/:id': RESOURCE_IDS.ownNote,
  'GET /notices': RESOURCE_IDS.instructorNotice,
  'GET /notices/:id': RESOURCE_IDS.instructorNotice,
  'PUT /notices/:id': RESOURCE_IDS.instructorNotice,
});

// 'GET /api/notes/:id'와 'GET /notes/:id' 두 표기를 같은 경로로 봅니다. (앞의 /api/ 하나만 떼어 냅니다.)
export function resourceIdOf(route) {
  if (typeof route !== 'string') return null;
  const shape = route.replace(/^([A-Z]+) \/api\//u, '$1 /');
  return Object.hasOwn(ROUTE_RESOURCES, shape) ? ROUTE_RESOURCES[shape] : null;
}
