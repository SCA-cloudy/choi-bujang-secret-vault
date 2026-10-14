// 11단계 제작 2: 승인된 기기의 요청 서명을 서버에서 확인합니다.
// - 화면은 밖으로 꺼낼 수 없는 기기 키(ECDSA P-256)를 메모리에만 두고, 공개 키만 서버에 보냅니다.
// - 기기 번호는 공개 키(crv, x, y)에서 계산한 sha256의 앞 16자리(소문자 16진수)입니다. 판정기 계약의 deviceId 모양과 같습니다.
// - 보호 요청마다 화면은 "BYTEBACK-DEVICE-V1, 방식, 경로, 시각, 본문 sha256"을 기기 키로 서명해 헤더 세 개로 보냅니다.
//   서버는 승인된(approved) 기기인지, 그 기기의 공개 키로 서명이 맞는지, 시각이 2분 안인지 확인합니다.
//   서명 없음·경로 변경·본문 변경·승인 대기·남의 기기는 모두 403이며 자료를 주지 않습니다.
// - 승인은 서버 코드가 하지 않습니다. 학생이 SQL Editor에서 devices.status를 approved로 바꿉니다.
// - 서버 기록에는 짧은 이유 코드만 남기고 기기 번호·공개 키·서명·사용자 ID는 남기지 않습니다.
import { createHash, createPublicKey, verify } from 'node:crypto';

export const SIGNATURE_VERSION = 'BYTEBACK-DEVICE-V1';
export const MAX_SKEW_MS = 2 * 60 * 1000;
const B64URL_32 = /^[A-Za-z0-9_-]{43}$/u;
const DEVICE_ID = /^[0-9a-f]{16}$/u;
const SIGNATURE = /^[A-Za-z0-9_-]{86}$/u; // P-256 ECDSA 서명 r||s 64바이트의 base64url

const sha256Hex = text => createHash('sha256').update(text, 'utf8').digest('hex');

// 공개 키만 받는다(개인키 d가 있으면 거부). P-256 좌표 x, y가 base64url 32바이트여야 한다.
export function publicJwk(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return null;
  if (value.kty !== 'EC' || value.crv !== 'P-256' || 'd' in value) return null;
  if (typeof value.x !== 'string' || typeof value.y !== 'string' || !B64URL_32.test(value.x) || !B64URL_32.test(value.y)) return null;
  const jwk = { kty: 'EC', crv: 'P-256', x: value.x, y: value.y };
  try { createPublicKey({ key: jwk, format: 'jwk' }); } catch { return null; }
  return jwk;
}

export const deviceIdOf = jwk => sha256Hex(`${jwk.crv}|${jwk.x}|${jwk.y}`).slice(0, 16);

// 서명할 글자열. 화면(public/index.html)과 같은 순서·같은 줄바꿈이어야 한다.
export function canonicalRequest({ method, path, timestamp, bodySha256 }) {
  return [SIGNATURE_VERSION, method, path, String(timestamp), bodySha256].join('\n');
}

// 서버가 받은 본문을 화면이 서명한 글자열로 되돌린다. 본문이 없거나 빈 객체면 빈 글자열.
export function bodyText(body) {
  if (body === undefined || body === null || body === '') return '';
  if (typeof body === 'string') return body;
  if (typeof body === 'object' && !Array.isArray(body) && Object.keys(body).length === 0) return '';
  return JSON.stringify(body);
}

const header = (request, name) => {
  const value = request.headers?.[name];
  return typeof value === 'string' ? value : Array.isArray(value) ? value[0] : undefined;
};

// 요청 경로: 서명은 쿼리를 뺀 경로(pathname)에 묶는다. 경로 끝의 메모 번호와 다른 id를 쿼리로 끼워 넣어
// 서명한 경로와 다른 대상을 고르는 것을 막기 위해, query.id가 있으면 경로의 마지막 조각과 같아야 한다.
function signedPath(request) {
  const url = typeof request.url === 'string' ? request.url : '';
  if (!url.startsWith('/') || url.startsWith('//')) return null;
  let pathname;
  try { pathname = new URL(url, 'http://local.invalid').pathname; } catch { return null; }
  const id = request.query?.id;
  if (id !== undefined) {
    const last = decodeURIComponent(pathname.split('/').pop() ?? '');
    if (typeof id !== 'string' || id.toLowerCase() !== last.toLowerCase()) return null;
  }
  return pathname;
}

// 기기 확인. 통과하면 { ok: true, deviceId, status }, 아니면 { ok: false, status: 403, error, reason }.
// allowPending: 상태 확인(/api/device/status)처럼 승인 대기 기기도 자기 상태는 볼 수 있게 할 때만 true.
export async function checkDevice(request, identity, { store, now = () => Date.now(), allowPending = false } = {}) {
  const deny = (error, reason = error) => ({ ok: false, status: 403, error, reason });
  const deviceId = header(request, 'x-device-id');
  const time = header(request, 'x-device-time');
  const signature = header(request, 'x-device-signature');
  if (!deviceId || !time || !signature) return deny('DEVICE_SIGNATURE_REQUIRED');
  if (!DEVICE_ID.test(deviceId) || !/^[0-9]{13}$/u.test(time) || !SIGNATURE.test(signature)) return deny('DEVICE_SIGNATURE_INVALID', 'DEVICE_HEADER_FORMAT');
  if (Math.abs(now() - Number(time)) > MAX_SKEW_MS) return deny('DEVICE_SIGNATURE_INVALID', 'DEVICE_TIME_SKEW');
  const path = signedPath(request);
  if (!path) return deny('DEVICE_SIGNATURE_INVALID', 'DEVICE_PATH_MISMATCH');
  const row = await store.getDevice(deviceId);
  if (!row || row.owner_id !== identity.userId || row.status === 'revoked') return deny('DEVICE_NOT_REGISTERED');
  const jwk = publicJwk(row.public_key);
  if (!jwk || deviceIdOf(jwk) !== deviceId) return deny('DEVICE_NOT_REGISTERED', 'DEVICE_KEY_INVALID');
  const message = canonicalRequest({ method: request.method, path, timestamp: time, bodySha256: sha256Hex(bodyText(request.body)) });
  let valid = false;
  try {
    valid = verify('sha256', Buffer.from(message, 'utf8'), { key: createPublicKey({ key: jwk, format: 'jwk' }), dsaEncoding: 'ieee-p1363' },
      Buffer.from(signature, 'base64url'));
  } catch { valid = false; }
  if (!valid) return deny('DEVICE_SIGNATURE_INVALID');
  if (row.status !== 'approved' && !allowPending) return deny('DEVICE_NOT_APPROVED');
  return { ok: true, deviceId, status: row.status };
}

// 보호 경로에서 쓰는 도우미: 통과하지 못하면 403으로 답하고 false.
export async function requireDevice(request, response, identity, options) {
  let result;
  try { result = await checkDevice(request, identity, options); } catch { result = { ok: false, status: 503, error: 'DEVICE_CHECK_UNAVAILABLE', reason: 'DEVICE_STORE_ERROR' }; }
  if (result.ok) return result;
  console.error(`device: 거부 사유=${result.reason}`);
  response.status(result.status).json({ error: result.error });
  return null;
}
