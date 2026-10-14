// 11단계 제작 2: 기기 승인 요청(POST /api/device/request)과 상태 확인(GET /api/device/status).
// - 둘 다 로그인이 먼저입니다. 로그인하지 않으면 401.
// - 승인 요청은 공개 키(개인키 없는 JWK)와 그 키로 만든 요청 서명을 받아, 키를 정말 가진 기기인지 확인한 뒤
//   devices 표에 "승인 대기(pending)"로만 적습니다. 이 요청으로 권한이 생기지 않습니다. 승인은 SQL Editor에서만 합니다.
// - 상태 확인은 서명한 요청으로 이 기기의 상태(pending/approved)만 알려 줍니다. 자료는 주지 않습니다.
import { checkDevice, deviceIdOf, publicJwk, requireDevice } from './device-auth.mjs';
import { createSupabaseStore, defaultVerifyAuthorization } from './notes-api.mjs';

const log = text => console.error(`device: ${text}`);

function readJsonBody(request) {
  let value = request.body;
  if (typeof value === 'string') { try { value = JSON.parse(value); } catch { return null; } }
  return value && typeof value === 'object' && !Array.isArray(value) ? value : null;
}

export function createDeviceHandlers({ verifyAuthorization, store, now }) {
  async function login(request, response) {
    let identity = null;
    try { identity = await verifyAuthorization(request.headers?.authorization); } catch { log('로그인 검사를 끝내지 못했습니다.'); }
    if (!identity) {
      response.setHeader('WWW-Authenticate', 'Bearer');
      response.status(401).json({ error: 'LOGIN_REQUIRED' });
    }
    return identity;
  }
  const prepare = (request, response, method) => {
    response.setHeader('Cache-Control', 'no-store');
    response.setHeader('Vary', 'Authorization');
    if (request.method === method) return true;
    response.setHeader('Allow', method);
    response.status(405).json({ error: 'METHOD_NOT_ALLOWED' });
    return false;
  };

  async function requestApproval(request, response) {
    if (!prepare(request, response, 'POST')) return;
    const identity = await login(request, response);
    if (!identity) return;
    const value = readJsonBody(request);
    if (!value || Object.keys(value).some(name => name !== 'publicKey' && name !== 'label')) {
      return response.status(400).json({ error: 'INVALID_DEVICE_REQUEST' });
    }
    const jwk = publicJwk(value.publicKey);
    const label = value.label === undefined ? '' : value.label;
    if (!jwk || typeof label !== 'string' || label.length > 60) return response.status(400).json({ error: 'INVALID_DEVICE_REQUEST' });
    const deviceId = deviceIdOf(jwk);
    // 이 공개 키의 개인키를 정말 가진 화면인지: 같은 키로 서명한 요청인지 먼저 확인한다(아직 표에 없으므로 임시 행으로 대조).
    const proof = await checkDevice(request, identity, {
      now, allowPending: true, store: { getDevice: async id => (id === deviceId ? { owner_id: identity.userId, public_key: jwk, status: 'pending' } : null) },
    });
    if (!proof.ok) { log(`승인 요청 거부 사유=${proof.reason}`); return response.status(403).json({ error: proof.error }); }
    try {
      const existing = await store.getDevice(deviceId);
      if (existing) {
        if (existing.owner_id !== identity.userId) { log('승인 요청 거부 사유=DEVICE_ID_IN_USE'); return response.status(409).json({ error: 'DEVICE_ID_IN_USE' }); }
        return response.status(200).json({ deviceId, status: existing.status });
      }
      await store.addDevice({ deviceId, ownerId: identity.userId, publicKey: jwk, label });
      log('승인 요청=pending');
      return response.status(201).json({ deviceId, status: 'pending' });
    } catch (error) {
      log(`처리하지 못했습니다. ${String(error?.message ?? '').slice(0, 40)}`);
      return response.status(503).json({ error: 'DEVICE_STORE_UNAVAILABLE' });
    }
  }

  async function status(request, response) {
    if (!prepare(request, response, 'GET')) return;
    const identity = await login(request, response);
    if (!identity) return;
    const device = await requireDevice(request, response, identity, { store, now, allowPending: true });
    if (!device) return;
    return response.status(200).json({ deviceId: device.deviceId, status: device.status });
  }

  return { requestApproval, status };
}

let defaults;
export function defaultDeviceHandlers() {
  defaults ??= createDeviceHandlers({ verifyAuthorization: defaultVerifyAuthorization, store: createSupabaseStore() });
  return defaults;
}
