// GET /api/device/status: 서명한 요청으로 이 기기의 승인 상태만 알려 줍니다. 처리는 src/device-api.mjs.
import { defaultDeviceHandlers } from '../../src/device-api.mjs';

export default function handler(request, response) {
  return defaultDeviceHandlers().status(request, response);
}
