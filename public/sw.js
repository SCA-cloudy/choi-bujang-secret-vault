// 11단계 제작 1: 오프라인 안내만 하는 서비스 워커입니다.
// - 페이지 이동(navigate) 요청은 항상 네트워크로 보내고, 네트워크가 끊겼을 때만 아래 오프라인 안내 화면을 돌려줍니다.
// - 자료(/api/*), 로그인 출입증, 기기 정보는 가로채지도 저장하지도 않습니다. Cache Storage를 쓰지 않습니다.
// - 이 파일이 설치되었다고 해서 기기가 승인된 것은 아닙니다. 승인 여부는 서버와 판정기가 정합니다.
const OFFLINE_PAGE = `<!doctype html><html lang="ko"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1"><title>오프라인 | 내 자료실</title>
<style>body{margin:0;min-height:100vh;display:grid;place-items:center;background:#101a28;color:#ecf4ff;font-family:system-ui,sans-serif}
main{max-width:520px;padding:24px;line-height:1.7}h1{font-size:24px}p{color:#bfd0e5}</style></head>
<body><main><h1>오프라인입니다</h1>
<p>인터넷에 연결되지 않아 자료실을 열 수 없습니다. 자료는 서버에서만 보여 주며 이 기기에 저장해 두지 않습니다.</p>
<p>연결된 뒤 다시 열어 주세요. 앱을 설치했다고 해서 기기 승인이 끝난 것은 아닙니다.</p></main></body></html>`;

self.addEventListener('install', event => { event.waitUntil(self.skipWaiting()); });
self.addEventListener('activate', event => { event.waitUntil(self.clients.claim()); });

self.addEventListener('fetch', event => {
  const request = event.request;
  if (request.mode !== 'navigate') return; // 자료·API·그 밖의 요청은 손대지 않는다
  event.respondWith(fetch(request).catch(() => new Response(OFFLINE_PAGE, {
    status: 503, headers: { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store' },
  })));
});
