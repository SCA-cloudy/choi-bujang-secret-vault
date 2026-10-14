# 12단계 실측 요청 표 (배포 사이트에서 실제로 보낸 요청의 결과)

- 만든 곳: 배포 사이트의 「탈환 작전실」 → 「실측 요청 표 만들기」 → 「표 복사」. 아래 표는 화면이 만든 글을 **그대로** 붙인 것이며 옮겨 적지 않았습니다.
- 실행: 2026-10-14 15:44~15:45 KST(표의 시각은 GMT), 시험 계정 B, 배포 커밋 `45984c4`(표 첫 줄의 `/aleph.json`이 보여 줌).
- 다른 계정(A)의 메모 번호를 넣고 실행했습니다(번호는 이 파일에 적지 않음). 번호를 비우면 4단계의 「<A의 메모>」 3줄이 미실행이 됩니다. 같은 날 번호를 비운 첫 실행은 `36줄 · 일치 29 · 불일치 0 · 미실행 7`이었고, 이 표는 번호를 넣은 두 번째 실행입니다.
- 「요청 ID」는 Vercel이 응답에 붙인 `x-vercel-id`, 「확인 시각」은 응답의 `Date`(서버 가상 요청 줄은 `/api/ops`가 기록한 ISO 시각)입니다. 메모 제목·본문, 출입증, 전체 번호는 표에 없습니다.
- **「일치」는 기대와 실제 글자가 같다는 뜻**이며, 운영 41종 공격 시험의 통과를 뜻하지 않습니다. 41종은 심판이 실행하므로 이 문서에서는 미실행입니다.

## 실행 결과 표

| 단계 | 구분 | 요청 | 기대 | 실제 | 결과 | 요청 ID | 확인 시각 |
|---|---|---|---|---|---|---|---|
| 1 | 정상 | GET /aleph.json | 200 | 200 (commit 45984c4) | 일치 | icn1::lrh86-1791960278008-91866cd2a7dc | Wed, 14 Oct 2026 06:44:38 GMT |
| 2 | 금지 | 공개 흔적 확인(git log -S) | — | 미실행: Git 기록 검사라서 내 PC 명령으로 실행 | 미실행 | — | — |
| 3 | 금지 | GET /api/notes (로그인 없음) | 401 LOGIN_REQUIRED | 401 LOGIN_REQUIRED | 일치 | icn1::iad1::7w2q2-1791960278034-9830f1de4475 | Wed, 14 Oct 2026 06:44:38 GMT |
| 3 | 금지 | GET /data.json (로그인 없음) | 404 | 404 | 일치 | icn1::7w2q2-1791960278823-5fd236aa9dcb | Wed, 14 Oct 2026 06:44:38 GMT |
| 3 | 금지 | DELETE /api/notes/<없는 번호> (로그인 없음) | 401 LOGIN_REQUIRED | 401 LOGIN_REQUIRED | 일치 | icn1::iad1::7w2q2-1791960278838-e7c2397f5f30 | Wed, 14 Oct 2026 06:44:39 GMT |
| 3 | 정상 | GET /api/notes (로그인+서명) | 200 | 200 (내 메모 1건) | 일치 | icn1::iad1::7w2q2-1791960279743-95196b5d52ff | Wed, 14 Oct 2026 06:44:41 GMT |
| 4 | 정상 | POST /api/notes (임시 메모 추가) | 201 | 201 | 일치 | icn1::iad1::rh945-1791960281674-f86698b1e7d2 | Wed, 14 Oct 2026 06:44:43 GMT |
| 4 | 정상 | GET /api/notes/<임시 메모> | 200 | 200 | 일치 | icn1::iad1::rh945-1791960283882-682b11f0f37e | Wed, 14 Oct 2026 06:44:45 GMT |
| 4 | 정상 | PUT /api/notes/<임시 메모> | 200 | 200 | 일치 | icn1::iad1::rh945-1791960285703-a021df90bdb3 | Wed, 14 Oct 2026 06:44:46 GMT |
| 4 | 금지 | PUT /api/notes/<임시 메모> + 주인 바꾸기 값 | 403 OWNER_CHANGE_FORBIDDEN | 403 OWNER_CHANGE_FORBIDDEN | 일치 | icn1::iad1::rh945-1791960287001-fa9a2c506ccb | Wed, 14 Oct 2026 06:44:47 GMT |
| 4 | 금지 | GET /api/notes/<없는 번호> | 404 NOT_FOUND | 404 NOT_FOUND | 일치 | icn1::iad1::fh5rn-1791960287819-51a6d57a0e32 | Wed, 14 Oct 2026 06:44:49 GMT |
| 4 | 금지 | GET /api/notes/<A의 메모> | 404 NOT_FOUND | 404 NOT_FOUND | 일치 | icn1::iad1::fh5rn-1791960289320-7ed241f03ee8 | Wed, 14 Oct 2026 06:44:50 GMT |
| 4 | 금지 | PUT /api/notes/<A의 메모> | 404 NOT_FOUND | 404 NOT_FOUND | 일치 | icn1::iad1::kzw74-1791960290447-13c1999956fa | Wed, 14 Oct 2026 06:44:50 GMT |
| 4 | 금지 | DELETE /api/notes/<A의 메모> | 404 NOT_FOUND | 404 NOT_FOUND | 일치 | icn1::iad1::kzw74-1791960291106-8fb23a28d923 | Wed, 14 Oct 2026 06:44:52 GMT |
| 4 | 정상 | DELETE /api/notes/<임시 메모> | 200 | 200 | 일치 | icn1::iad1::d2cg8-1791960301494-f5b9e38f81c7 | Wed, 14 Oct 2026 06:45:03 GMT |
| 4 | 정상 | GET /api/notes/<지운 임시 메모> | 404 NOT_FOUND | 404 NOT_FOUND | 일치 | icn1::iad1::mvv4j-1791960303211-703b93eb4359 | Wed, 14 Oct 2026 06:45:03 GMT |
| 5 | 금지 | 원본 주소 /rest/v1/notes 직접 조회 | — | 미실행: 공개 키가 필요해 화면에 넣지 않음. 콘솔과 npm run bundle 자기 점검에서 실행 | 미실행 | — | — |
| 6 | 금지 | GET /api/notes (등록 안 된 기기 키 서명) | 403 DEVICE_NOT_REGISTERED | 403 DEVICE_NOT_REGISTERED | 일치 | icn1::iad1::kzw74-1791960292168-9c82c98b49ee | Wed, 14 Oct 2026 06:44:52 GMT |
| 6 | 정상 | 서버 가상 요청(/api/ops 05681237): 등록 기기의 평소 읽기 | allow | allow (approved) | 일치 | icn1::iad1::wj8s8-1791960299549-4bfcba3368ed | 2026-10-14T06:45:00.412Z |
| 6 | 금지 | 서버 가상 요청(/api/ops 05681237): 미등록 기기의 읽기 | deny | deny (device_not_registered) | 일치 | icn1::iad1::wj8s8-1791960299549-4bfcba3368ed | 2026-10-14T06:45:00.412Z |
| 7 | 금지 | 서버 가상 요청(/api/ops 05681237): 복합 이상 접속(재확인 전) | step_up | step_up (step_up_required) | 일치 | icn1::iad1::wj8s8-1791960299549-4bfcba3368ed | 2026-10-14T06:45:00.412Z |
| 8 | 금지 | 서버 가상 요청(/api/ops 05681237): 구역 밖 동작: 메모 삭제 | deny | deny (starter_not_ready) | 일치 | icn1::iad1::wj8s8-1791960299549-4bfcba3368ed | 2026-10-14T06:45:00.412Z |
| 9 | 정상 | 서버 가상 요청(/api/ops 05681237): 같은 사용자의 가상 조회 30건 | observe | observe | 일치 | icn1::iad1::wj8s8-1791960299549-4bfcba3368ed | 2026-10-14T06:45:00.412Z |
| 9 | 금지 | 서버 가상 요청(/api/ops 05681237): 같은 사용자의 가상 조회 121건 | propose_revocation | propose_revocation | 일치 | icn1::iad1::wj8s8-1791960299549-4bfcba3368ed | 2026-10-14T06:45:00.412Z |
| 9 | 금지 | 반 엔진의 실제 접속 사건 전달·회수 | — | 미실행: 반 엔진의 실제 접속 사건 전달과 회수는 이 저장소에 연결되어 있지 않아 실행하지 않음 | 미실행 | — | — |
| 10 | 금지 | POST /api/restore (로그인 없음) | 401 LOGIN_REQUIRED | 401 LOGIN_REQUIRED | 일치 | icn1::iad1::hrr6k-1791960292630-17bd6b44efb2 | Wed, 14 Oct 2026 06:44:53 GMT |
| 10 | 금지 | POST /api/restore <사본 없는 번호> | 404 NOT_FOUND | 404 NOT_FOUND | 일치 | icn1::iad1::4jl28-1791960293491-5d46c34913b9 | Wed, 14 Oct 2026 06:44:54 GMT |
| 10 | 정상 | POST /api/restore <임시 메모> 미리 보기 | 200 | 200 (action update) | 일치 | icn1::iad1::s7wz5-1791960294902-7cbfb9a935da | Wed, 14 Oct 2026 06:44:56 GMT |
| 11 | 금지 | GET /api/notes (서명 없음) | 403 DEVICE_SIGNATURE_REQUIRED | 403 DEVICE_SIGNATURE_REQUIRED | 일치 | icn1::iad1::s7wz5-1791960296854-07b7f500a422 | Wed, 14 Oct 2026 06:44:56 GMT |
| 11 | 금지 | GET /api/notes/<없는 번호> (다른 경로용 서명) | 403 DEVICE_SIGNATURE_INVALID | 403 DEVICE_SIGNATURE_INVALID | 일치 | icn1::iad1::bt79d-1791960297078-8c53452198e7 | Wed, 14 Oct 2026 06:44:57 GMT |
| 11 | 금지 | GET /api/notes (5분 전 시각의 서명) | 403 DEVICE_SIGNATURE_INVALID | 403 DEVICE_SIGNATURE_INVALID | 일치 | icn1::iad1::bt79d-1791960297540-cfc5e74677c9 | Wed, 14 Oct 2026 06:44:57 GMT |
| 11 | 금지 | PUT /api/notes/<임시 메모> (서명 뒤 본문 바꿈) | 403 DEVICE_SIGNATURE_INVALID | 403 DEVICE_SIGNATURE_INVALID | 일치 | icn1::iad1::bt79d-1791960297752-65678a4387eb | Wed, 14 Oct 2026 06:44:58 GMT |
| 12 | 금지 | GET /api/ops (서명 없음) | 403 DEVICE_SIGNATURE_REQUIRED | 403 DEVICE_SIGNATURE_REQUIRED | 일치 | icn1::iad1::bt79d-1791960298205-ef7ba0df4ebd | Wed, 14 Oct 2026 06:44:59 GMT |
| 12 | 금지 | GET /api/ops (로그인 없음) | 401 LOGIN_REQUIRED | 401 LOGIN_REQUIRED | 일치 | icn1::iad1::wj8s8-1791960299326-89584d2ff3b0 | Wed, 14 Oct 2026 06:44:59 GMT |
| 12 | 정상 | GET /api/ops (로그인+서명) | 200 | 200 | 일치 | icn1::iad1::wj8s8-1791960299549-4bfcba3368ed | Wed, 14 Oct 2026 06:45:01 GMT |
| 운영 | 금지 | 운영 41종 공격 시험 | — | 미실행: 심판이 실행합니다. 이 화면의 표는 41종의 통과 근거가 아닙니다 | 미실행 | — | — |

36줄 · 일치 32 · 불일치 0 · 미실행 4
이 표는 이 화면이 방금 배포 사이트에 보낸 요청의 결과입니다. 「일치」는 기대와 실제 글자가 같다는 뜻이며 운영 41종 공격 시험의 통과가 아닙니다.
## 이 표만으로는 알 수 없는 것을 DB에서 따로 확인한 결과

- 「<A의 메모>」 읽기·수정·삭제가 404로 막힌 것만으로는 내용이 안 바뀌었는지 알 수 없어서, 실행 전후로 같은 SQL(읽기만 함: A의 그 메모 한 건의 `md5(title || '|' || content)`)을 SQL Editor에서 돌려 비교했습니다. **전후 지문이 같고 한 줄이 그대로 남아 있었습니다**(2026-10-14 15:43 → 15:47 KST). 지문 값과 메모 번호는 이 파일에 적지 않았습니다.
- 임시 메모는 표의 `DELETE 200` → `GET 404`로 지워진 것을 확인했습니다. 비공개 사본(`notes_backup`)은 추가만 되는 표라서 코드상 실행할 때마다 사본 1줄이 남습니다(이날 2번 실행했으므로 작전실의 「내 메모 사본」 개수가 8개에서 늘어나는지로 확인할 수 있고, 이 문서를 쓸 때는 아직 세어 보지 않았습니다).

## 미실행으로 남긴 것

| 항목 | 이유와 실행 위치 |
|---|---|
| 2단계 공개 흔적 | Git 기록 검사(`git log -S`)라서 내 PC에서 실행. 결과는 README 2단계·「복구 뒤 재실행」 표에 있음 |
| 5단계 원본 주소 직접 조회 | 공개 키가 필요해 화면에 넣지 않음. 콘솔 확인과 `npm run bundle` 자기 점검에서 실행 |
| 반 엔진의 실제 접속 사건 전달·회수 | 이 저장소에 연결되어 있지 않음 |
| 운영 41종 공격 시험 | 심판이 실행. 이 표는 통과 근거가 아님 |
