-- 3단계: 서버 함수(service_role)가 가상 메모를 추가·수정·삭제할 수 있게 합니다.
-- anon, authenticated(브라우저가 쓰는 권한)에는 계속 아무 권한도 주지 않습니다.
grant insert, update, delete on table public.notes to service_role;
