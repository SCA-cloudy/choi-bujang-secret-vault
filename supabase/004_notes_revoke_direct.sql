-- 5단계: 메모 표(public.notes)를 데이터베이스 주소로 바로 읽고 쓰는 길을 모두 닫는다.
-- 이 파일은 public.notes 한 표만 다룬다. 다른 표는 건드리지 않는다.
-- 서버 함수는 서버 전용 키(service_role)로 접근하므로 service_role 권한은 그대로 둔다.
-- 학생이 내용을 읽어 본 뒤 Supabase SQL Editor에서 직접 실행한다.

-- 1) 로그인한 사람(authenticated), 로그인 안 한 사람(anon), 전체(PUBLIC)의 직접 권한을 모두 회수한다.
revoke all on table public.notes from public, anon, authenticated;

-- 2) 3단계에서 만든 행 보안(RLS)과 정책은 그대로 둔다. 권한이 막혀도 두 번째 안전장치로 남는다.
--    (여기서는 아무것도 바꾸지 않는다.)

-- ===== 실행 전·후 확인용 조회 (읽기만 한다) =====
-- A. 어느 역할이 어떤 권한을 갖는지 목록으로 보기
--    select grantee, privilege_type
--    from information_schema.role_table_grants
--    where table_schema = 'public' and table_name = 'notes'
--      and grantee in ('PUBLIC', 'anon', 'authenticated', 'service_role')
--    order by grantee, privilege_type;
--    전: authenticated 4줄(DELETE/INSERT/SELECT/UPDATE) + service_role 7줄
--    후: authenticated 줄이 없어지고 service_role 7줄만 남아야 한다.
--
-- B. 역할별로 "할 수 있다/없다"로 보기
--    select r.role,
--           has_table_privilege(r.role, 'public.notes', 'select') as can_select,
--           has_table_privilege(r.role, 'public.notes', 'insert') as can_insert,
--           has_table_privilege(r.role, 'public.notes', 'update') as can_update,
--           has_table_privilege(r.role, 'public.notes', 'delete') as can_delete
--    from (values ('anon'), ('authenticated'), ('service_role')) as r(role);
--    후: anon과 authenticated는 모두 false, service_role은 모두 true여야 한다.
