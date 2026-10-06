-- 4단계 제작 3: notes 테이블에만 RLS(행 단위 보안)와 최소 권한을 건다. 다른 테이블은 건드리지 않는다.
-- Supabase SQL Editor에서 검토한 뒤 직접 실행한다. 이 파일에는 이메일·비밀값이 없다.
-- 서버 API가 쓰는 service_role의 권한(002_notes_write_grants.sql)은 바꾸지 않는다.

-- 1. 행 단위 보안을 켠다.
alter table public.notes enable row level security;

-- 2. 기존 권한을 모두 회수한 뒤, 로그인한 사용자(authenticated)에게 필요한 네 가지만 준다.
revoke all on table public.notes from public, anon, authenticated;
grant select, insert, update, delete on table public.notes to authenticated;

-- 3. 정책: 로그인한 사용자 본인의 행(auth.uid() = owner_id)일 때만 허용한다.
drop policy if exists notes_select_own on public.notes;
drop policy if exists notes_insert_own on public.notes;
drop policy if exists notes_update_own on public.notes;
drop policy if exists notes_delete_own on public.notes;

-- 읽기·삭제: 기존 행이 본인 것일 때만
create policy notes_select_own on public.notes
  for select to authenticated
  using (auth.uid() = owner_id);

create policy notes_delete_own on public.notes
  for delete to authenticated
  using (auth.uid() = owner_id);

-- 추가: 새 행의 owner_id가 본인일 때만
create policy notes_insert_own on public.notes
  for insert to authenticated
  with check (auth.uid() = owner_id);

-- 수정: 기존 행도, 고친 뒤의 새 행도 본인 것일 때만 (남에게 넘기는 수정 불가)
create policy notes_update_own on public.notes
  for update to authenticated
  using (auth.uid() = owner_id)
  with check (auth.uid() = owner_id);
