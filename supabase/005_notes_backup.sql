-- 10단계 제작 3: 가상 메모의 비공개 사본 표(public.notes_backup)를 만든다.
-- 이 파일은 notes_backup 표 하나만 만든다. notes 표는 아래 마지막 채우기에서 읽기만 하고 바꾸지 않는다.
-- 학생이 내용을 읽어 본 뒤 Supabase SQL Editor에서 직접 실행한다. 이 파일에는 이메일·비밀값이 없다.
--
-- 실행 전에 notes 표의 열 종류를 확인한다(읽기만 한다). id와 owner_id가 uuid여야 아래 문장이 그대로 돈다.
--   select column_name, data_type from information_schema.columns
--   where table_schema = 'public' and table_name = 'notes' order by ordinal_position;

-- 1. 사본 표: 메모를 처음 만들 때 서버가 한 번 저장하는 한 벌. 고치거나 지우지 않는다.
create table if not exists public.notes_backup (
  id uuid primary key,
  owner_id uuid not null,
  title text not null,
  content text not null,
  content_sha256 text not null check (content_sha256 ~ '^[0-9a-f]{64}$'),
  saved_at timestamptz not null default now()
);

-- 2. 비공개: 행 단위 보안을 켜고, 브라우저 역할(anon, authenticated)에는 아무 권한도 주지 않는다.
--    서버 함수(service_role)에는 읽기와 추가만 준다. 수정·삭제 권한이 없으므로 서버 키로도 사본을 바꾸거나 지울 수 없다.
alter table public.notes_backup enable row level security;
revoke all on table public.notes_backup from public, anon, authenticated, service_role;
grant select, insert on table public.notes_backup to service_role;

-- 3. 이미 있는 메모의 사본을 채운다. 이미 사본이 있는 메모는 건너뛴다.
--    내용 해시는 서버(src/note-backup.mjs)와 같은 식이다: sha256(제목 바이트 + 0x00 + 내용 바이트), 소문자 16진수.
insert into public.notes_backup (id, owner_id, title, content, content_sha256)
select n.id, n.owner_id, coalesce(n.title, ''), coalesce(n.content, ''),
       encode(sha256(convert_to(coalesce(n.title, ''), 'UTF8') || '\x00'::bytea || convert_to(coalesce(n.content, ''), 'UTF8')), 'hex')
from public.notes n
where n.owner_id is not null
on conflict (id) do nothing;

-- ===== 실행 후 확인용 조회 (읽기만 한다) =====
-- A. 역할별 권한: anon·authenticated는 모두 false, service_role은 select·insert만 true, update·delete는 false여야 한다.
--    select r.role,
--           has_table_privilege(r.role, 'public.notes_backup', 'select') as can_select,
--           has_table_privilege(r.role, 'public.notes_backup', 'insert') as can_insert,
--           has_table_privilege(r.role, 'public.notes_backup', 'update') as can_update,
--           has_table_privilege(r.role, 'public.notes_backup', 'delete') as can_delete
--    from (values ('anon'), ('authenticated'), ('service_role')) as r(role);
--
-- B. 사본 개수: notes 개수와 같거나 notes에 소유자 없는 행이 있으면 그만큼 적다. 내용은 조회하지 않는다.
--    select (select count(*) from public.notes) as notes_count,
--           (select count(*) from public.notes_backup) as backup_count;
