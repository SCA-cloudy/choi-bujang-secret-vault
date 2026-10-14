-- 11단계 제작 2: 기기 승인 표(public.devices)를 만든다.
-- 이 파일은 devices 표 하나만 만든다. 다른 표(notes, notes_backup)는 읽지도 바꾸지도 않는다.
-- 학생이 내용을 읽어 본 뒤 Supabase SQL Editor에서 직접 실행한다. 이 파일에는 이메일·비밀값·기기 개인키가 없다.
--
-- 흐름: 로그인한 화면이 기기 키(밖으로 꺼낼 수 없는 키, 화면 메모리에만 있음)를 만들고 "공개 키"만 서버로 보낸다.
--       서버는 이 표에 "승인 대기(pending)"로만 적는다. 승인은 화면의 버튼이 아니라 학생이 SQL Editor에서 직접 한다.
--       서버는 승인된(approved) 기기의 공개 키로 요청 서명을 확인한 뒤에만 자료를 준다.

-- 1. 기기 표: 기기 번호(공개 키에서 만든 16자리 16진수), 주인, 공개 키, 승인 상태.
create table if not exists public.devices (
  device_id text primary key check (device_id ~ '^[0-9a-f]{16}$'),
  owner_id uuid not null,
  public_key jsonb not null,
  label text not null default '' check (char_length(label) <= 60),
  status text not null default 'pending' check (status in ('pending', 'approved', 'revoked')),
  requested_at timestamptz not null default now(),
  approved_at timestamptz
);

-- 2. 비공개: 행 단위 보안을 켜고, 브라우저 역할(anon, authenticated)에는 아무 권한도 주지 않는다.
--    서버 함수(service_role)에는 읽기와 추가(승인 대기 등록)만 준다. 수정 권한이 없으므로 서버 키로도 기기를 승인할 수 없다.
alter table public.devices enable row level security;
revoke all on table public.devices from public, anon, authenticated, service_role;
grant select, insert on table public.devices to service_role;

-- ===== 실행 후 확인용 조회 (읽기만 한다) =====
-- A. 역할별 권한: anon·authenticated는 없음, service_role은 INSERT, SELECT만 있어야 한다.
--    select r.role,
--           coalesce(string_agg(p.priv, ', ' order by p.priv)
--             filter (where has_table_privilege(r.role, 'public.devices', p.priv)), '(없음)') as 허용된_권한
--    from (values ('anon'), ('authenticated'), ('service_role')) r(role)
--    cross join (values ('SELECT'), ('INSERT'), ('UPDATE'), ('DELETE')) p(priv)
--    group by r.role order by r.role;
--
-- ===== 기기 승인 (학생이 SQL Editor에서 직접, 화면에 나온 기기 번호로) =====
--    update public.devices set status = 'approved', approved_at = now()
--    where device_id = '<화면에 나온 16자리 기기 번호>' and status = 'pending';
-- 승인 취소: update public.devices set status = 'revoked' where device_id = '<기기 번호>';
