-- 10단계: 사전 백업(notes_backup)을 다시 읽어 검증합니다. 읽기만 합니다(select 하나, 아무것도 바꾸지 않음).
-- 학생이 Supabase SQL Editor에서 실행하고, 결과 한 줄을 README의 「사전 백업 다시 읽어 검증」에 적습니다.
-- 해시 계산식은 서버(src/note-backup.mjs)와 같습니다: sha256( UTF-8(제목) || 0x00 || UTF-8(내용) ), 소문자 16진수.
-- 이 파일에는 키, 메모 문장, 이메일, 사용자 ID가 없습니다. 결과에도 개수만 나옵니다.

select
  (select count(*) from public.notes)                                   as 메모_건수,
  (select count(*) from public.notes_backup)                            as 사본_건수,
  (select count(*) from public.notes n
     where not exists (select 1 from public.notes_backup b where b.id = n.id)) as 사본_없는_메모,
  (select count(*) from public.notes_backup b
     where b.content_sha256 is null
        or b.content_sha256 !~ '^[0-9a-f]{64}$'
        or b.content_sha256 <> encode(
             sha256(convert_to(b.title, 'UTF8') || '\x00'::bytea || convert_to(b.content, 'UTF8')),
             'hex'))                                                    as 해시가_틀린_사본,
  (select count(*) from public.notes_backup b
     join public.notes n on n.id = b.id
     where n.owner_id is distinct from b.owner_id)                      as 소유자가_다른_사본,
  (select count(*) from public.notes_backup where owner_id is null)     as 소유자_없는_사본;

-- 정상 결과: 해시가_틀린_사본 = 0, 소유자가_다른_사본 = 0, 소유자_없는_사본 = 0.
-- 사본_없는_메모가 0보다 크면 그 메모는 복구할 수 없습니다(사본 저장 실패, 또는 005가 건너뛴 소유자 없는 옛 메모). 숫자 그대로 기록합니다.
-- 사본_건수가 메모_건수보다 큰 것은 정상일 수 있습니다(지운 메모의 사본은 남겨 둡니다).
