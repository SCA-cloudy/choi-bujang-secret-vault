// 10단계: 복원 전 사본 검증 절차 (npm run backup:verify).
// 복원을 실행하기 전에 반드시 먼저 따로 거치는 단계입니다. policy:restore 는 이 절차를 통과해야만 다음으로 갑니다.
//   1) 사본 읽기: policy/safe-policy.json 이 있는지 확인합니다. 없으면 멈춥니다.
//   2) 사본 검증: 모양, 사본 안의 지문, 사본에 적힌 원본 커밋(침해 전 저장점)을 git 기록에서 다시 읽어 계산한 지문을 대조합니다.
//   3) 사본 다시 읽기: 사본을 한 번 더 읽어 같은 방법으로 검증하고, 지문이 처음과 같은지 확인합니다.
//   4) 실행 전에 보여 주기: 복원할 버전과 바뀔 항목(현재 시험 정책과의 차이)을 보여 줍니다.
// 하나라도 실패하면 "중단:"으로 시작하는 한 줄만 돌려주고, 복원으로 넘어가지 않습니다.
// 이 절차는 파일·정책·DB를 하나도 바꾸지 않습니다. 실제 운영 정책은 건드리지 않습니다.
import { access } from 'node:fs/promises';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { diffPolicy } from '../src/policy-diff.mjs';
import { DEFAULT_SNAPSHOT, REPO_ROOT, currentPolicyOf, readVerifiedSnapshot } from './policy-diff.mjs';

const KIND_TEXT = { restore_add: '다시 생김', restore_remove: '없어짐', restore_change: '값이 바뀜' };

export async function verifyBeforeRestore({ base = REPO_ROOT, file = DEFAULT_SNAPSHOT, expectSha256, readSnapshot = readVerifiedSnapshot } = {}) {
  try { await access(file); } catch {
    return { ok: false, lines: ['중단: 복원 전 사본 검증 1/4 — 안전 정책 사본 파일이 없습니다. 사본이 없으면 복원하지 않습니다.'] };
  }
  const first = await readSnapshot(file, expectSha256);
  if (!first.ok) return { ok: false, lines: [first.line] };
  const again = await readSnapshot(file, expectSha256);
  if (!again.ok) return { ok: false, lines: [again.line] };
  if (again.snapshot.sha256 !== first.snapshot.sha256) {
    return { ok: false, lines: ['중단: 복원 전 사본 검증 3/4 — 사본을 다시 읽었더니 처음 검증한 사본과 지문이 다릅니다(reread_mismatch). 복원하지 않습니다.'] };
  }
  const { snapshot } = first;
  const diff = diffPolicy(snapshot.policy, await currentPolicyOf(base));
  const pin = snapshot.sha256.slice(0, 12);
  const lines = [
    '복원 전 사본 검증 절차:',
    `  1/4 사본 읽기: 통과 (policy/safe-policy.json, 버전 ${snapshot.version})`,
    `  2/4 사본 검증: 통과 (모양·지문 일치, 원본 커밋 ${snapshot.source.commit.slice(0, 7)}을 다시 읽어 계산한 지문과 일치)`,
    `  3/4 사본 다시 읽기: 통과 (두 번째로 읽어 검증한 사본의 지문 ${pin}이 처음과 같음)`,
    `  4/4 실행 전에 보여 주기: 아래 버전과 바뀔 항목`,
    `복원할 정책 버전: ${snapshot.version} (커밋 ${snapshot.source.commit.slice(0, 7)}, 사본 지문 ${pin})`,
    '사본 검증: 통과 (모양·지문 일치, 원본 커밋을 다시 읽어 계산한 지문과 일치)',
    diff.same ? '변경 범위: 없음 (현재 시험 정책이 사본과 같습니다)' : `변경 범위: ${diff.changes.length}건`,
    ...diff.changes.map(change => `  - [${change.area}] ${change.item}: ${KIND_TEXT[change.kind]} (사본 ${change.safe ?? '없음'} / 현재 ${change.current ?? '없음'})`),
  ];
  return { ok: true, lines, snapshot, diff };
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const args = process.argv.slice(2);
  const pick = name => { const at = args.indexOf(name); return at >= 0 ? args[at + 1] : undefined; };
  try {
    const result = await verifyBeforeRestore({
      file: pick('--file') ? resolve(pick('--file')) : DEFAULT_SNAPSHOT, expectSha256: pick('--expect-sha256'),
    });
    const tail = result.ok ? ['복원 전 사본 검증: 통과. 이 명령은 검증만 했고 어떤 파일·정책도 고치지 않았습니다.']
      : ['복원 전 사본 검증: 실패. 복원하지 마세요. 이 명령은 어떤 파일·정책도 고치지 않았습니다.'];
    process.stdout.write(`${[...result.lines, ...tail].join('\n')}\n`);
    process.exitCode = result.ok ? 0 : 1;
  } catch (error) {
    process.stderr.write(`복원 전 사본 검증 첫 오류: ${error.message}\n`);
    process.exitCode = 1;
  }
}
