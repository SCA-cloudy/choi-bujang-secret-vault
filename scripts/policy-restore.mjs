import { execFile } from 'node:child_process';
import { appendFile, mkdir, readFile, writeFile } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';
import { diffPolicy } from '../src/policy-diff.mjs';
import { matchEol, planRestore, setAllowedRoutes } from '../src/policy-restore.mjs';
import { DEFAULT_SNAPSHOT, REPO_ROOT, currentPolicyOf, readVerifiedSnapshot } from './policy-diff.mjs';

// 10단계 제작 2: 검증한 안전 정책 버전으로 시험 정책을 되돌립니다.
// - 기본은 미리보기입니다. 바뀔 파일·항목을 먼저 보여 주고 아무것도 고치지 않습니다.
// - 실제로 되돌리려면 --apply 와 --confirm <사본 지문 앞 12자리>를 함께 줘야 합니다(미리보기에 지문이 보입니다).
// - 되돌리는 곳은 정책 파일뿐입니다. 다른 서비스 규칙, 감사 기록, 자료·DB, git 기록은 건드리지 않습니다.
// - 되돌린 뒤 정책 지문이 사본과 같지 않으면 모든 파일을 원래대로 돌려놓고 중단합니다.
// - 되돌린 일은 policy/restore-audit.log 에 한 줄씩 덧붙입니다(시각·버전·파일 이름만, 내용은 담지 않습니다).
const exec = promisify(execFile);

// 사본에 적힌 커밋 시점의 파일 내용을 git 에서 읽습니다(셸 없이, 읽기만 합니다).
export async function gitSource(base, commit, file) {
  const { stdout } = await exec('git', ['show', `${commit}:${file}`], { cwd: base, maxBuffer: 5_000_000 });
  return stdout;
}

const KIND_TEXT = { restore_add: '다시 생김', restore_remove: '없어짐', restore_change: '값이 바뀜' };
const KEPT = '그대로 두는 것: 다른 서비스 규칙(XDR 등), 기존 감사 기록, README, 자료와 DB, git 기록';

export async function run({ base = REPO_ROOT, file = DEFAULT_SNAPSHOT, expectSha256, apply = false, confirm, readSource, now = () => new Date() } = {}) {
  const loaded = await readVerifiedSnapshot(file, expectSha256);
  if (!loaded.ok) return { code: 1, lines: [loaded.line] };
  const { snapshot } = loaded;
  const source = readSource ?? ((commit, path) => gitSource(base, commit, path));
  const pin = snapshot.sha256.slice(0, 12);

  const diff = diffPolicy(snapshot.policy, await currentPolicyOf(base));
  const targets = planRestore(diff);
  const lines = [
    `복원할 정책 버전: ${snapshot.version} (커밋 ${snapshot.source.commit.slice(0, 7)}, 사본 지문 ${pin})`,
    '사본 검증: 통과 (모양·지문 일치, 원본 커밋을 다시 읽어 계산한 지문과 일치)',
    diff.same ? '변경 범위: 없음 (현재 시험 정책이 사본과 같습니다)' : `변경 범위: ${diff.changes.length}건`,
    ...diff.changes.map(change => `  - [${change.area}] ${change.item}: ${KIND_TEXT[change.kind]} (사본 ${change.safe ?? '없음'} / 현재 ${change.current ?? '없음'})`),
  ];
  if (diff.same) return { code: 0, lines: [...lines, '복원할 것이 없습니다. 아무것도 고치지 않았습니다.'] };

  lines.push('바뀔 파일·항목:');
  for (const target of targets) {
    lines.push(target.kind === 'file'
      ? `  - ${target.file} 전체를 ${snapshot.source.commit.slice(0, 7)} 시점 내용으로`
      : `  - ${target.file} 의 ${target.field} 항목 하나만 (step, judgeIssuer, restoreRoute 등 다른 값은 그대로)`);
  }
  lines.push(KEPT);

  if (!apply) {
    return { code: 0, lines: [...lines, '미리보기입니다. 아무것도 고치지 않았습니다.',
      `위 내용을 확인했다면 실행: npm run policy:restore -- --apply --confirm ${pin}`] };
  }
  if (confirm !== pin) {
    return { code: 1, lines: [...lines, `중단: --confirm 값이 사본 지문 앞 12자리(${pin})와 다릅니다. 아무것도 고치지 않았습니다.`] };
  }

  // 실행: 원래 내용을 기억해 두고 쓴 뒤, 검증에 실패하면 모두 되돌립니다.
  const before = new Map();
  const abs = path => resolve(base, path);
  try {
    for (const target of targets) {
      const current = await readFile(abs(target.file), 'utf8');
      before.set(target.file, current);
      const next = target.kind === 'file'
        ? matchEol(await source(snapshot.source.commit, target.file), current)
        : setAllowedRoutes(current, snapshot.policy.allowedRoutes);
      await writeFile(abs(target.file), next);
    }
    const after = diffPolicy(snapshot.policy, await currentPolicyOf(base));
    if (!after.same) throw new Error('복원 뒤 정책이 사본과 같지 않습니다');
  } catch (error) {
    for (const [path, text] of before) await writeFile(abs(path), text);
    return { code: 1, lines: [...lines, `중단: ${error.message}. 바꾼 파일을 모두 원래대로 돌려놓았습니다.`] };
  }

  const entry = { at: now().toISOString(), event: 'policy_restore', version: snapshot.version, sha256: snapshot.sha256,
    files: targets.map(target => (target.field ? `${target.file}#${target.field}` : target.file)), changes: diff.changes.length };
  try {
    await mkdir(dirname(abs('policy/restore-audit.log')), { recursive: true });
    await appendFile(abs('policy/restore-audit.log'), `${JSON.stringify(entry)}\n`);
  } catch {
    return { code: 1, lines: [...lines, '복원은 끝났고 검증도 통과했지만 감사 기록(policy/restore-audit.log)에 쓰지 못했습니다. 기록을 직접 확인하세요.'] };
  }
  return { code: 0, lines: [...lines, '복원 완료: 복원 뒤 정책 지문이 사본과 같습니다(검증 통과).',
    '감사 기록 한 줄을 policy/restore-audit.log 에 덧붙였습니다(기존 기록은 지우지 않습니다).',
    '다음: npm run policy:diff 로 "변경 범위: 없음"을 확인하세요.'] };
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const args = process.argv.slice(2);
  const pick = name => { const at = args.indexOf(name); return at >= 0 ? args[at + 1] : undefined; };
  try {
    const result = await run({
      file: pick('--file') ? resolve(pick('--file')) : DEFAULT_SNAPSHOT,
      expectSha256: pick('--expect-sha256'), apply: args.includes('--apply'), confirm: pick('--confirm'),
    });
    process.stdout.write(`${result.lines.join('\n')}\n`);
    process.exitCode = result.code;
  } catch (error) {
    process.stderr.write(`정책 복원 첫 오류: ${error.message}\n`);
    process.exitCode = 1;
  }
}
