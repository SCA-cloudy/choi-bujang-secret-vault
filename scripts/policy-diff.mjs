import { execFile } from 'node:child_process';
import { mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { promisify } from 'node:util';
import { collectCurrentPolicy, describePlan, diffPolicy, policyDigest, verifySnapshot } from '../src/policy-diff.mjs';
import { fixtureRequests } from './fixture-7.mjs';

// 10단계 제작 1: 안전 정책 사본과 현재 시험 정책의 차이를 "보기만" 합니다. 어떤 파일도 고치지 않습니다.
// 사본이 없거나 검증에 실패하면 차이를 계산하지 않고 중단합니다(종료 코드 1).
export const REPO_ROOT = resolve(fileURLToPath(import.meta.url), '..', '..');
const root = REPO_ROOT;
export const DEFAULT_SNAPSHOT = resolve(root, 'policy', 'safe-policy.json');

const KIND_TEXT = { restore_add: '다시 생김', restore_remove: '없어짐', restore_change: '값이 바뀜' };

const exec = promisify(execFile);
const POLICY_FILES = ['src/decider.mjs', 'src/resources.mjs', 'aleph.config.json'];

// 사본에 적힌 원본 커밋(침해 전, 심판이 통과시킨 저장점)의 정책 파일을 git 기록에서 다시 읽어 정책 지문을 새로 계산합니다.
// 임시 폴더에서만 계산하고 이 저장소의 실제 정책 파일은 건드리지 않습니다. 읽지 못하면 null.
export async function sourcePolicyDigest(commit, { repo = root } = {}) {
  const temp = await mkdtemp(join(tmpdir(), 'policy-source-'));
  try {
    await mkdir(join(temp, 'src'), { recursive: true });
    for (const file of POLICY_FILES) {
      const { stdout } = await exec('git', ['show', `${commit}:${file}`], { cwd: repo, maxBuffer: 5_000_000 });
      await writeFile(join(temp, file), stdout);
    }
    return policyDigest(await currentPolicyOf(temp));
  } catch {
    return null;
  } finally {
    await rm(temp, { recursive: true, force: true });
  }
}

// 사본을 읽고 검증합니다. 실패하면 { ok: false, line }(중단 문장), 통과하면 { ok: true, snapshot }.
// 1) 사본 모양과 사본 안의 지문을 대조하고, 2) 사본에 적힌 원본 커밋을 git 기록에서 다시 읽어 계산한 지문과도 대조합니다.
//    사본의 정책과 지문이 함께 바뀌었으면 2)에서 걸리며, 원본 커밋을 읽지 못해도 검증하지 못한 것으로 보고 멈춥니다.
export async function readVerifiedSnapshot(file = DEFAULT_SNAPSHOT, expectSha256, { readSourceDigest = sourcePolicyDigest } = {}) {
  let text;
  try { text = await readFile(file, 'utf8'); } catch {
    return { ok: false, line: '중단: 안전 정책 사본 파일이 없습니다. 사본이 없으면 복원할 버전을 정할 수 없어 아무것도 하지 않습니다.' };
  }
  let snapshot;
  try { snapshot = JSON.parse(text); } catch {
    return { ok: false, line: '중단: 안전 정책 사본을 JSON으로 읽을 수 없습니다(검증 실패: snapshot_not_json).' };
  }
  const verdict = verifySnapshot(snapshot, { expectedSha256: expectSha256 });
  if (!verdict.ok) return { ok: false, line: `중단: 안전 정책 사본 검증에 실패했습니다(${verdict.reason}). 차이를 계산하지 않았습니다.` };
  const fromSource = await readSourceDigest(snapshot.source.commit);
  if (fromSource === null) {
    return { ok: false, line: `중단: 사본의 원본 커밋(${snapshot.source.commit.slice(0, 7)})을 git 기록에서 다시 읽지 못해 사본을 검증할 수 없습니다(source_unreadable). 차이를 계산하지 않았습니다.` };
  }
  if (fromSource !== snapshot.sha256) {
    return { ok: false, line: `중단: 안전 정책 사본이 원본 커밋(${snapshot.source.commit.slice(0, 7)})의 정책과 다릅니다(source_mismatch). 사본이 바뀌었을 수 있어 차이를 계산하지 않았습니다.` };
  }
  return { ok: true, snapshot };
}

// 지정한 폴더(기본: 이 저장소)의 판정기·설정으로 현재 시험 정책을 모읍니다.
let loadCount = 0;
export async function currentPolicyOf(base = root) {
  const url = `${pathToFileURL(resolve(base, 'src', 'decider.mjs')).href}?load=${++loadCount}`;
  const { RULE_IDS, decide } = await import(url);
  const config = JSON.parse(await readFile(resolve(base, 'aleph.config.json'), 'utf8'));
  const { normal, suspicious } = fixtureRequests();
  return collectCurrentPolicy({ ruleIds: RULE_IDS, allowedRoutes: config.allowedRoutes, decide, baseRequest: normal, anomalyRequest: suspicious });
}

export async function run({ file = DEFAULT_SNAPSHOT, expectSha256, current } = {}) {
  const out = [];
  const loaded = await readVerifiedSnapshot(file, expectSha256);
  if (!loaded.ok) return { code: 1, lines: [loaded.line] };
  const { snapshot } = loaded;

  const now = current ?? await currentPolicyOf();
  const diff = diffPolicy(snapshot.policy, now);
  const plan = describePlan(snapshot, diff);
  out.push(`복원할 정책 버전: ${plan.version} (커밋 ${plan.commit.slice(0, 7)}, 사본 지문 ${plan.sha256.slice(0, 12)})`);
  out.push('사본 검증: 통과 (모양·지문 일치, 원본 커밋을 다시 읽어 계산한 지문과 일치)');
  out.push(diff.same ? '변경 범위: 없음 (현재 시험 정책이 사본과 같습니다)' : `변경 범위: ${plan.changeCount}건 (${plan.areas.join(', ')})`);
  for (const change of diff.changes) {
    out.push(`  - [${change.area}] ${change.item}: ${KIND_TEXT[change.kind]} (사본 ${change.safe ?? '없음'} / 현재 ${change.current ?? '없음'})`);
  }
  out.push('이 명령은 보기만 했고 어떤 파일·정책도 고치지 않았습니다.');
  return { code: 0, lines: out };
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const args = process.argv.slice(2);
  const pick = name => { const at = args.indexOf(name); return at >= 0 ? args[at + 1] : undefined; };
  try {
    const result = await run({ file: pick('--file') ? resolve(pick('--file')) : DEFAULT_SNAPSHOT, expectSha256: pick('--expect-sha256') });
    process.stdout.write(`${result.lines.join('\n')}\n`);
    process.exitCode = result.code;
  } catch (error) {
    process.stderr.write(`정책 차이 첫 오류: ${error.message}\n`);
    process.exitCode = 1;
  }
}
