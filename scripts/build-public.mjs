import { copyFile, mkdir, readFile, rm, writeFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { deploymentIdentity } from './deployment-identity.mjs';

const root = resolve(import.meta.dirname, '..');
const output = resolve(root, 'public', 'data.json');
const config = JSON.parse(await readFile(resolve(root, 'aleph.config.json'), 'utf8'));
await mkdir(resolve(root, 'public'), { recursive: true });

if (config.step === 1) {
  // 1단계: 가상 메모를 공개 data.json으로 복사한다.
  const source = resolve(root, 'data.json');
  const data = JSON.parse(await readFile(source, 'utf8'));
  if (!Array.isArray(data.notes)) {
    throw new Error('실습용 공개 자료 형식을 확인하세요. 실제 학생 자료를 넣으면 안 됩니다.');
  }
  await copyFile(source, output);
  console.log('실습용 공개 자료를 public/data.json에 복사했습니다.');
} else {
  // 2단계 이후: 메모는 서버 자료(DB)에 있다. 공개 폴더에 data.json을 만들지 않는다.
  await rm(output, { force: true });
  console.log('공개 data.json을 만들지 않습니다. 자료는 /api/notes 서버 함수가 읽습니다.');
}

if (!process.argv.includes('--local')) {
  const identity = deploymentIdentity(process.env, config);
  await writeFile(resolve(root, 'public', 'aleph.json'),
    `${JSON.stringify(identity, null, 2)}\n`, 'utf8');
  console.log('배포 저장소·커밋·주소를 public/aleph.json에 기록했습니다.');
}
