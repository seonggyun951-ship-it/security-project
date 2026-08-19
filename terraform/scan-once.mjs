// 보안 점검을 한 번만 실행한다. 에이전트를 켜지 않고 결과를 확인할 때 쓴다.
//
//   node scan-once.mjs
//
// 에이전트는 이 모듈(scan.js)을 하루 한 번과 적용 직후에 부른다.
// 이 파일은 그 경로를 그대로 타면서 결과만 화면에 보여준다.

import { createClient } from '@supabase/supabase-js'
import fs from 'fs'
import path from 'path'
import { fileURLToPath } from 'url'
import { runScan } from './scan.js'

const here = path.dirname(fileURLToPath(import.meta.url))

// agent.js와 같은 방식으로 .env를 읽는다
const envPath = path.join(here, '.env')
if (fs.existsSync(envPath)) {
  for (const line of fs.readFileSync(envPath, 'utf-8').split('\n')) {
    const m = line.match(/^\s*([\w.-]+)\s*=\s*(.*)?\s*$/)
    if (m && !process.env[m[1]]) process.env[m[1]] = (m[2] || '').trim()
  }
}

const supabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_SERVICE_KEY)

// 알림은 화면에만 띄운다. 시험 실행이 Discord로 나가면 곤란하다.
const r = await runScan(supabase, {
  notify: async (m) => console.log('\n─── Discord로 갈 내용 ───\n' + m + '\n'),
})

console.log('결과:', JSON.stringify(r, null, 2))
