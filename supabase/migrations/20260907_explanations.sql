-- 생성된 설명을 남긴다.
--
-- 지금까지 rag-explain은 부를 때마다 설명을 만들고 버렸다. 그래서 "무엇을 물었을 때
-- 어떤 근거로 이렇게 답했다"는 기록이 하나도 없다. 나중에 정제해 파인튜닝 재료로
-- 쓰려면 그 쌍이 있어야 하고, 지금 안 쌓으면 나중에 소급할 방법이 없다.
--
-- 검증(rating)은 자리만 만들어 둔다. 모이기 전에 검토 화면부터 만들면 볼 게 없다.

create table if not exists public.explanations (
  id          uuid primary key default gen_random_uuid(),
  created_at  timestamptz not null default now(),

  -- 무엇에 대한 설명인가.
  -- request = 신청 검토, finding = 점검 결과. subject_id는 각각 신청 id와 check_id다.
  kind        text not null check (kind in ('request', 'finding', 'question')),
  subject_id  text,
  user_id     uuid references auth.users(id) on delete set null,

  -- 입력. 같은 질문이 어떤 판정과 함께 들어왔는지까지 남겨야 재현이 된다.
  summary     text,
  question    text,
  findings    jsonb not null default '[]'::jsonb,
  verdict     text,

  -- 근거. 검색으로 뽑은 것과 표가 지정한 것을 나눠 담는다 —
  -- 나중에 어느 쪽이 나은 답을 만들었는지 갈라 보려면 섞여 있으면 안 된다.
  sources     jsonb not null default '[]'::jsonb,
  pinned_refs jsonb,

  -- 출력
  answer      text not null,
  model       text not null,
  usage       jsonb,

  -- 검증. 사람이 보고 표시한다. 아직 화면은 없다.
  rating      text check (rating in ('good', 'bad')),
  rated_by    uuid references auth.users(id) on delete set null,
  rated_at    timestamptz,
  note        text
);

-- 최근 것부터 훑는 게 기본이고, 검증 화면은 아직 표시 안 한 것만 골라 본다.
create index if not exists explanations_created_idx on public.explanations (created_at desc);
create index if not exists explanations_unrated_idx on public.explanations (created_at desc)
  where rating is null;

alter table public.explanations enable row level security;

-- 읽기와 검증 표시는 관리자만. 신청자에게는 자기 신청 화면에서 설명이 이미 보이므로
-- 이 표를 따로 열어 줄 이유가 없다.
drop policy if exists "admin can select explanations" on public.explanations;
create policy "admin can select explanations"
  on public.explanations for select to authenticated
  using (exists (select 1 from public.admins a where a.user_id = auth.uid()));

drop policy if exists "admin can rate explanations" on public.explanations;
create policy "admin can rate explanations"
  on public.explanations for update to authenticated
  using (exists (select 1 from public.admins a where a.user_id = auth.uid()))
  with check (exists (select 1 from public.admins a where a.user_id = auth.uid()));

-- 넣는 것은 Edge Function(서비스 키)만 한다. 클라이언트가 직접 쓰게 두면
-- 실제로 생성되지 않은 기록이 섞일 수 있고, 그러면 학습 재료로서 값을 잃는다.

comment on table public.explanations is
  '생성된 설명 기록. 정제해 파인튜닝 재료로 쓴다. 넣는 것은 rag-explain만.';
