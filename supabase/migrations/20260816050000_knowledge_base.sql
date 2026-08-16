-- RAG 지식 베이스
--
-- 규칙 엔진의 판정을 자연어로 설명하기 위한 자료를 담는다.
-- LLM은 아무것도 기억하지 않으므로, 질문이 올 때마다 여기서 관련 조각을 찾아
-- 프롬프트에 실어 보낸다. 자료가 우리 DB에 있으니 남의 모델을 써도 된다.
--
-- 담을 것:
--   rule_engine  Terraform 시나리오를 규칙 엔진에 통과시켜 얻은 (설정, 판정, 이유)
--   mitre        MITRE ATT&CK 기법 설명
--   owasp        OWASP Top 10 항목
--
-- 임베딩 모델: nvidia/llama-nemotron-embed-1b-v2, dimensions=1024
--   한국어 신청으로 영어 MITRE/OWASP 문서가 검색되는지(교차 언어) 실측해 고른 모델이다.
--   1024로 줄여도 검색 순위가 같았고, pgvector 인덱스 한계(2000차원)에도 들어간다.

create extension if not exists vector;

create table if not exists knowledge (
  id uuid primary key default gen_random_uuid(),

  content text not null,
  embedding vector(1024),

  source text not null check (source in ('rule_engine', 'mitre', 'owasp')),
  ref text,                                  -- 원문 식별자 (T1021.004, A01:2021 등)
  meta jsonb not null default '{}'::jsonb,

  -- 어떤 모델로 임베딩했는지 남긴다. 나중에 모델을 바꾸면 원문이 남아 있어
  -- 스크립트 한 번으로 다시 임베딩할 수 있다. 원문을 안 남기면 자료를 다시 긁어와야 한다.
  model text not null,

  -- 같은 자료를 다시 넣어도 중복되지 않게 하는 열쇠.
  -- 적재 스크립트를 여러 번 돌려도 안전해야 한다.
  content_hash text not null,

  created_at timestamptz not null default now()
);

create unique index if not exists knowledge_source_hash_key
  on knowledge (source, content_hash);

-- 코사인 유사도 검색용. HNSW는 2000차원까지만 되는데 1024라 문제없다.
create index if not exists knowledge_embedding_idx
  on knowledge using hnsw (embedding vector_cosine_ops);

create index if not exists knowledge_source_idx on knowledge (source);

alter table knowledge enable row level security;

-- 읽기는 로그인한 사용자면 된다. 공개 보안 문서와 우리 규칙 엔진의 판정이라
-- 계정별로 가릴 내용이 없다.
drop policy if exists knowledge_read on knowledge;
create policy knowledge_read on knowledge
  for select to authenticated using (true);

-- 쓰기 정책을 두지 않는다. RLS가 켜져 있고 정책이 없으면 아무도 못 쓴다.
-- 적재는 service_role(Edge Function)만 한다 — service_role은 RLS를 우회한다.

comment on table knowledge is
  'RAG 지식 베이스. 질문이 올 때마다 여기서 조각을 찾아 프롬프트에 실어 보낸다.';
comment on column knowledge.model is
  '임베딩에 쓴 모델. 모델을 바꾸면 content로 재임베딩한다.';
comment on column knowledge.content_hash is
  '같은 자료 재적재 시 중복을 막는 값. md5(content).';

-- 유사도 검색.
-- 임베딩 컬럼을 그대로 돌려주지 않는다 — 조각 하나당 4KB라 응답이 쓸데없이 커진다.
create or replace function match_knowledge(
  query_embedding vector(1024),
  match_count int default 5,
  filter_sources text[] default null,
  min_similarity float default 0.0
)
returns table (
  id uuid,
  content text,
  source text,
  ref text,
  meta jsonb,
  similarity float
)
language sql
stable
as $$
  select
    k.id,
    k.content,
    k.source,
    k.ref,
    k.meta,
    1 - (k.embedding <=> query_embedding) as similarity
  from knowledge k
  where k.embedding is not null
    and (filter_sources is null or k.source = any(filter_sources))
    and 1 - (k.embedding <=> query_embedding) >= min_similarity
  order by k.embedding <=> query_embedding
  limit match_count;
$$;

grant execute on function match_knowledge to authenticated;
