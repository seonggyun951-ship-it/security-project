-- 임베딩 모델 교체에 따른 차원 변경: 1024 → 2048.
--
-- 쓰던 nvidia/llama-nemotron-embed-1b-v2가 2026-08-25 18:00(KST)에 서비스 종료됐다.
-- 살아 있는 임베딩 모델을 전부 호출해 확인한 결과 응답하는 건 두 개뿐이었고,
-- 그중 nvidia/nemotron-3-embed-1b을 골랐다 (34개 언어·32K 컨텍스트·RTEB 1위).
--
-- 임베딩은 모델마다 좌표계가 달라 섞어 쓸 수 없다. 기존 3,355건의 벡터는 버리고
-- 새 모델로 전부 다시 만든다. 원문(content)은 그대로 있으므로 자료를 다시 긁을 필요는 없다.
--
-- 인덱스 주의 — pgvector의 hnsw는 vector 타입을 2000차원까지만 색인한다. 2048은 넘는다.
-- 값은 vector(2048)로 정확하게 두고, 색인은 halfvec으로 캐스팅한 식에 건다
-- (halfvec은 4000차원까지 가능). 검색 함수도 같은 식으로 정렬해야 이 인덱스를 탄다.

drop index if exists knowledge_embedding_idx;

-- 타입을 바꾸려면 기존 값이 비어 있어야 한다. 어차피 못 쓰는 값이다.
update public.knowledge set embedding = null where embedding is not null;

alter table public.knowledge
  alter column embedding type vector(2048);

create index knowledge_embedding_idx on public.knowledge
  using hnsw ((embedding::halfvec(2048)) halfvec_cosine_ops);

-- 정렬은 인덱스와 같은 식(halfvec)으로, 점수는 원본 vector로 정확히 계산한다.
-- 인덱스가 후보를 좁히고 점수는 손실 없이 매기는 형태다.
create or replace function public.match_knowledge(
  query_embedding vector,
  match_count integer default 5,
  filter_sources text[] default null,
  min_similarity double precision default 0.0
)
returns table (id uuid, content text, source text, ref text, meta jsonb, similarity double precision)
language sql
stable
as $function$
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
  order by k.embedding::halfvec(2048) <=> query_embedding::halfvec(2048)
  limit match_count;
$function$;
