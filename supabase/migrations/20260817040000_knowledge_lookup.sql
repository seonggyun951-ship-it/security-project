-- 식별자로 찾아보는 경로.
--
-- 유사도 검색으로는 풀리지 않는 질문이 있다.
-- "랜섬웨어에 쓰인 취약점"을 검색하면 문장 틀이 비슷한 1,665건이 서로 가까워
-- 엉뚱한 것이 올라온다. 애초에 이건 검색이 아니라 조회다.
--
-- 실제로 필요한 것은 교집합이다.
--   스캔 결과 CVE 40개 ∩ KEV 1,665건 → 보통 2~5건. 그게 먼저 고칠 것이다.
-- 나머지는 이론상 위험이고, 교집합에 든 것은 실제로 악용된 적이 있는 것이다.

create index if not exists knowledge_ref_idx on knowledge (source, ref);

-- 식별자 목록으로 한 번에 찾는다. 없는 것은 결과에 나오지 않으므로,
-- 호출한 쪽에서 "몇 개 중 몇 개가 걸렸는지"를 그대로 알 수 있다.
create or replace function lookup_knowledge(
  refs text[],
  filter_source text default null
)
returns table (
  id uuid,
  source text,
  ref text,
  content text,
  meta jsonb
)
language sql
stable
as $$
  select k.id, k.source, k.ref, k.content, k.meta
  from knowledge k
  where k.ref = any(refs)
    and (filter_source is null or k.source = filter_source);
$$;

grant execute on function lookup_knowledge to authenticated;

comment on function lookup_knowledge is
  '식별자(CVE ID 등)로 지식을 찾는다. 스캔 결과와 KEV의 교집합을 구할 때 쓴다.';
