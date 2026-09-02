-- 지식 베이스에 ISMS-P 인증기준을 담을 자리를 만든다.
--
-- source에 허용 목록 제약이 걸려 있어 새 출처는 여기에 더해야 들어간다.
-- 오타로 만들어진 출처가 조용히 쌓이는 걸 막아 주는 장치라 목록 방식은 그대로 둔다.
--
-- 다만 적재 실패 메시지가 '[object Object]'로만 나와 원인을 찾는 데 시간이 걸렸다.
-- 제약에 걸린 것이었다.

alter table public.knowledge drop constraint if exists knowledge_source_check;

alter table public.knowledge add constraint knowledge_source_check
  check (source = any (array[
    'rule_engine', 'mitre', 'owasp', 'aws_baseline', 'concept',
    'policy', 'mitigation', 'gcp_baseline', 'kev',
    'ismsp'
  ]));
