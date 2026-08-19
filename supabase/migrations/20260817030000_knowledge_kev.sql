-- 지식 출처에 CISA KEV를 추가한다.
--
-- 취약점 스캔 결과에는 CVE가 수백 개씩 나오는데, 그중 무엇을 먼저 고쳐야 하는지가 문제다.
-- KEV에 올라와 있다는 것은 "이론상 위험"이 아니라 "실제로 악용된 적이 있다"는 뜻이라
-- 우선순위를 가르는 기준이 된다.

alter table knowledge drop constraint if exists knowledge_source_check;

alter table knowledge
  add constraint knowledge_source_check
  check (source in (
    'rule_engine', 'mitre', 'owasp', 'aws_baseline',
    'concept', 'policy', 'mitigation', 'gcp_baseline', 'kev'
  ));
