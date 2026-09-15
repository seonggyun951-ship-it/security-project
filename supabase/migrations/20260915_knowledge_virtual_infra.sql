-- 지식 소스에 virtual_infra 추가.
--
-- 가상 회사 설계(design/virtual-company.yaml)를 RAG 지식으로 색인하려면
-- knowledge.source 화이트리스트에 이 소스를 넣어야 한다. 없으면 rag-index가
-- 제약에 걸려 거부하는데, 오류가 [object Object]로만 떠서 원인을 못 찾는다.
--
-- 소스 목록은 지금까지 추가된 순서대로 둔다.

alter table knowledge drop constraint if exists knowledge_source_check;
alter table knowledge
  add constraint knowledge_source_check
  check (source in (
    'rule_engine', 'mitre', 'owasp', 'aws_baseline', 'concept',
    'policy', 'mitigation', 'gcp_baseline', 'kev', 'ismsp',
    'virtual_infra'
  ));
