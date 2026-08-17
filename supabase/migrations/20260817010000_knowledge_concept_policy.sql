-- 지식 출처 두 가지 추가.
--
-- 지금까지는 판정 사례(rule_engine)와 점검 항목(aws_baseline), 공격 기법(mitre),
-- 웹 보안 원칙(owasp)만 있었다. "Security Group이 무엇인지" 설명하는 자료가 없어
-- LLM이 판정만 되풀이하고 개념을 설명하지 못했다.
--
--   concept  AWS 공식 문서로 확인한 기초 개념 (SG, NACL, CIDR, IAM)
--   policy   이 시스템 고유의 정책. rules.js 상수와 Terraform 파일에서 생성한다

alter table knowledge drop constraint if exists knowledge_source_check;

alter table knowledge
  add constraint knowledge_source_check
  check (source in ('rule_engine', 'mitre', 'owasp', 'aws_baseline', 'concept', 'policy'));
