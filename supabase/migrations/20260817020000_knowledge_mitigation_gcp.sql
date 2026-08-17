-- 지식 출처 두 가지 추가.
--
--   mitigation    MITRE ATT&CK 완화책. 지금은 "어떤 공격이 있는지"만 있고
--                 "그래서 어떻게 막는지"가 없어, 막는 방법을 물으면 규칙 엔진
--                 문장을 되풀이했다.
--   gcp_baseline  GCP 보안 기준. 앱에 GCP 신청 화면이 있는데 GCP 지식이 없어
--                 GCP를 물으면 AWS 문서가 걸렸다.
--
-- 출처를 따로 두는 이유: 설명을 만들 때 출처별로 나눠 뽑기 때문이다.
-- 섞어두면 "어떻게 막나"를 물어도 공격 기법 설명만 올라온다.

alter table knowledge drop constraint if exists knowledge_source_check;

alter table knowledge
  add constraint knowledge_source_check
  check (source in (
    'rule_engine', 'mitre', 'owasp', 'aws_baseline',
    'concept', 'policy', 'mitigation', 'gcp_baseline'
  ));
