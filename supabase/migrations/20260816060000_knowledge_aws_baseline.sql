-- 지식 출처에 AWS 보안 기준선을 추가한다.
--
-- 규칙 엔진은 우리가 직접 짠 몇 가지(SG 포트·CIDR, S3 일부, GCP 방화벽)만 본다.
-- 실제 AWS 운영에서 지켜야 할 것은 훨씬 많아서, 규칙에 없는 질문에는 근거가 없었다.
-- 키 순환, MFA, 로그 보존, 암호화 같은 기준선을 별도 출처로 담는다.

alter table knowledge drop constraint if exists knowledge_source_check;

alter table knowledge
  add constraint knowledge_source_check
  check (source in ('rule_engine', 'mitre', 'owasp', 'aws_baseline'));
