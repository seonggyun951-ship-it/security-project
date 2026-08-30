-- AWS 리소스 수집을 정기적으로 돌린다.
--
-- 지금까지는 관리자가 화면에서 버튼을 눌러야만 수집됐다. 안 누르면 신청 화면
-- 드롭다운이 옛날 상태로 남고, 사라진 리소스를 골라 신청했다가 적용 단계에서 실패한다.
--
-- 크론에는 로그인한 사람이 없으므로 CRON_SECRET 헤더로 확인한다(expire-access와 동일).
-- 시크릿은 저장소에 두지 않고 Vault에서 이름으로 꺼내 쓴다.
--
-- 00:30 UTC = 09:30 KST. expire-access가 09:00에 돌므로 겹치지 않게 30분 뒤로 뒀다.
select cron.schedule(
  'aws-collect-daily',
  '30 0 * * *',
  $$
  select net.http_post(
    url := 'https://phqiejtztwhychazikim.supabase.co/functions/v1/aws-collect',
    headers := jsonb_build_object(
      'Content-Type', 'application/json',
      'x-cron-secret', (select decrypted_secret from vault.decrypted_secrets where name = 'cron_secret')
    ),
    body := '{}'::jsonb,
    timeout_milliseconds := 120000
  );
  $$
);
