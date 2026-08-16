-- 만료 회수 배치를 하루 한 번 돌린다.
--
-- 매일 09:00 KST (00:00 UTC). 만료 목적이라 몇 시간 늦어도 문제가 없고,
-- 자주 돌릴수록 AWS API 호출만 늘어난다.
--
-- 시크릿은 저장소에 두지 않는다. Vault에 넣어두고 여기서는 이름으로만 꺼낸다.
-- 넣는 방법은 아래 주석 참고.

create extension if not exists pg_cron;
create extension if not exists pg_net;

-- 같은 이름의 작업이 이미 있으면 지우고 다시 만든다 (재적용 가능하게).
do $$
begin
  perform cron.unschedule('expire-access-daily');
exception
  when others then null; -- 아직 없으면 그냥 넘어간다
end $$;

select cron.schedule(
  'expire-access-daily',
  '0 0 * * *',
  $cron$
  select net.http_post(
    url := 'https://phqiejtztwhychazikim.supabase.co/functions/v1/expire-access',
    headers := jsonb_build_object(
      'Content-Type', 'application/json',
      'x-cron-secret', (select decrypted_secret from vault.decrypted_secrets where name = 'cron_secret')
    ),
    body := '{}'::jsonb,
    timeout_milliseconds := 120000
  );
  $cron$
);

-- 시크릿 등록 (한 번만, Supabase SQL Editor에서 직접 실행):
--   select vault.create_secret('<CRON_SECRET 값>', 'cron_secret');
-- 바꿀 때:
--   select vault.update_secret(
--     (select id from vault.secrets where name = 'cron_secret'), '<새 값>');
