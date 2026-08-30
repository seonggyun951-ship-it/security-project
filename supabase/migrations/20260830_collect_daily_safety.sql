-- 하루 한 번 수집을 안전망으로 되살린다.
--
-- 8/24에 시간표 수집(aws-collect-daily)을 걷어내고 '승인이 적용되면 수집'으로 바꿨다.
-- 아무것도 안 바뀐 날에 AWS를 긁지 않으려던 것이었는데, 앱 밖에서 일어나는 변경을
-- 계산에 넣지 않았다. dirty는 aws_requests.status가 applied가 될 때만 서므로
-- terraform apply나 콘솔에서 바꾸면 아무도 표시를 세워주지 않는다.
--
-- 실제로 그렇게 됐다. NACL을 Terraform으로 바꾼 뒤 5일 동안 수집이 한 번도 일어나지
-- 않았고(크론은 10분마다 정상적으로 돌았지만 매번 dirty가 아니라 건너뛰었다),
-- 신청 화면에는 이미 없는 NACL이 계속 떠서 적용 단계에서 InvalidNetworkAclID.NotFound로
-- 실패했다.
--
-- dirty 방식은 그대로 둔다. 승인 직후 몇 분 안에 목록이 맞춰지는 건 그쪽이 하는 일이고,
-- 이건 "그 경로를 타지 않은 변경"을 하루 안에는 따라잡게 하는 바닥이다.
-- 하루 한 번이면 비용도 문제되지 않는다.
--
-- 00:30 UTC = 09:30 KST. expire-access가 09:00에 도니 30분 뒤로 둔다(전과 같은 시각).
-- sweep과 겹칠 수는 있으나 sweep은 dirty일 때만 호출을 만들고, 수집이 끝나면
-- dirty가 false로 내려가므로 연달아 두 번 긁히지 않는다.
select cron.unschedule('aws-collect-daily')
where exists (select 1 from cron.job where jobname = 'aws-collect-daily');

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
