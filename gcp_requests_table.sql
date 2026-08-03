create table if not exists gcp_requests (
  id uuid primary key default gen_random_uuid(),
  resource_type text not null,
  action text not null,
  title text,
  target_id text,
  payload jsonb default '{}',
  reason text,
  status text not null default 'pending',
  requester_id uuid,
  requester_email text,
  requested_at timestamptz not null default now(),
  reviewed_at timestamptz,
  applied_at timestamptz,
  result jsonb,
  error_message text
);

alter table gcp_requests enable row level security;

create policy "gcp_requests_all" on gcp_requests for all using (true) with check (true);
