create extension if not exists pgcrypto with schema extensions;

create table if not exists public.workbench_sync (
  access_hash text primary key,
  payload jsonb not null default '{}'::jsonb,
  changed_at timestamptz not null default timezone('utc', now())
);

alter table public.workbench_sync enable row level security;
revoke all on table public.workbench_sync from public, anon, authenticated;

create or replace function public.workbench_sync_pull(p_code text)
returns jsonb
language plpgsql
security definer
set search_path = public, extensions
as $$
declare
  result jsonb;
  code_hash text;
begin
  if length(p_code) < 24 then
    raise exception 'invalid sync code';
  end if;
  code_hash := encode(digest(p_code, 'sha256'), 'hex');
  select jsonb_build_object(
    'exists', true,
    'payload', payload,
    'changed_at', changed_at
  ) into result
  from public.workbench_sync
  where access_hash = code_hash;
  return coalesce(result, jsonb_build_object('exists', false));
end;
$$;

create or replace function public.workbench_sync_save(p_code text, p_payload jsonb)
returns jsonb
language plpgsql
security definer
set search_path = public, extensions
as $$
declare
  code_hash text;
  saved_at timestamptz;
begin
  if length(p_code) < 24 then
    raise exception 'invalid sync code';
  end if;
  if pg_column_size(p_payload) > 1048576 then
    raise exception 'payload too large';
  end if;
  code_hash := encode(digest(p_code, 'sha256'), 'hex');
  saved_at := timezone('utc', now());
  insert into public.workbench_sync(access_hash, payload, changed_at)
  values (code_hash, p_payload, saved_at)
  on conflict (access_hash) do update
    set payload = excluded.payload,
        changed_at = excluded.changed_at;
  return jsonb_build_object('saved', true, 'changed_at', saved_at);
end;
$$;

revoke all on function public.workbench_sync_pull(text) from public;
revoke all on function public.workbench_sync_save(text, jsonb) from public;
grant execute on function public.workbench_sync_pull(text) to anon, authenticated;
grant execute on function public.workbench_sync_save(text, jsonb) to anon, authenticated;
