-- AI Asset Gate: schema voor submissions, audit trail en de private upload-bucket.
-- Alle toegang loopt via de server (secret key). RLS staat aan zonder policies,
-- dus de publishable key in de browser kan geen rijen lezen of schrijven.

create extension if not exists pgcrypto;

create table if not exists public.submissions (
  id              uuid primary key default gen_random_uuid(),
  created_at      timestamptz not null default now(),
  asset_name      text not null check (char_length(asset_name) <= 200),
  asset_version   text,
  owner_name      text not null,
  owner_email     text not null,
  business_unit   text,
  asset_type      text,
  answers         jsonb not null default '{}'::jsonb,
  file_name       text,
  file_size       bigint,
  file_path       text,
  file_sha256     text,
  status          text not null default 'scanning' check (status in ('scanning', 'completed', 'failed')),
  decision        text check (decision in ('approved', 'conditional', 'blocked')),
  score           integer check (score between 0 and 100),
  ai_act_tier     text check (ai_act_tier in ('prohibited', 'high', 'limited', 'minimal')),
  counts          jsonb,
  report          jsonb,
  error           text,
  review_status   text not null default 'pending' check (review_status in ('pending', 'approved', 'rejected')),
  reviewer        text,
  review_comment  text,
  reviewed_at     timestamptz,
  catalog_status  text not null default 'not_published' check (catalog_status in ('not_published', 'published')),
  published_at    timestamptz
);

create index if not exists submissions_created_at_idx on public.submissions (created_at desc);

create table if not exists public.audit_events (
  id             uuid primary key default gen_random_uuid(),
  submission_id  uuid not null references public.submissions (id) on delete cascade,
  created_at     timestamptz not null default now(),
  actor          text not null,
  action         text not null,
  detail         jsonb not null default '{}'::jsonb
);

create index if not exists audit_events_submission_idx on public.audit_events (submission_id, created_at);

alter table public.submissions enable row level security;
alter table public.audit_events enable row level security;

-- Audit-regels zijn onveranderlijk (verwijderen kan alleen samen met de submission).
create or replace function public.audit_events_immutable() returns trigger
language plpgsql
set search_path = ''
as $$
begin
  raise exception 'audit_events rows cannot be modified';
end;
$$;

drop trigger if exists audit_events_no_update on public.audit_events;
create trigger audit_events_no_update
  before update on public.audit_events
  for each row execute function public.audit_events_immutable();

-- Private bucket voor geüploade assets (max 50 MB, alleen archieven en broncode).
insert into storage.buckets (id, name, public, file_size_limit)
values ('ai-assets', 'ai-assets', false, 52428800)
on conflict (id) do update set public = false, file_size_limit = excluded.file_size_limit;
