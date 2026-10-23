-- AI Asset Gate: hardening bovenop 0001_init.sql. Idempotent; uitvoeren in de Supabase SQL editor.
--  1. Audit trail echt append-only: ook DELETE (behalve cascade vanuit submissions) en TRUNCATE geblokkeerd.
--  2. Geen tabelrechten voor anon/authenticated (naast RLS zonder policies: defense in depth).
--  3. Eén submission per geüpload bestand (unieke file_path) en per Idempotency-Key.
--  4. Governance-regels in de database: Blocked kan niet goedgekeurd worden, publiceren vereist goedkeuring.
--  5. Bucket blijft privé met 50 MB limiet.

-- 1. append-only audit trail ---------------------------------------------------------------
create or replace function public.audit_events_immutable() returns trigger
language plpgsql
set search_path = ''
as $$
begin
  -- verwijderen mag alleen via de foreign key cascade (submission verwijderd); die draait genest in een RI-trigger
  if tg_op = 'DELETE' and pg_trigger_depth() > 1 then
    return old;
  end if;
  raise exception 'audit_events is append-only (% not allowed)', tg_op;
end;
$$;

drop trigger if exists audit_events_no_update on public.audit_events;
create trigger audit_events_no_update
  before update on public.audit_events
  for each row execute function public.audit_events_immutable();

drop trigger if exists audit_events_no_delete on public.audit_events;
create trigger audit_events_no_delete
  before delete on public.audit_events
  for each row execute function public.audit_events_immutable();

drop trigger if exists audit_events_no_truncate on public.audit_events;
create trigger audit_events_no_truncate
  before truncate on public.audit_events
  for each statement execute function public.audit_events_immutable();

revoke all on function public.audit_events_immutable() from public, anon, authenticated;

-- 2. geen directe toegang met de publishable key -------------------------------------------
alter table public.submissions enable row level security;
alter table public.audit_events enable row level security;
revoke all on table public.submissions from anon, authenticated;
revoke all on table public.audit_events from anon, authenticated;

-- 3. een upload hoort bij precies één submission ------------------------------------------
create unique index if not exists submissions_file_path_key
  on public.submissions (file_path)
  where file_path is not null;

-- idempotency: een retry van de browser (Idempotency-Key header) maakt geen tweede submission
alter table public.submissions add column if not exists idempotency_key text
  check (idempotency_key is null or char_length(idempotency_key) between 16 and 100);
create unique index if not exists submissions_idempotency_key_key
  on public.submissions (idempotency_key)
  where idempotency_key is not null;

-- dashboardfilters
create index if not exists submissions_status_idx on public.submissions (status, review_status, catalog_status);

-- 4. governance-regels (not valid: bestaande rijen worden niet herbeoordeeld, nieuwe writes wel) --
do $$
begin
  if not exists (select 1 from pg_constraint where conname = 'submissions_blocked_not_approved') then
    alter table public.submissions
      add constraint submissions_blocked_not_approved
      check (not (review_status = 'approved' and decision = 'blocked')) not valid;
  end if;
  if not exists (select 1 from pg_constraint where conname = 'submissions_publish_requires_approval') then
    alter table public.submissions
      add constraint submissions_publish_requires_approval
      check (catalog_status <> 'published' or (review_status = 'approved' and status = 'completed')) not valid;
  end if;
  if not exists (select 1 from pg_constraint where conname = 'submissions_review_requires_scan') then
    alter table public.submissions
      add constraint submissions_review_requires_scan
      check (review_status = 'pending' or status = 'completed') not valid;
  end if;
  if not exists (select 1 from pg_constraint where conname = 'submissions_text_lengths') then
    alter table public.submissions
      add constraint submissions_text_lengths
      check (
        char_length(owner_name) <= 200
        and char_length(owner_email) <= 200
        and (reviewer is null or char_length(reviewer) <= 100)
        and (review_comment is null or char_length(review_comment) <= 2000)
        and (file_path is null or char_length(file_path) <= 300)
      ) not valid;
  end if;
end;
$$;

-- 5. private bucket -------------------------------------------------------------------------
insert into storage.buckets (id, name, public, file_size_limit)
values ('ai-assets', 'ai-assets', false, 52428800)
on conflict (id) do update set public = false, file_size_limit = excluded.file_size_limit;
