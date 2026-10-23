-- AI Asset Gate: versies van hetzelfde asset aan elkaar koppelen. Idempotent; uitvoeren in de Supabase SQL editor
-- na 0001_init.sql en 0002_hardening.sql.
-- Een herindiening wijst naar de vorige versie, zodat het rapport kan tonen wat er is opgelost, wat nieuw is en wat
-- nog open staat. Zonder deze migratie werkt de vergelijking ook (die staat in report.comparison), maar ziet een oud
-- rapport niet dat er een nieuwere versie is.

alter table public.submissions add column if not exists previous_id uuid
  references public.submissions (id) on delete set null;

do $$
begin
  if not exists (select 1 from pg_constraint where conname = 'submissions_previous_not_self') then
    alter table public.submissions
      add constraint submissions_previous_not_self check (previous_id is null or previous_id <> id);
  end if;
end;
$$;

create index if not exists submissions_previous_id_idx
  on public.submissions (previous_id, created_at desc)
  where previous_id is not null;
