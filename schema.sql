-- شغّل هذا النص في SQL Editor داخل مشروع Supabase جديد مخصص للأرشيف فقط.
-- لا تشغّله داخل قواعد بيانات الحضور أو شؤون المعلمين السابقة.
create extension if not exists pgcrypto;

create table if not exists public.archive_users (
  id uuid primary key default gen_random_uuid(),
  username text not null unique,
  full_name text not null,
  password_hash text not null,
  role text not null default 'scanner' check(role in ('admin','scanner','viewer')),
  active boolean not null default true,
  created_at timestamptz not null default now()
);

create table if not exists public.archive_teachers (
  id uuid primary key default gen_random_uuid(),
  full_name text not null,
  national_id text not null unique,
  position text not null,
  created_at timestamptz not null default now()
);

create table if not exists public.archive_documents (
  id uuid primary key default gen_random_uuid(),
  teacher_id uuid not null references public.archive_teachers(id) on delete cascade,
  kind text not null check (kind in ('start','appointment','birth','service','qualification')),
  storage_path text not null unique,
  pages integer not null default 1 check(pages > 0),
  version integer not null default 1,
  uploaded_by uuid references public.archive_users(id) on delete set null,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  unique(teacher_id,kind)
);

create table if not exists public.archive_logs (
  id uuid primary key default gen_random_uuid(),
  actor_id uuid references public.archive_users(id) on delete set null,
  actor_name text,
  action text not null,
  details text,
  created_at timestamptz not null default now()
);

create index if not exists archive_documents_teacher_idx on public.archive_documents (teacher_id);
create index if not exists archive_logs_created_idx on public.archive_logs (created_at desc);

-- لا يصل أحد لهذه الجداول مباشرة بواسطة مفتاح anon أو authenticated.
-- تطبيق Flask فقط يستعمل المفتاح السري على خادم Render.
alter table public.archive_users enable row level security;
alter table public.archive_teachers enable row level security;
alter table public.archive_documents enable row level security;
alter table public.archive_logs enable row level security;
revoke all on public.archive_users from anon, authenticated;
revoke all on public.archive_teachers from anon, authenticated;
revoke all on public.archive_documents from anon, authenticated;
revoke all on public.archive_logs from anon, authenticated;
grant all on public.archive_users to service_role;
grant all on public.archive_teachers to service_role;
grant all on public.archive_documents to service_role;
grant all on public.archive_logs to service_role;

-- مخزن صور PDF خاص (لا تجعله Public نهائيًا).
insert into storage.buckets (id, name, public)
values ('teacher-archive-private','teacher-archive-private',false)
on conflict(id) do update set public=false;
