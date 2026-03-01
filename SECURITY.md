-- ============================================
-- VOÛTIX — Schema Supabase
-- Colle ce code dans : Supabase > SQL Editor > New Query
-- ============================================

-- 1. TABLE PROFILS UTILISATEURS
create table if not exists public.profiles (
  id uuid references auth.users on delete cascade primary key,
  email text not null,
  full_name text,
  role text default 'member', -- 'admin' | 'member'
  avatar_url text,
  created_at timestamptz default now()
);

-- 2. TABLE DÉPARTEMENTS
create table if not exists public.departments (
  id uuid default gen_random_uuid() primary key,
  owner_id uuid references public.profiles(id) on delete cascade,
  name text not null,
  icon text default '🏢',
  color text default '#4fffb0',
  external boolean default false,
  created_at timestamptz default now()
);

-- 3. TABLE FICHIERS PARTAGÉS
create table if not exists public.shared_files (
  id uuid default gen_random_uuid() primary key,
  owner_id uuid references public.profiles(id) on delete cascade,
  department_id uuid references public.departments(id) on delete set null,
  file_name text not null,
  file_size bigint default 0,
  file_type text,
  storage_path text not null,
  encrypted boolean default true,
  enc_key_hint text, -- hint seulement, jamais la vraie clé
  expires_at timestamptz not null,
  max_downloads integer default 10,
  download_count integer default 0,
  share_token text unique default encode(gen_random_bytes(16), 'hex'),
  created_at timestamptz default now()
);

-- 4. TABLE JOURNAL D'ACCÈS
create table if not exists public.access_logs (
  id uuid default gen_random_uuid() primary key,
  file_id uuid references public.shared_files(id) on delete cascade,
  ip_address text,
  user_agent text,
  location text,
  action text, -- 'viewed' | 'downloaded' | 'expired' | 'blocked'
  risk_level text default 'normal', -- 'normal' | 'suspect' | 'blocked'
  created_at timestamptz default now()
);

-- ============================================
-- ROW LEVEL SECURITY (chaque user voit ses données)
-- ============================================

alter table public.profiles enable row level security;
alter table public.departments enable row level security;
alter table public.shared_files enable row level security;
alter table public.access_logs enable row level security;

-- Profils : chacun voit le sien
create policy "profiles_own" on public.profiles
  for all using (auth.uid() = id);

-- Départements : chacun voit les siens
create policy "departments_own" on public.departments
  for all using (auth.uid() = owner_id);

-- Fichiers : chacun voit les siens
create policy "files_own" on public.shared_files
  for all using (auth.uid() = owner_id);

-- Accès publics aux fichiers via token (sans auth)
create policy "files_public_read" on public.shared_files
  for select using (true);

-- Logs : propriétaire du fichier voit ses logs
create policy "logs_own" on public.access_logs
  for select using (
    file_id in (
      select id from public.shared_files where owner_id = auth.uid()
    )
  );

create policy "logs_insert_anon" on public.access_logs
  for insert with check (true);

-- ============================================
-- STORAGE BUCKET POUR LES FICHIERS
-- ============================================

insert into storage.buckets (id, name, public)
values ('voutix-files', 'voutix-files', false)
on conflict do nothing;

-- Politique de storage : chaque user gère son dossier
create policy "storage_own" on storage.objects
  for all using (
    bucket_id = 'voutix-files' and
    auth.uid()::text = (storage.foldername(name))[1]
  );

-- ============================================
-- TRIGGER : créer un profil à l'inscription
-- ============================================

create or replace function public.handle_new_user()
returns trigger as $$
begin
  insert into public.profiles (id, email, full_name)
  values (
    new.id,
    new.email,
    coalesce(new.raw_user_meta_data->>'full_name', split_part(new.email, '@', 1))
  );
  return new;
end;
$$ language plpgsql security definer;

drop trigger if exists on_auth_user_created on auth.users;
create trigger on_auth_user_created
  after insert on auth.users
  for each row execute procedure public.handle_new_user();
