create extension if not exists pgcrypto;
create schema if not exists app_private;

create table if not exists public.profiles (
  id uuid primary key references auth.users(id) on delete cascade,
  public_id char(4) not null unique check (public_id ~ '^[0-9]{4}$'),
  display_name text not null check (char_length(display_name) between 1 and 40),
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create or replace function app_private.generate_public_id()
returns char(4) language plpgsql security definer set search_path = ''
as $$
declare candidate char(4);
begin
  loop
    candidate := lpad((floor(random() * 9000)::int + 1000)::text, 4, '0')::char(4);
    exit when not exists (select 1 from public.profiles where public_id = candidate);
  end loop;
  return candidate;
end;
$$;

create or replace function app_private.handle_new_user()
returns trigger language plpgsql security definer set search_path = ''
as $$
declare display_name_value text;
begin
  display_name_value := coalesce(nullif(trim(new.raw_user_meta_data ->> 'display_name'), ''), 'New member');
  insert into public.profiles (id, public_id, display_name)
  values (new.id, app_private.generate_public_id(), left(display_name_value, 40))
  on conflict (id) do nothing;
  return new;
end;
$$;

drop trigger if exists on_auth_user_created_profile on auth.users;
create trigger on_auth_user_created_profile after insert on auth.users
for each row execute function app_private.handle_new_user();

create table if not exists public.conversations (
  id uuid primary key default gen_random_uuid(),
  created_at timestamptz not null default now(),
  last_message_at timestamptz not null default now()
);
create table if not exists public.conversation_members (
  conversation_id uuid not null references public.conversations(id) on delete cascade,
  user_id uuid not null references auth.users(id) on delete cascade,
  joined_at timestamptz not null default now(),
  last_read_at timestamptz,
  primary key (conversation_id, user_id)
);
create table if not exists public.messages (
  id uuid primary key default gen_random_uuid(),
  conversation_id uuid not null references public.conversations(id) on delete cascade,
  sender_id uuid not null references auth.users(id) on delete cascade,
  ciphertext text not null,
  nonce text not null,
  key_version smallint not null default 1,
  created_at timestamptz not null default now(),
  edited_at timestamptz,
  deleted_at timestamptz
);
create index if not exists messages_conversation_created_idx on public.messages (conversation_id, created_at desc);
create index if not exists messages_sender_idx on public.messages (sender_id);
create index if not exists conversation_members_user_idx on public.conversation_members (user_id, conversation_id);

create table if not exists public.message_receipts (
  message_id uuid not null references public.messages(id) on delete cascade,
  user_id uuid not null references auth.users(id) on delete cascade,
  delivered_at timestamptz,
  seen_at timestamptz,
  primary key (message_id, user_id)
);
create index if not exists message_receipts_user_idx on public.message_receipts (user_id);

create table if not exists public.devices (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references auth.users(id) on delete cascade,
  device_label text not null default 'Web device',
  identity_public_key text not null,
  signed_prekey text,
  signed_prekey_signature text,
  created_at timestamptz not null default now(),
  revoked_at timestamptz
);
create index if not exists devices_user_idx on public.devices (user_id) where revoked_at is null;

create table if not exists app_private.pin_credentials (
  user_id uuid primary key references auth.users(id) on delete cascade,
  pin_hash text not null,
  failed_attempts smallint not null default 0 check (failed_attempts between 0 and 3),
  locked_until timestamptz,
  updated_at timestamptz not null default now()
);
create table if not exists public.pin_credentials (
  user_id uuid primary key references auth.users(id) on delete cascade,
  pin_hash text not null unique,
  failed_attempts smallint not null default 0 check (failed_attempts between 0 and 3),
  locked_until timestamptz,
  updated_at timestamptz not null default now()
);
create table if not exists public.pin_login_attempts (
  client_key text primary key,
  failed_attempts smallint not null default 0 check (failed_attempts between 0 and 3),
  locked_until timestamptz,
  updated_at timestamptz not null default now()
);

create or replace function app_private.is_conversation_member(target_conversation_id uuid, target_user_id uuid default auth.uid())
returns boolean language sql stable security definer set search_path = ''
as $$
  select exists (
    select 1 from public.conversation_members cm
    where cm.conversation_id = target_conversation_id and cm.user_id = target_user_id
  );
$$;

create or replace function public.bump_pin_login_attempt(p_client_key text)
returns table (failed_attempts smallint, locked_until timestamptz)
language plpgsql security definer set search_path = ''
as $$
declare current_row public.pin_login_attempts%rowtype;
begin
  insert into public.pin_login_attempts (client_key, failed_attempts)
  values (p_client_key, 0) on conflict (client_key) do nothing;
  select * into current_row from public.pin_login_attempts where client_key = p_client_key for update;
  if current_row.locked_until is not null and current_row.locked_until > now() then
    return query select current_row.failed_attempts, current_row.locked_until; return;
  end if;
  if current_row.locked_until is not null and current_row.locked_until <= now() then
    current_row.failed_attempts := 0; current_row.locked_until := null;
  end if;
  current_row.failed_attempts := least(current_row.failed_attempts + 1, 3);
  if current_row.failed_attempts >= 3 then current_row.locked_until := now() + interval '30 seconds';
  else current_row.locked_until := null; end if;
  update public.pin_login_attempts set failed_attempts = current_row.failed_attempts,
    locked_until = current_row.locked_until, updated_at = now() where client_key = p_client_key;
  return query select current_row.failed_attempts, current_row.locked_until;
end;
$$;

create or replace function public.reset_pin_login_attempt(p_client_key text)
returns void language sql security definer set search_path = ''
as $$
  update public.pin_login_attempts set failed_attempts = 0, locked_until = null, updated_at = now()
  where client_key = p_client_key;
$$;

create or replace function public.start_one_to_one_conversation(p_target_public_id text)
returns uuid language plpgsql security definer set search_path = ''
as $$
declare
  current_user_id uuid := auth.uid();
  target_user_id uuid;
  conversation_id_value uuid;
  pair_key text;
begin
  if current_user_id is null then raise exception 'Authentication required'; end if;
  select p.id into target_user_id from public.profiles p where p.public_id::text = p_target_public_id;
  if target_user_id is null then raise exception 'Member not found'; end if;
  if target_user_id = current_user_id then raise exception 'Cannot start a conversation with yourself'; end if;
  pair_key := least(current_user_id::text, target_user_id::text) || ':' || greatest(current_user_id::text, target_user_id::text);
  perform pg_advisory_xact_lock(hashtextextended(pair_key, 0));
  select mine.conversation_id into conversation_id_value
  from public.conversation_members mine
  join public.conversation_members theirs on theirs.conversation_id = mine.conversation_id
  join public.conversations c on c.id = mine.conversation_id
  where mine.user_id = current_user_id and theirs.user_id = target_user_id limit 1;
  if conversation_id_value is not null then return conversation_id_value; end if;
  insert into public.conversations default values returning id into conversation_id_value;
  insert into public.conversation_members (conversation_id, user_id)
  values (conversation_id_value, current_user_id), (conversation_id_value, target_user_id);
  return conversation_id_value;
end;
$$;

create or replace function app_private.handle_new_message()
returns trigger language plpgsql security definer set search_path = ''
as $$
begin
  update public.conversations set last_message_at = new.created_at where id = new.conversation_id;
  insert into public.message_receipts (message_id, user_id)
  select new.id, cm.user_id from public.conversation_members cm
  where cm.conversation_id = new.conversation_id and cm.user_id <> new.sender_id
  on conflict (message_id, user_id) do nothing;
  return new;
end;
$$;
drop trigger if exists on_message_insert_update_conversation on public.messages;
create trigger on_message_insert_update_conversation after insert on public.messages
for each row execute function app_private.handle_new_message();

alter table public.profiles enable row level security;
alter table public.conversations enable row level security;
alter table public.conversation_members enable row level security;
alter table public.messages enable row level security;
alter table public.message_receipts enable row level security;
alter table public.devices enable row level security;
alter table app_private.pin_credentials enable row level security;
alter table public.pin_credentials enable row level security;
alter table public.pin_login_attempts enable row level security;

drop policy if exists "Authenticated users can view public profiles" on public.profiles;
create policy "Authenticated users can view public profiles" on public.profiles for select to authenticated using (true);
drop policy if exists "Users can update their own profile" on public.profiles;
create policy "Users can update their own profile" on public.profiles for update to authenticated
using ((select auth.uid()) = id) with check ((select auth.uid()) = id);

drop policy if exists "Members can view their conversations" on public.conversations;
create policy "Members can view their conversations" on public.conversations for select to authenticated
using (exists (select 1 from public.conversation_members cm where cm.conversation_id = id and cm.user_id = (select auth.uid())));

drop policy if exists "Members can view membership rows for their conversations" on public.conversation_members;
create policy "Members can view membership rows for their conversations" on public.conversation_members for select to authenticated
using (app_private.is_conversation_member(conversation_id, (select auth.uid())));

drop policy if exists "Members can read messages in their conversations" on public.messages;
create policy "Members can read messages in their conversations" on public.messages for select to authenticated
using (exists (select 1 from public.conversation_members cm where cm.conversation_id = messages.conversation_id and cm.user_id = (select auth.uid())));
drop policy if exists "Members can send their own messages" on public.messages;
create policy "Members can send their own messages" on public.messages for insert to authenticated
with check (sender_id = (select auth.uid()) and exists (
  select 1 from public.conversation_members cm where cm.conversation_id = messages.conversation_id and cm.user_id = (select auth.uid())
));

drop policy if exists "Users can read receipts in their conversations" on public.message_receipts;
create policy "Users can read receipts in their conversations" on public.message_receipts for select to authenticated
using (user_id = (select auth.uid()) or exists (
  select 1 from public.messages m join public.conversation_members cm on cm.conversation_id = m.conversation_id
  where m.id = message_id and cm.user_id = (select auth.uid())
));
drop policy if exists "Users can update their own receipt" on public.message_receipts;
create policy "Users can update their own receipt" on public.message_receipts for update to authenticated
using (user_id = (select auth.uid())) with check (user_id = (select auth.uid()));

drop policy if exists "Users can view active device public keys" on public.devices;
create policy "Users can view active device public keys" on public.devices for select to authenticated using (revoked_at is null);
drop policy if exists "Users can add their own device keys" on public.devices;
create policy "Users can add their own device keys" on public.devices for insert to authenticated with check (user_id = (select auth.uid()));
drop policy if exists "Users can revoke their own devices" on public.devices;
create policy "Users can revoke their own devices" on public.devices for update to authenticated
using (user_id = (select auth.uid())) with check (user_id = (select auth.uid()));

revoke all on schema app_private from public, anon, authenticated;
grant usage on schema app_private to authenticated;
revoke all on all tables in schema app_private from public, anon, authenticated;
grant usage on schema app_private to service_role;
grant all on all tables in schema app_private to service_role;
revoke all on function app_private.generate_public_id() from public, anon, authenticated;
revoke all on function app_private.handle_new_user() from public, anon, authenticated;
revoke all on function app_private.handle_new_message() from public, anon, authenticated;
revoke all on function app_private.is_conversation_member(uuid, uuid) from public, anon;
grant execute on function app_private.is_conversation_member(uuid, uuid) to authenticated;

revoke all on public.pin_credentials, public.pin_login_attempts from public, anon, authenticated;
grant all on public.pin_credentials, public.pin_login_attempts to service_role;
revoke all on function public.bump_pin_login_attempt(text) from public, anon, authenticated;
revoke all on function public.reset_pin_login_attempt(text) from public, anon, authenticated;
grant execute on function public.bump_pin_login_attempt(text) to service_role;
grant execute on function public.reset_pin_login_attempt(text) to service_role;
revoke all on function public.start_one_to_one_conversation(text) from public, anon;
grant execute on function public.start_one_to_one_conversation(text) to authenticated;

grant select, update on public.profiles to authenticated;
grant select on public.conversations, public.conversation_members, public.messages, public.message_receipts, public.devices to authenticated;
grant insert on public.messages to authenticated;
grant insert, update on public.message_receipts to authenticated;
grant insert, update on public.devices to authenticated;

do $$
begin
  if to_regprocedure('public.rls_auto_enable()') is not null then
    execute 'revoke all on function public.rls_auto_enable() from public, anon, authenticated';
  end if;
  if not exists (select 1 from pg_publication_tables where pubname = 'supabase_realtime' and schemaname = 'public' and tablename = 'messages') then
    alter publication supabase_realtime add table public.messages;
  end if;
end $$;
