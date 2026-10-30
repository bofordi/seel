-- SellXBay schema for Supabase. Run this in SQL Editor.
create extension if not exists pgcrypto;

create type public.user_role as enum ('user','admin','support_manager','buyback_manager','product_manager');
create type public.item_status as enum ('draft','published','archived');
create type public.review_status as enum ('pending','approved','rejected');
create type public.chat_type as enum ('support','buyback','order');

create table public.profiles (
  id uuid primary key references auth.users(id) on delete cascade,
  email text,
  display_name text,
  role public.user_role not null default 'user',
  created_at timestamptz not null default now()
);
create table public.shops (
  id uuid primary key default gen_random_uuid(),
  owner_id uuid not null references public.profiles(id) on delete cascade,
  name text not null,
  slug text unique,
  description text not null,
  category text not null,
  status public.review_status not null default 'pending',
  is_official boolean not null default false,
  created_at timestamptz not null default now()
);
create table public.products (
  id uuid primary key default gen_random_uuid(),
  seller_id uuid not null references public.profiles(id),
  shop_id uuid references public.shops(id) on delete set null,
  title text not null,
  description text,
  category text not null,
  price numeric(12,2) not null check(price >= 0),
  image_url text,
  status public.item_status not null default 'draft',
  created_at timestamptz not null default now()
);
create table public.buyback_requests (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references public.profiles(id),
  manager_id uuid references public.profiles(id),
  title text not null,
  category text not null,
  model text,
  condition text,
  description text,
  desired_price numeric(12,2) default 0,
  city text,
  status text not null default 'pending_manager',
  created_at timestamptz not null default now()
);
create table public.chats (
  id uuid primary key default gen_random_uuid(),
  customer_id uuid not null references public.profiles(id),
  manager_id uuid references public.profiles(id),
  buyback_request_id uuid references public.buyback_requests(id) on delete set null,
  type public.chat_type not null default 'support',
  created_at timestamptz not null default now()
);
create table public.messages (
  id uuid primary key default gen_random_uuid(),
  chat_id uuid not null references public.chats(id) on delete cascade,
  sender_id uuid not null references public.profiles(id),
  body text not null,
  created_at timestamptz not null default now()
);

create or replace function public.current_role()
returns public.user_role language sql stable security definer set search_path=public
as $$ select role from public.profiles where id=auth.uid() $$;
create or replace function public.is_admin()
returns boolean language sql stable security definer set search_path=public
as $$ select coalesce(public.current_role()='admin',false) $$;

create or replace function public.handle_new_user()
returns trigger language plpgsql security definer set search_path=public
as $$
begin
 insert into public.profiles(id,email,display_name,role)
 values(new.id,new.email,coalesce(new.raw_user_meta_data->>'display_name',''),'user')
 on conflict(id) do nothing;
 return new;
end $$;
create trigger on_auth_user_created after insert on auth.users
for each row execute procedure public.handle_new_user();

create or replace function public.get_or_create_support_chat()
returns public.chats language plpgsql security definer set search_path=public
as $$
declare c public.chats;
begin
 if auth.uid() is null then raise exception 'Authentication required'; end if;
 select * into c from public.chats where customer_id=auth.uid() and type='support' order by created_at desc limit 1;
 if c.id is null then
   insert into public.chats(customer_id,type) values(auth.uid(),'support') returning * into c;
 end if;
 return c;
end $$;

create or replace function public.create_buyback_chat(request_id uuid)
returns public.chats language plpgsql security definer set search_path=public
as $$
declare c public.chats; r public.buyback_requests;
begin
 select * into r from public.buyback_requests where id=request_id and user_id=auth.uid();
 if r.id is null then raise exception 'Request not found'; end if;
 insert into public.chats(customer_id,buyback_request_id,type) values(auth.uid(),request_id,'buyback') returning * into c;
 return c;
end $$;

alter table public.profiles enable row level security;
alter table public.shops enable row level security;
alter table public.products enable row level security;
alter table public.buyback_requests enable row level security;
alter table public.chats enable row level security;
alter table public.messages enable row level security;

create policy "profiles self or admin read" on public.profiles for select using(id=auth.uid() or public.is_admin());
create policy "profile self update safe fields" on public.profiles for update using(id=auth.uid()) with check(id=auth.uid() and role=(select p.role from public.profiles p where p.id=auth.uid()));
create policy "admin profiles manage" on public.profiles for all using(public.is_admin()) with check(public.is_admin());

create policy "approved shops public read" on public.shops for select using(status='approved' or owner_id=auth.uid() or public.is_admin());
create policy "users apply shop" on public.shops for insert with check(owner_id=auth.uid() and status='pending' and is_official=false);
create policy "admin shop moderation" on public.shops for update using(public.is_admin()) with check(public.is_admin());

create policy "published products public read" on public.products for select using(status='published' or seller_id=auth.uid() or public.is_admin());
create policy "seller add product only after shop approved or authorized staff" on public.products for insert with check(
 public.is_admin() or public.current_role()='product_manager' or (seller_id=auth.uid() and shop_id is not null and exists(select 1 from public.shops s where s.id=shop_id and s.owner_id=auth.uid() and s.status='approved'))
);
create policy "seller or admin update product" on public.products for update using(seller_id=auth.uid() or public.is_admin()) with check(seller_id=auth.uid() or public.is_admin());
create policy "admin or seller delete product" on public.products for delete using(seller_id=auth.uid() or public.is_admin());

create policy "buyback customer or admin manager read" on public.buyback_requests for select using(user_id=auth.uid() or public.is_admin() or manager_id=auth.uid() or public.current_role()='buyback_manager');
create policy "customer create buyback" on public.buyback_requests for insert with check(user_id=auth.uid());
create policy "admin and assigned manager update buyback" on public.buyback_requests for update using(public.is_admin() or manager_id=auth.uid() or public.current_role()='buyback_manager') with check(public.is_admin() or manager_id=auth.uid() or public.current_role()='buyback_manager');

create policy "chat participants or admin read" on public.chats for select using(customer_id=auth.uid() or manager_id=auth.uid() or public.is_admin() or public.current_role() in ('support_manager','buyback_manager'));
create policy "customer create chat" on public.chats for insert with check(customer_id=auth.uid());
create policy "admin assign manager" on public.chats for update using(public.is_admin()) with check(public.is_admin());

create policy "chat members and admin read messages" on public.messages for select using(
 exists(select 1 from public.chats c where c.id=chat_id and (c.customer_id=auth.uid() or c.manager_id=auth.uid() or public.is_admin() or public.current_role() in ('support_manager','buyback_manager')))
);
create policy "chat members send messages" on public.messages for insert with check(
 sender_id=auth.uid() and exists(select 1 from public.chats c where c.id=chat_id and (c.customer_id=auth.uid() or c.manager_id=auth.uid() or public.is_admin() or public.current_role() in ('support_manager','buyback_manager')))
);

insert into storage.buckets(id,name,public) values('product-images','product-images',true) on conflict(id) do nothing;
create policy "public read product images" on storage.objects for select using(bucket_id='product-images');
create policy "authenticated upload product images" on storage.objects for insert to authenticated with check(bucket_id='product-images');
