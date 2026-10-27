create table notes (id uuid primary key, body text, owner uuid);
alter table notes disable row level security;
