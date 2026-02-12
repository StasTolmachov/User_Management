alter table users
add column role varchar(20) not null default 'user';

alter table users
add constraint check_role check ( role in ('user', 'moderator', 'admin') );