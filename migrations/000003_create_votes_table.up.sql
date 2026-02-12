create table votes (
    user_id uuid not null unique references users(id) on delete cascade,
    target_id uuid not null unique references users(id) on delete cascade,
    value smallint not null check ( value in (-1, 1) ),
    update_at timestamptz not null default now(),
    primary key (user_id, target_id)
);

create index idx_votes_user_updated on votes(user_id, update_at);

create index idx_votes_target on votes(target_id);