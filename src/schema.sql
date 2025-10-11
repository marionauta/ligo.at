drop table if exists keyval;
create table if not exists keyval (
    prefix text not null,
    key text not null,
    value text,
    primary key (prefix, key)
) strict, without rowid;
