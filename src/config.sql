create table if not exists pdss (
    name text not null unique,
    url text not null unique,
    relevance integer not null
) strict;

create index if not exists pdss_by_relevance on pdss(relevance desc);
