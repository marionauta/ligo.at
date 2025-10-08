create table if not exists oauth_auth_requests (
    state text not null primary key,
    authserver_iss text not null,
    did text,
    handle text,
    pds_url text,
    pkce_verifier text not null,
    scope text not null,
    dpop_authserver_nonce text not null,
    dpop_private_jwk text not null
) strict, without rowid;

create table if not exists oauth_sessions (
    did text not null primary key,
    handle text,
    pds_url text not null,
    authserver_iss text not null,
    access_token text,
    refresh_token text,
    dpop_authserver_nonce text not null,
    dpop_pds_nonce text,
    dpop_private_jwk text not null
) strict, without rowid;
