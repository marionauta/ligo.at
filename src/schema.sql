create table if not exists oauth_session (
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
