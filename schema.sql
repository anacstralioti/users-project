create table if not exists usuarios (
    id integer primary key autoincrement,
    login varchar not null unique,
    senha varchar not null,
    nome varchar not null,
    created timestamp default current_timestamp,
    modified timestamp default current_timestamp,
    status smallint default 1,
    is_admin INTEGER NOT NULL DEFAULT 0
);