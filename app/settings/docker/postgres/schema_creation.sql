create schema if not exists auth;

alter role app set search_path = auth;