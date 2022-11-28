spicy_add_analyzer(
    NAME PostgreSQL
    PACKAGE_NAME spicy-postgresql
    SOURCES postgresql.spicy postgresql.evt zeek_postgresql.spicy
    SCRIPTS __load__.zeek main.zeek dpd.sig
)
