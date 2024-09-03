# @TEST-DOC: Test that dump events works out
#
# @TEST-EXEC: zeek -b -Cr ${TRACES}/psql-select-now.pcap ${PACKAGE}/spicy-events.zeek %INPUT >output
#
# @TEST-EXEC: btest-diff output

@load misc/dump-events

redef DumpEvents::dump_all_events = T;
redef DumpEvents::include=/^(PostgreSQL|analyzer_)/;
