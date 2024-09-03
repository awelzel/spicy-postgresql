# @TEST-DOC: Test that misc/dump-events works right just with spicy-events.zeek
#
# @TEST-EXEC: zeek -b -Cr ${TRACES}/psql-select-now.pcap ${PACKAGE}/spicy-events.zeek %INPUT >output
#
# @TEST-EXEC: btest-diff output

@load misc/dump-events

redef DumpEvents::dump_all_events = T;
redef DumpEvents::include=/^(PostgreSQL|analyzer_)/;

event zeek_init() {
	Analyzer::register_for_port(Analyzer::ANALYZER_POSTGRESQL, 5432/tcp);
}
