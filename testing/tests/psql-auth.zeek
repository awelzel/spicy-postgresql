# @TEST-DOC: Test Zeek parsing a trace file through the PostgreSQL analyzer.
#
# @TEST-EXEC: zeek -b -Cr ${TRACES}/psql-select-now.pcap ${PACKAGE} %INPUT >output
#
# @TEST-EXEC: btest-diff output
#
event PostgreSQL::authentication_request(c: connection, identifier: count, data: string) {
	print "authentication_request", c$uid, identifier, data;
}

event PostgreSQL::authentication_response(c: connection, data: string) {
	print "authentication_response", c$uid, data;
}

event PostgreSQL::authentication_ok(c: connection) {
	print "authentication_ok", c$uid;
}
