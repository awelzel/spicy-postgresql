# @TEST-DOC: Event for name, value pairs in the startup message.
# @TEST-EXEC: zeek -Cr ${TRACES}/psql-login-no-sslrequest.pcap ${PACKAGE} %INPUT >output
# @TEST-EXEC: btest-diff output

event PostgreSQL::startup_parameter(c: connection, name: string, value: string) {
	print "startup_parameter", c$uid, name, value;
}
