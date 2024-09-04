# @TEST-DOC: Test the parameter status event.
#
# @TEST-EXEC: zeek -b -Cr ${TRACES}/psql-login-no-sslrequest.pcap ${PACKAGE} %INPUT >output
#
# @TEST-EXEC: btest-diff output

event PostgreSQL::parameter_status(c: connection, name: string, value: string) {
	print "parameter_status", c$uid, name, value;
}
