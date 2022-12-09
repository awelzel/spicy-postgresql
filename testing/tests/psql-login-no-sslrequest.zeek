# @TEST-DOC: The client does not start with SSLRequest. This pcap has two connections which is a bit strange, but must have been psql doing something.
#
# @TEST-EXEC: zeek -Cr ${TRACES}/psql-login-no-sslrequest.pcap ${PACKAGE} %INPUT >output
#
# @TEST-EXEC: zeek-cut -m ts uid id.orig_h id.orig_p id.resp_h id.resp_p service  < conn.log > conn.cut
# @TEST-EXEC: zeek-cut -m < postgresql.log > postgresql.cut
#
# @TEST-EXEC: btest-diff conn.cut
# @TEST-EXEC: btest-diff postgresql.cut
