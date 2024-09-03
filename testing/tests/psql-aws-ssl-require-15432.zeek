# @TEST-DOC: Test that the dpd.sig picks up the SSLRequest and server response on a non-standard port.
#
# @TEST-EXEC: zeek -b -Cr ${TRACES}/psql-aws-ssl-require-15432.pcap ${PACKAGE} %INPUT >output
# @TEST-EXEC: zeek-cut -m ts uid id.orig_h id.orig_p id.resp_h id.resp_p service  < conn.log > conn.cut
# @TEST-EXEC: zeek-cut -m ts uid id.orig_h id.orig_p id.resp_h id.resp_p version cipher curve server_name < ssl.log > ssl.cut
#
# @TEST-EXEC: btest-diff conn.cut
# @TEST-EXEC: btest-diff ssl.cut

@load base/protocols/conn
@load base/protocols/ssl
