# @TEST-DOC: Test that the dpd.sig picks up a plaintext connection on a non-standard port.
#
# @TEST-EXEC: zeek -Cr ${TRACES}/psql-aws-ssl-disable-15432.pcap ${PACKAGE} %INPUT >output
#
# @TEST-EXEC: zeek-cut -m ts uid id.orig_h id.orig_p id.resp_h id.resp_p service  < conn.log > conn.cut
#
# @TEST-EXEC: btest-diff conn.cut
