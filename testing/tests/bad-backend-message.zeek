# @TEST-DOC: Startup message triggering integer overflow

# @TEST-EXEC: zeek -b -Cr ${TRACES}/bad-backend-message-1.pcap ${PACKAGE} %INPUT
# @TEST-EXEC: zeek-cut -m ts uid id.orig_h id.orig_p id.resp_h id.resp_p service  < conn.log > conn.cut
#
# @TEST-EXEC: btest-diff conn.cut
# @TEST-EXEC: test ! -f reporter.log

@load base/protocols/conn
