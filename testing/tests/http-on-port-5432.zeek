# @TEST-DOC: Test rejecting wrong protocol.
#
# @TEST-EXEC: zeek -b -Cr ${TRACES}/http-on-port-5432.pcap ${PACKAGE} %INPUT >output
# @TEST-EXEC: zeek-cut -m ts uid id.orig_h id.orig_p id.resp_h id.resp_p history service  < conn.log > conn.cut
# @TEST-EXEC: zeek-cut -m < analyzer.log > analyzer.cut
#
# @TEST-EXEC: btest-diff conn.cut
# @TEST-EXEC: TEST_DIFF_CANONIFIER="sed -r 's,(.*) \(/[^\)]+\),\1 (...),'" btest-diff analyzer.cut
# @TEST-EXEC: test ! -f postgresql.log

@load base/protocols/conn
