# @TEST-DOC: Test Zeek parsing a trace file through the PostgreSQL analyzer.
#
# @TEST-EXEC: zeek -b -Cr ${TRACES}/psql-insert-fail-drop-fail.pcap ${PACKAGE} %INPUT >output
# @TEST-EXEC: zeek-cut -m < postgresql.log > postgresql.cut
#
# @TEST-EXEC: btest-diff postgresql.cut
