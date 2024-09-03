# @TEST-DOC: Trace with CREATE TABLE, INSERT, SELECT DELETE and DROP.
#
# @TEST-EXEC: zeek -Cr ${TRACES}/psql-create-insert-select-delete-drop.pcap ${PACKAGE} %INPUT >output
#
# @TEST-EXEC: zeek-cut -m ts uid id.orig_h id.orig_p id.resp_h id.resp_p service  < conn.log > conn.cut
# @TEST-EXEC: zeek-cut -m frontend frontend_arg backend rows < postgresql.log > postgresql.cut
#
# @TEST-EXEC: btest-diff conn.cut
# @TEST-EXEC: btest-diff postgresql.cut
