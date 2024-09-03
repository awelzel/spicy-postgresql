module PostgreSQL;

export {
	## Log stream identifier.
	redef enum Log::ID += { LOG };

	option log_not_implemented = F;

	type Version: record {
		major: count;
		minor: count;
	} &log;

	## Record type containing the column fields of the PostgreSQL log.
	type Info: record {
		## Timestamp for when the activity happened.
		ts: time &log;
		## Unique ID for the connection.
		uid: string &log;
		## The connection's 4-tuple of endpoint addresses/ports.
		id: conn_id &log;

		version: Version &optional &log;
		user: string &optional &log;
		database: string &optional &log;
		application_name: string &optional &log;

		frontend: string &optional &log;
		frontend_arg: string &optional &log;
		backend: string &optional &log;

		# The number of rows returned or affectd.
		rows: count &optional &log;
	};

	type State: record {
		version: Version &optional &log;
		user: string &optional;
		database: string &optional;
		application_name: string &optional;
		# How many data_rows have been received.
		rows: count &default=0;
	};

	## Default hook into PostgreSQL logging.
	global log_postgresql: event(rec: Info);

	global finalize_postgresql: Conn::RemovalHook;
}

redef record connection += {
	postgresql: Info &optional;
	postgresql_state: State &optional;
};

const ports = {
	5432/tcp
};

redef likely_server_ports += { ports };

event zeek_init() &priority=5 {
	Log::create_stream(PostgreSQL::LOG, [$columns=Info, $ev=log_postgresql, $path="postgresql"]);
}

hook set_session(c: connection) {
	if ( ! c?$postgresql )
		c$postgresql = Info($ts=network_time(), $uid=c$uid, $id=c$id);

	if ( ! c?$postgresql_state ) {
		c$postgresql_state = State();
		Conn::register_removal_hook(c, finalize_postgresql);
	}
}

function emit_log(c: connection) {
	if ( ! c?$postgresql )
		return;

	if ( c$postgresql_state?$version )
		c$postgresql$version = c$postgresql_state$version;

	if ( c$postgresql_state?$user )
		c$postgresql$user = c$postgresql_state$user;

	if ( c$postgresql_state?$database )
		c$postgresql$database = c$postgresql_state$database;

	if ( c$postgresql_state?$application_name )
		c$postgresql$application_name = c$postgresql_state$application_name;

	Log::write(PostgreSQL::LOG, c$postgresql);
	delete c$postgresql;
}

event PostgreSQL::ssl_request(c: connection, is_orig: bool) {
	hook set_session(c);

	c$postgresql$frontend = "ssl_request";
}

# b: The S or N byte from the server
event PostgreSQL::ssl_reply(c: connection, is_orig: bool, b: string) {
	hook set_session(c);

	# if ( c$postgresql$message != "ssl_request" ):
	#	weird();

	# if ( b !in /S|N/ )
	#	weird()

	c$postgresql$backend = b;
	emit_log(c);
}

event PostgreSQL::startup_parameter(c: connection, name: string, value: string) {
	hook set_session(c);

	if ( name == "user" ) {
		c$postgresql_state$user = value;
	} else if ( name == "database" ) {
		c$postgresql_state$database = value;
	} else if ( name== "application_name" ) {
		c$postgresql_state$application_name = value;
	}
}

event PostgreSQL::startup_message(c: connection, version: Version) {
	hook set_session(c);

	c$postgresql_state$version = version;
	c$postgresql$frontend = "startup";
	emit_log(c);
}

event PostgreSQL::terminate(c: connection, is_orig: bool) {
	hook set_session(c);
	c$postgresql$frontend = "terminate";
	emit_log(c);
}

event PostgreSQL::simple_query(c: connection, is_orig: bool, query: string) {
	hook set_session(c);
	c$postgresql$frontend = "simple_query";
	c$postgresql$frontend_arg = query;
	c$postgresql_state$rows = 0;
}

event PostgreSQL::data_row(c: connection, is_orig: bool) {
	hook set_session(c);
	++c$postgresql_state$rows;
}

event PostgreSQL::ready_for_query(c: connection, is_orig: bool, transaction_status: string) {
	# Log a query (if there was one).
	if ( ! c?$postgresql )
		return;

	# TODO: This filters out prepared statement queries.
	if ( ! c$postgresql?$frontend || c$postgresql$frontend != "simple_query" )
		return;

	c$postgresql$rows = c$postgresql_state$rows;
	emit_log(c);
}

event PostgreSQL::not_implemented(c: connection, is_orig: bool, typ: string, chunk: string) {
	if ( log_not_implemented )
		Reporter::warning(fmt("PostgreSQL: not_implemented %s: %s (%s is_orig=%s)", typ, to_json(chunk), c$id, is_orig));
}

hook finalize_postgresql(c: connection) &priority=-5 {
	emit_log(c);
}
