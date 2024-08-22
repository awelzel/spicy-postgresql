module PostgreSQL;

export {
	## Log stream identifier.
	redef enum Log::ID += { LOG };

	option log_not_implemented = F;

	type Version: record {
		major: count;
		minor: count;
	} &log;

	type RowDataField: record {
		col_len: count;
		data: string;
	} &log;
	
	# For Bind in extend query 
	type ParamValue: record {
    	length: count;
    	data: string;
	} &log;

	# For error identifier
	type IdentifiedField: record {
		code: string;
    	value: string;
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
		backend_arg: string &optional &log;
		# The number of rows returned or affectd.
		rows: count &optional &log;
		# number of colunm
		column_num: count &optional &log;
	};

	type State: record {
		version: Version &optional &log;
		user: string &optional;
		database: string &optional;
		application_name: string &optional;
		# How many data_rows have been received.
		rows: count &default=0;
		column_num: count &default=0;
	};

	## Default hook into PostgreSQL logging.
	global log_postgresql: event(rec: Info);
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

	if ( ! c?$postgresql_state )
		c$postgresql_state = State();
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

	if (c$postgresql_state?$column_num)
		c$postgresql$column_num = c$postgresql_state$column_num;	

	Log::write(PostgreSQL::LOG, c$postgresql);
	delete c$postgresql;
}

event PostgreSQL::ssl_request(c: connection, is_orig: bool) {
	hook set_session(c);

	c$postgresql$frontend = "ssl_request";
	emit_log(c);
}

# b: The S or N byte from the server
event PostgreSQL::ssl_reply(c: connection, is_orig: bool, b: string) {
	hook set_session(c);

	# if ( c$postgresql$message != "ssl_request" ):
	#	weird();

	# if ( b !in /S|N/ )
	#	weird()
	c$postgresql$frontend = "Waiting response for SSLRequest ";
	c$postgresql$backend = b;
	emit_log(c);
}

event PostgreSQL::startup_message(
	c: connection,
	is_orig:
	bool, version: Version,
	parameters: table[string] of string
) {
	hook set_session(c);
	
	c$postgresql_state$version = version;
	if ( "user" in parameters )
		c$postgresql_state$user = parameters["user"];

	if ( "database" in parameters )
		c$postgresql_state$database = parameters["database"];

	if ( "application_name" in parameters )
		c$postgresql_state$application_name = parameters["application_name"];

	c$postgresql$frontend = "startup";

	# Not sure this is great, but unclear where to put them otherwise.
	c$postgresql$frontend_arg = to_json(parameters);
	emit_log(c);
}

event PostgreSQL::parameter_status(c: connection, is_orig: bool, parameter: table[string] of string)
	{
		hook set_session(c);
		c$postgresql$backend = "Parameter status";
		c$postgresql$backend_arg = to_json(parameter);

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

event PostgreSQL::row_description(c: connection, is_orig: bool, column_num: count, fields: table[string] of count)
	{	
		hook set_session(c);
		c$postgresql$backend = "Row description";
		c$postgresql$backend_arg = to_json(fields);
		c$postgresql_state$column_num = column_num;
		emit_log(c);
	}	

event PostgreSQL::data_row(c: connection, is_orig: bool, fields: vector of RowDataField)
	{
		hook set_session(c);
		++c$postgresql_state$rows;
		c$postgresql$backend = "Data row";
		c$postgresql$backend_arg = to_json(fields);
		emit_log(c);
	}

event PostgreSQL::ready_for_query(c: connection, is_orig: bool, transaction_status: string) 
	{
		hook set_session(c);
		if ( ! c?$postgresql )
			return;
		# TODO: This filters out prepared statement queries.

		# FIXME:The value of the status seems not to be maintained. 
		# FIXME:When it's "ready for query," the frontend status is always empty.
		c$postgresql$rows = c$postgresql_state$rows;
		c$postgresql_state$rows = 0;
		c$postgresql_state$column_num = 0;
		c$postgresql$backend = "Ready for query";
		emit_log(c);
	}

event PostgreSQL::parse(c: connection, is_orig: bool, query: string, parameter_num: count)
	{
		hook set_session(c);
		if (!c?$postgresql)
			return;
		c$postgresql$frontend = "Parse";
		c$postgresql$frontend_arg = query;
		emit_log(c);	
	}	

event PostgreSQL::bind(c: connection, is_orig: bool, param_values: vector of ParamValue)
	{
		hook set_session(c);
		if (!c?$postgresql)
			return;
		c$postgresql$frontend = "Bind";
		c$postgresql$frontend_arg = to_json(param_values);
		emit_log(c);
	}

event PostgreSQL::execute(c: connection, is_orig: bool, portal: string, return_num: count)
	{
		hook set_session(c);

		if(!c?$postgresql)
			return;		
		c$postgresql$frontend = "Execute";
		c$postgresql$frontend_arg = portal;
		emit_log(c);
	}	

event PostgreSQL::error(c: connection, is_orig: bool, fields: table[string] of string)
	{
		hook set_session(c);
		
		if(!c?$postgresql)
			return;
		c$postgresql$backend = "Error";
		c$postgresql$backend_arg = to_json(fields);
		emit_log(c);	
	}

event PostgreSQL::backend_key_data(c: connection, is_orig: bool, key_data: table[count] of count)
	{
		hook set_session(c);

		c$postgresql$backend = "BackendKeyData";
		c$postgresql$backend_arg = to_json(key_data);
		emit_log(c);
	}	

event PostgreSQL::not_implemented(c: connection, is_orig: bool, typ: string, chunk: string) {
	if ( log_not_implemented )
		Reporter::warning(fmt("PostgreSQL: not_implemented %s: %s (%s is_orig=%s)", typ, to_json(chunk), c$id, is_orig));
}

# TODO: Switch to connection finalizers
event connection_state_remove(c: connection) &priority=-5 {
	emit_log(c);
}
