module PostgreSQL;

export {
	## Log stream identifier.
	redef enum Log::ID += { LOG };

	## Record type containing the column fields of the PostgreSQL log.
	type Info: record {
		## Timestamp for when the activity happened.
		ts: time &log;
		## Unique ID for the connection.
		uid: string &log;
		## The connection's 4-tuple of endpoint addresses/ports.
		id: conn_id &log;

		# TODO: Adapt subsequent fields as needed.

		## Request-side payload.
		request: string &optional &log;
		## Response-side payload.
		reply: string &optional &log;
	};

	## Default hook into PostgreSQL logging.
	global log_postgresql: event(rec: Info);
}

redef record connection += {
	postgresql: Info &optional;
};

const ports = {
	# TODO: Replace with actual port(s).
	12345/tcp # adapt port number in postgresql.evt accordingly
};

redef likely_server_ports += { ports };

event zeek_init() &priority=5
	{
	Log::create_stream(PostgreSQL::LOG, [$columns=Info, $ev=log_postgresql, $path="postgresql"]);
	}

# Initialize logging state.
hook set_session(c: connection)
	{
	if ( c?$postgresql )
		return;

	c$postgresql = Info($ts=network_time(), $uid=c$uid, $id=c$id);
	}

function emit_log(c: connection)
	{
	if ( ! c?$postgresql )
		return;

	Log::write(PostgreSQL::LOG, c$postgresql);
	delete c$postgresql;
	}

# Example event defined in postgresql.evt.
event PostgreSQL::message(c: connection, is_orig: bool, payload: string)
	{
	hook set_session(c);

	local info = c$postgresql;
	if ( is_orig )
		info$request = payload;
	else
		info$reply = payload;
	}

event connection_state_remove(c: connection) &priority=-5
	{
	# TODO: For UDP protocols, you may want to do this after every request
	# and/or reply.
	emit_log(c);
	}
