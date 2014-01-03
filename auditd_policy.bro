# auditd_policy.bro
# Scott Campbell
#
# 
# Every login and related activities is associated with login session id (ses)
#   and the {pid} pair.  This collection of stuff identifies the key which
#   is actually the table used to hold multi action/record data.
#
# The ses id is monotomicly incrementing, so the odds of collision between many
#   systems is reasonably high.  Because of this the node identity is appended to 
#   ses and pid values since the internal systems should remove duplicate values.
#
@load auditd_policy/util
@load auditd_policy/auditd_net

module AUDITD_POLICY;

export {

	redef enum Notice::Type += {
		AUDITD_IDTransform,
		AUDITD_SocketOpen,
		AUDITD_ExecPathcheck,
		};

	# tag for file loaded
	const AUDITD_POLICY_LOAD = T;

	# List of identities which are consitered ok to be seen translating
	#  between one another.
	#
	global whitelist_to_id: set[string] &redef;
	global whitelist_from_id: set[string] &redef;

	### --- ###
	# This is the set of system calls that define the creation of a 
	#  network listening socket	
	global net_listen_syscalls: set[string] &redef;
	# Duration that the socket data is allowed to live in the syscall/id
	#  table.
	const syscall_flush_interval: interval = 30 sec &redef;
	# short term mapping designed to live for
	#   action duration
	global socket_lookup: table[string] of socket_data &write_expire=syscall_flush_interval;

	# this tracks rolling execution history of user and is
	#   keyed on the longer lived identity Info$i$auid value.
	type history_rec: record {
		exec_hist:	table[count] of string;
		exec_count:	count &default = 0;
		};

	global execution_history_length: count = 5 &redef;
	global execution_history: table[string] of history_rec;

	## -- ##

	global auditd_policy_dispatcher: event(i: Info);
	global s: event(s: string);

	## Execution configuration ##

	# blacklist of directories which 
	global exec_blacklist = /^\/dev/ | /^\/var\/run/ &redef;
	global exec_blacklist_test = T &redef;
	
	# identiy related configs
	global identity_drift_test = T &redef;


	} # end export
		
### ----- # ----- ###
#      Local Constants
### ----- # ----- ###
global NULL_ID: string = "-1";

### ----- # ----- ###
#      Config
### ----- # ----- ###
redef net_listen_syscalls += { "bind", "accept", };

### ----- # ----- ###
#      Functions
### ----- # ----- ###

function get_identity_id(ses: int, node: string) : string
{
	# This function returns the identity-id (huh?!?)
	local ret = "NULL";
	
	if (! ((ses == INT_CONV_ERROR) || (node == STRING_CONV_ERROR)) )
		ret = fmt("%s%s", ses, node);

	return ret;
}


# This function compares two id values and in the event that
#  the post value are not whitelisted you get {0,1,2} 
#  depending on results.
function identity_atomic(old_id: string, new_id: string): bool
	{
	local ret_val = F;

	if ( (new_id != old_id) && (old_id != NULL_ID) ) {
		# there has been a non-trivial change in identity
		if ( (new_id !in whitelist_to_id) && (old_id !in whitelist_from_id) )
			ret_val = F;
		else
			ret_val = T;
		}

	return ret_val;
	}

# Look for a unexpected transformation of the identity subvalues
#  returning a vector of changes.
#
# NOTE: the record provided by identityState[] has *not* yet been synced 
#  to the current living record, so changes will be reflected in the diff
#  between the live record and the historical.
#
# NOTE2: Since it is not possible to know what is the cause of the transition,
#  this function only identifies the existance of a non-whitelisted uid.
#
function process_identity(inf: Info) : count
	{
	# return value is a map of 
	local ret_val = 0;

	# Tests current set of provided identities against the current archived set
	#  - pick it up.
	local id_index =  get_identity_id(inf$i$ses, inf$i$node);
	local old_id =  identityState[id_index];

	# In this case the record is either new or corrupt.
	if ( inf$i$idv[v_uid] == NULL_ID )
		return ret_val;

	# Now loop through the various identities, looking for changes
	for ( i in old_id$idv ) {

		# Compare older (looked up) value, against the newer
		#  one taken from the presented Info object
		if ( old_id$idv[i] != inf$i$idv[i] ) {
			# A change has been detected ...
			# Check the identities against whitelist candidates for
			#  user and group transitions and report back the change.
			# At this point we need to evaluate just *what* it was that 
			#  forced the tansition, so just report back change.
			if ( (inf$i$idv[i] in whitelist_to_id) || (old_id$idv[i] in whitelist_from_id) ) {

				# do nothing
				}
			else
				++ret_val;
			
			}
		} # end for loop

	return ret_val;
	} # end function

## Begin network related functions ##

function syscall_socket(inf: Info) : count
	{
	# Function test for socket exist.
	# If none, create; if exist, test dt 
	local ret_val = 0;
	local t_socket_data: socket_data;

	local index = fmt("%s%s", inf$ses, inf$node);

	# If the policy is set to only look at TCP connections
	#  return with 0
	#
	#if ( AUDITD_NET::filter_tcp_only && ( (inf$a0 != AF_INET) || (inf$a1 != SOCK_STREAM)))
	#	return ret_val;

	t_socket_data$domain = to_count(inf$a0);
	t_socket_data$s_type = to_count(inf$a1);
	t_socket_data$ts = inf$ts;
	t_socket_data$state = 1;
	
	if ( index !in socket_lookup ) {

		ret_val = 1;
		socket_lookup[index] = t_socket_data;

		}
	else {
		# skip for now
		ret_val = 2;
		}

	return ret_val;
	} # syscall_socket end


function syscall_bind(inf: Info) : count
	{
	# bind(int socket, const struct sockaddr *address, socklen_t address_len);
	# From the saddr component, we can get the source IP and port ...
	local ret_val = 0;
	local t_socket_data: socket_data;

	local index = fmt("%s%s", inf$ses, inf$node);

	if ( index in socket_lookup )
		t_socket_data = socket_lookup[index];

	t_socket_data$o_addr_info = inf$s_host;
	t_socket_data$o_port_info = inf$s_serv;
	t_socket_data$ts = inf$ts;
	t_socket_data$state = 3;
		
	socket_lookup[index] = t_socket_data;

	return ret_val;
	} # syscall_bind end


function syscall_connect(inf: Info) : count
	{
	# connect(int socket, const struct sockaddr *address, socklen_t address_len);
	local ret_val = 0;

	local t_socket_data: socket_data;

	local index = fmt("%s%s", inf$ses, inf$node);

	if ( index in socket_lookup )
		t_socket_data = socket_lookup[index];

	t_socket_data$r_addr_info = inf$s_host;
	t_socket_data$r_port_info = inf$s_serv;
	t_socket_data$ts = inf$ts;
	t_socket_data$state = 3;
		
	socket_lookup[index] = t_socket_data;

	return ret_val;
	} # syscall_connect end


function syscall_listen(inf: Info) : count
	{
	# listen(int socket, int backlog);
	local ret_val = 0;

	local t_socket_data: socket_data;

	local index = fmt("%s%s", inf$ses, inf$node);

	if ( index in socket_lookup )
		t_socket_data = socket_lookup[index];

	t_socket_data$o_addr_info = inf$s_host;
	t_socket_data$o_port_info = inf$s_serv;
	t_socket_data$ts = inf$ts;
	t_socket_data$state = 3;
		
	socket_lookup[index] = t_socket_data;

	return ret_val;
	} # syscall_listen end


function network_register_listener(i: Info) : count
	{
	# This captures data from the system calls bind() and
	#  accept() and checks to see if the system in question already
	#  has an open network listener
	#
	# Here use the ip_id_map to store data: use {ses}{node} as the
	#   table index.  Results for the listener will be handed over to the 
	#   systems object for further analysis.

	local ret_val = 0;
	local t_socket_data: socket_data;
	local cid: conn_id;

	local index = fmt("%s%s", i$ses, i$node);

	if ( index in socket_lookup )
		t_socket_data = socket_lookup[index];
	else
		return ret_val;

	# sanity check the data
	if ( t_socket_data$domain != AF_INET )
		return ret_val;

	if ( (t_socket_data$o_addr_info == "NULL") || (t_socket_data$o_port_info == "NULL"))
		return ret_val;

	ret_val = 1;
	# now if there is sufficient information in the socket_data structure we
	#  have enjoyed it long enough and should pass it off to the server object
	#  holding all the info on this system
	#
	# Build a conn_id and hand it off w/ identity info
	local ptype = "NULL";

	if ( t_socket_data$s_type == SOCK_STREAM )
		ptype = "tcp";
	else
		# assume this for now ...
		ptype = "udp";

	# test and create the port sets
	# orig ports
	cid$orig_p = s_port( fmt("%s/%s", t_socket_data$o_port_info, ptype));

	# resp ports
	if ( t_socket_data$r_port_info != "NULL" )
		cid$resp_p = s_port( fmt("%s/%s", t_socket_data$r_port_info, ptype));
	else
		cid$resp_p = s_port( fmt("0/%s", ptype));

	# IP Addresses
	# orig host
	cid$orig_h = s_addr(t_socket_data$r_addr_info);

	# resp host
	if ( t_socket_data$r_addr_info != "NULL" )
		cid$resp_h = s_addr(t_socket_data$r_addr_info);
	else
		cid$resp_h = s_addr("0.0.0.0");

	# having built a prototype connection id, register it with the 
	#  new socket systems policy
	#SYSTEMS_DATA::new_socket(i,cid);

	return ret_val;
	}


function network_register_conn(i: Info) : count
	{
	# This attempts to register outbound network connection data with a central correlator
	#  in order to link the {user:conn} with the "real" netwok connection as seen by the 
	#  external network facing bro.
	#
	local ret_val = 0;
	local t_socket_data: socket_data;
	local cid: conn_id;

	# For the time being we focus on succesful connect() syscalls - in
	#  this event the "error" code will be 0.
	if ( to_int(i$ext) != 0 )
		return ret_val;	

	local index = fmt("%s%s", i$ses, i$node);

	if ( index in socket_lookup )
		t_socket_data = socket_lookup[index];
	else
		return ret_val;

	# sanity check the data
	if ( t_socket_data$domain != AF_INET )
		return ret_val;

	if ( (t_socket_data$r_addr_info == "NULL") || (t_socket_data$r_port_info == "NULL"))
		return ret_val;

	ret_val = 1;

	# Build a conn_id and hand it off w/ identity info
	local ptype = "NULL";

	if ( t_socket_data$s_type == SOCK_STREAM )
		ptype = "tcp";
	else
		# assume this for now ...
		ptype = "udp";

	# test and create the port sets
	# resp ports
	cid$resp_p = s_port( fmt("%s/%s", t_socket_data$r_port_info, ptype));

	# orig ports
	if ( t_socket_data$o_port_info != "NULL" )
		cid$orig_p = s_port( fmt("%s/%s", t_socket_data$o_port_info, ptype));
	else
		cid$orig_p = s_port( fmt("0/%s", ptype));

	# IP Addresses
	# resp host
	cid$resp_h = s_addr(t_socket_data$r_addr_info);

	# orig host
	if ( t_socket_data$r_addr_info != "NULL" )
		cid$resp_h = s_addr(t_socket_data$r_addr_info);
	else
		cid$resp_h = s_addr("0.0.0.0");

	# We have a conn_id more or less whicih gives us a 'what'
	#  hand it off with the 'who' information to the connection
	#  correlator.
	# Still working on details ...
	AUDITD_NET::audit_conn_register(cid, i);

	return 0;
	}

function exec_pathcheck(exec_path: string) : count
	{
	# given a list of directory prefixes, check to see if the path
	#  sits in any of them
	# note that the path provided is should be consitered 'absolute'.

	local ret_val = 0;

	if ( exec_blacklist in exec_path ) {
		
		#print fmt("EXECBLACKLIST: %s", exec_path);
		NOTICE([$note=AUDITD_ExecPathcheck,
			$msg=fmt("Exec path on blacklist: %s", exec_path)]);

		ret_val = 1;
		}

	return ret_val;
	}

function exec_history(inf: Info) : count
	{
	# Mostly this is a library function to track execution
	#  to look into in the event of a permission transition
	#
	local ret_val = 0;
	local id = inf$i$idv[v_auid];
	local t_hrec: history_rec;

	if ( id !in execution_history ) {
		# new identity
		t_hrec$exec_count = 1;
		t_hrec$exec_hist[1] = inf$exe;
		}
	else {
		# calculate new position in table
		local n = (t_hrec$exec_count % execution_history_length) + 1;
		
		++t_hrec$exec_count;
		t_hrec$exec_hist[n] = inf$exe;
		}

	return ret_val;
	}


function exec_wrapper(inf: Info) : count
	{
	# There are many things to be done with the execution chain.  This is the wrapper
	#   for that set of things to do.
	# Where is (it) being executed
	# Permissions chain/changes
	# Exec history ( n=5?)
	local ret_val = 0;

	if ( exec_blacklist_test )
		exec_pathcheck(inf$exe);

	exec_history(inf);

	# track id drift.  start by just detecting it, then begin building
	#  whitelists and implement
	if ( identity_drift_test ) {
		if (process_identity(inf) != 0 ) {
			# something changed ..

			}
			
		}

	return ret_val;
	}

### ----- # ----- ###
#      Events
### ----- # ----- ###

# This event currently in holding - might not need it

event syscall_flush(index: string)
	{
	local t_socket_data: socket_data;
	local td = time_to_double(network_time());

	if ( index in socket_lookup ) {
		# look up the current socket_data struct and if it is 
		#  not been touched, remove it.
		t_socket_data = socket_lookup[index];

		if ( (td - time_to_double(t_socket_data$ts)) > 20 )
			delete socket_lookup[index];
		else
			# the timestamp on the socket_data struct has been moved since creation
			#  time.  schedule a re-check 
			schedule syscall_flush_interval { syscall_flush(index) };
		}

	return;
	}

event auditd_policy_dispatcher(inf: Info)
	{
	# This makes routing decisions for policy based on Info content.  It is
	#  a bit of a kluge, but will have to do for now.

	# Initial filtering based on action and key values
	#  ex: {PLACE_OBJ, PATH} .

	# Key is from audit.rules
	#
	local action = inf$action;
	local key    = inf$key;
	local syscall = inf$syscall;	

        switch ( action ) {
        case "EXECVE":
                break;
        case "GENERIC":
                break;
        case "PLACE":
                break;
        case "SADDR":
		# the SADDR data will be passed over in the network system
		#  call information.
		#
                break;
        case "SYSCALL":
		switch( syscall ) {
			### ----- ## ----- ####
			# from syscalls: bind, connect, accept, accept4, listen, socketpair, socket
			# key: SYS_NET
			case "connect":		# initiate a connection on a socket (C/S)
				syscall_connect(inf);
				network_register_conn(inf);
				break;
			case "bind": 		# bind a name/address to a socket (S)
				syscall_bind(inf);
				break;
			case "listen":		# listen for connections on a socket (S)
				syscall_listen(inf);
				network_register_listener(inf);
				break;
			case "socket":		# create an endpoint for communication (C/S)
				syscall_socket(inf);
				break;
			case "socketpair":	# create a pair of connected sockets (C/S)
				syscall_socket(inf);
				break;
			case "accept":		# accept a connection on a socket (S)
				break;
			case "accept4":		#  accept a connection on a socket (S)
				break;
			### ----- ## ----- ####
			# 
			case "execve":
				print "calling exec_wrapper";
				exec_wrapper(inf);
				break;
			}
                break;
        case "USER":
                break;
        }

	

	} # event end

# do a test for "where" something is executed like /dev/shm ...


