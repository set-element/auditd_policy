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
@load auditd_policy/auditd_core

module AUDITD_POLICY;
#module AUDITD_CORE;

export {
	redef enum Log::ID += { LOGCONN };
	redef enum Log::ID += { LOGLIST };

	redef enum Notice::Type += {
		AUDITD_IDTransform,
		AUDITD_IDTransformSkip,
		AUDITD_SocketOpen,
		AUDITD_ExecPathcheck,
		AUDITD_Longtime,
		AUDITD_FileMetadata,
		AUDITD_POLICY_UserLocation,
		AUDITD_POLICY_NetError,
		AUDITD_POLICY_HostScan,
		AUDITD_POLICY_PortScan,
		};

	# tag for file loaded
	const AUDITD_POLICY_LOAD = T;

	# socket_data is struct to maintain state across the (con/de)struction
	#   of network related system calls.
        type socket_data: record {
                domain: string &default="NULL";         # UNIX/INET
                s_type: string &default="NULL";         # STREAM/DGRAM
                s_prot: string &default="NULL";         # UNSET/IP/ICMP/TCP/UDP/IPV6
                ts: time &default=double_to_time(0.000);# start time
                o_addr_info: string &default="NULL";    #
                o_port_info: string &default="NULL";    #
                r_addr_info: string &default="NULL";    #
                r_port_info: string &default="NULL";    #
                state: count &default=0;                # see below:
                };

        #     Note on socket state:
        #          0 = new
        #          1 = init
        #          2 = conn         -> make connection
        #          3 = bind|listen  -> create listener
        #          4 = accept       -> listener connect
        #    

	# connection_log is a logging construct that holds some of the socket_data
	#  info as well as type fixed data like addr/port and identity info
	type connection_log: record {
		ts: time &log;
		cid: conn_id &log;
		log_id: string &default="NULL" &log;
		protocol: string &default="NULL" &log;
		state: string &default="NULL" &log;
		ses: int &default=0 &log;
		node: string &default="NULL" &log;
		uid: string &default="NULL" &log;
		gid: string &default="NULL" &log;
		euid: string &default="NULL" &log;
		egid: string &default="NULL" &log;
		};


	# List of identities which are consitered ok to be seen translating
	#  between one another.
	#
	global whitelist_to_id: set[string] = { "NULL", "-1", } &redef;
	global whitelist_from_id: set[string] = { "NULL", "-1" } &redef;

	# --- #
	# This is the set of system calls that define the creation of a 
	#  network listening socket	
	global net_listen_syscalls: set[string] &redef;
	# Duration that the socket data is allowed to live in the syscall/id
	#  table.
	const syscall_flush_interval: interval = 90 sec &redef;
	# short term mapping designed to live for
	#   action duration
	global socket_lookup: table[string] of socket_data &write_expire=syscall_flush_interval;

	# this tracks rolling execution history of user and is
	#   keyed on the longer lived identity AUDITD_CORE::Info$i$auid value.
	type history_rec: record {
		exec_hist:	vector of string;
		exec_count:	count &default = 0;
		};

	global execution_history_length: count = 5 &redef;
	global execution_history: table[string] of history_rec;

	# -- #
	global clear_exec_hist: event(id: string);

	global auditd_policy_dispatcher: function(i: AUDITD_CORE::Info);
	#global s: event(s: string);

	global auditd_execve: function(i: AUDITD_CORE::Info);
	global auditd_generic: function(i: AUDITD_CORE::Info);
	global auditd_place: function(i: AUDITD_CORE::Info);
	global auditd_saddr: function(i: AUDITD_CORE::Info);
	global auditd_syscall: function(i: AUDITD_CORE::Info);
	global auditd_user: function(i: AUDITD_CORE::Info);

	global network_register_listener: function(inf: AUDITD_CORE::Info): count;

	global identity_time_test: event(ses: int, node: string, n: int, exe: string, did: string);
	# # Execution configuration #
	# blacklist of suspicous execution bases
	global exec_blacklist = /^\/dev/ | /^\/var\/run/ &redef;
	global exec_blacklist_test = T &redef;
	
	# identiy related configs
	global identity_drift_test = T &redef;
	global id_test_delay: interval = 5 sec &redef;
	
	# Table of allowed identity transitions
	global identity_transition_wl: table[string] of string &redef;
	global ExeWhitelist: set[string] &redef;
	global UpList = set("root") &redef;


	# # Network metadata
	#  here metadata can be both unix socket or inet
	# Also for tracking scanning info - the lists here
	#  are only for failed conns
	#
	type connMetaData: record {
		bind_err_count: count &default=0;
		bind_err_set: set[string];
		socket_err_count: count &default=0;
		socket_err_set: set[string];
		connect_err_count: count &default=0;
		connect_err_set: set[string];
		listen_err_count: count &default=0;
		listen_err_set: set[string];
		#
		host_scan: set[string];
		port_scan: set[string];
		};

	global connMetaDataTable: table[string] of connMetaData;

	global SYS_NET_BIND_THRESHOLD =    10 &redef;
	global SYS_NET_SOCKET_THRESHOLD =  50 &redef;
	global SYS_NET_CONNECT_THRESHOLD = 50 &redef;
	global SYS_NET_LISTEN_THRESHOLD = 5 &redef;
	global SYS_NET_HOSTSCAN_THRESHOLD = 10 &redef;
	global SYS_NET_PORTSCAN_THRESHOLD = 10 &redef;

	# File system metadata
	# Table, indexed by identity, which tracks aggrigate filesystem activity
	type fileMetaData: record {
		open_error: count &default=0;
		open_error_set: string &default="";
		create_error: count &default=0;
		create_error_set: string &default="";
		mod_error: count &default=0;
		mod_error_set: string &default="";
		delete_error: count &default=0;
		delete_error_set: string &default="";
		};

	global fileMetaDataTable: table[string] of fileMetaData;

	global SYS_FILE_OPEN_THRESHOLD = 5 &redef;
	global SYS_FILE_CREATE_THRESHOLD = 5 &redef;
	global SYS_FILE_MOD_THRESHOLD = 5 &redef;
	global SYS_FILE_DELETE_THRESHOLD = 5 &redef;
	
	# should we have a blacklist of where users should not be poking around - ie cwd
	global run_location_check = T &redef;
	global location_blacklist = /^\/boot.*/ &redef;


	} # end export
		
# ----- # ----- #
#      Local Constants
# ----- # ----- #
global NULL_ID: string = "-1";

# ----- # ----- #
#      Config
# ----- # ----- #
redef net_listen_syscalls += { "bind", "accept", };

# ----- # ----- #
#      Functions
# ----- # ----- #

# Fill out an empty connMetaData object
function init_cmd() : connMetaData
	{
	local t_cmd: connMetaData;

	local t_bind_err_set: set[string];
	local t_socket_err_set: set[string];
	local t_connect_err_set: set[string];
	local t_listen_err_set: set[string];

	t_cmd$bind_err_set = t_bind_err_set;
	t_cmd$socket_err_set = t_socket_err_set;
	t_cmd$connect_err_set = t_connect_err_set;
	t_cmd$listen_err_set = t_listen_err_set;

	return t_cmd;
	}

# This function compares two id values and in the event that
#  the post value are not whitelisted you get {0,1,2} 
#  depending on results.
function identity_atomic(old_id: string, new_id: string): bool
	{
	local ret_val = F;

	if ( new_id != old_id ) {
	
		# there has been a non-trivial change in identity
		if ( (new_id !in whitelist_to_id) || (old_id !in whitelist_from_id) )
			ret_val = T;
		}

	return ret_val;
	}

# Begin network related functions #

function syscall_socket(inf: AUDITD_CORE::Info) : count
	{
	# socket(int domain, int type, int protocol);
	#  a0: domain: PF_LOCAL|PF_UNIX=1  PF_INET=2  PF_INET6=10
	#  a1: type: SOCK_STREAM=1    SOCK_DATAGRAM=2   SOCK_RAW=3
	#  a2: protocol: 0=UNSET 1=ICMP 4=IP 6=TCP 17=UDP 41=IPv6
	#
	# This info will have been extracted out in the saddr part of the auditd analysis
	#
	local ret_val = 0;
	local t_socket_data: socket_data;

	# Index is composed of node, session, pid and return value.  The return
	#  value is the file descriptor which is used as a0 for the remaining 
	#  calls connect, bind and listen.
	#
	local index = fmt("%s%s%s%s", inf$node, inf$ses, inf$pid, inf$ext);

	# identify domain, bail if not an inet varient
	#    numeric values are expressed as hex

	if ( inf$a0 == "2" ) { 	
		t_socket_data$domain = "PF_INET";
		}
	else if ( to_lower(inf$a0) == "a" ) {
		t_socket_data$domain = "PF_INET6";
		}
	else {
		# unknown domain, exit
		return ret_val;
		}

	# identify type, bail if not wanted
	if ( inf$a1 == "1" ) {
		t_socket_data$s_type = "SOCK_STREAM";
		}
	else if ( inf$a1 == "2" ) {
		t_socket_data$s_type = "SOCK_DGRAM";
		}
	else if ( inf$a1 == "3" ) {
		t_socket_data$s_type = "SOCK_RAW";
		}
	else {
		# unknown type, exit
		return ret_val;
		}

	# identify protocol - note numerical values are expressed in hex
	if ( inf$a2 == "0") {
		t_socket_data$s_prot = "UNSET";
		}
	else if ( inf$a2 == "1") {
		t_socket_data$s_prot = "ICMP";
		}
	else if ( inf$a2 == "4") {
		t_socket_data$s_prot = "IP";
		}
	else if ( inf$a2 == "6") {
		t_socket_data$s_prot = "TCP";
		}
	else if ( inf$a2 == "11") {
		t_socket_data$s_prot = "UDP";
		}
	else if ( inf$a2 == "29") {
		t_socket_data$s_prot = "IPV6";
		}
	else {
		# unknown protocol, exit
		return ret_val;
		}

	t_socket_data$ts = inf$ts;
	t_socket_data$state = 1; # init
	
	ret_val = 1;
	socket_lookup[index] = t_socket_data;

	# track error conditions for identity
	if ( inf$key == "SYS_NET_ERR" ) {
	
		local cmd: connMetaData;
		local cmdIndex = fmt("%s%s", inf$node, inf$i$idv[AUDITD_CORE::v_auid]);

		if ( cmdIndex in connMetaDataTable )
			cmd = connMetaDataTable[cmdIndex];
		else
			cmd = init_cmd();

		local t_index = fmt("%s|%s", t_socket_data$domain, t_socket_data$s_type);

		if ( t_index !in cmd$socket_err_set ) {
			
			add cmd$socket_err_set[t_index];

			if ( ++cmd$socket_err_count == SYS_NET_SOCKET_THRESHOLD ) {

				NOTICE([$note=AUDITD_POLICY_NetError,
					$msg = fmt("Socket error count [%s] [%s] for %s %s", 
						SYS_NET_SOCKET_THRESHOLD, cmd$socket_err_set, 
						inf$i$idv[AUDITD_CORE::v_uid], inf$i$idv[AUDITD_CORE::v_gid])]);
				}

			} # end of t_index test

		connMetaDataTable[cmdIndex] = cmd;
		}

	return ret_val;
	} # syscall_socket end


function syscall_bind(inf: AUDITD_CORE::Info) : count
	{
	# bind(int socket, const struct sockaddr *address, socklen_t address_len);
	# From the saddr component, we can get the source IP and port ...
	# if the socket has not been already registered, skip further processing since
	#   there will not be enough data available to make for a meaningful record
	#
	local ret_val = 0;
	local t_socket_data: socket_data;

	# track error conditions for identity
	if ( inf$key == "SYS_NET_ERR" ) {
	
		local cmd: connMetaData;
		local cmdIndex = fmt("%s%s", inf$node, inf$i$idv[AUDITD_CORE::v_auid]);

		if ( cmdIndex in connMetaDataTable )
			cmd = connMetaDataTable[cmdIndex];
                else
                        cmd = init_cmd();

                local t_index = fmt("%s|%s", t_socket_data$domain, t_socket_data$s_type);
	
		if ( t_index !in cmd$bind_err_set ) {

                        add cmd$bind_err_set[t_index];
	
			if ( ++cmd$bind_err_count == SYS_NET_BIND_THRESHOLD ) {
	
				NOTICE([$note=AUDITD_POLICY_NetError,
					$msg = fmt("Bind error count [%s] [%s] for %s %s", 
					SYS_NET_BIND_THRESHOLD, cmd$bind_err_set, inf$i$idv[AUDITD_CORE::v_uid], 
					inf$i$idv[AUDITD_CORE::v_gid])]);
				}

			} # end of t_index test

		connMetaDataTable[cmdIndex] = cmd;
		}

	# see socket function for argument details
	local index = fmt("%s%s%s%s", inf$node, inf$ses, inf$pid, inf$a0);

	if ( index in socket_lookup )
		t_socket_data = socket_lookup[index];
	else {
		return ret_val;
		}

	t_socket_data$o_addr_info = inf$s_host;
	t_socket_data$o_port_info = inf$s_serv;
	t_socket_data$ts = inf$ts;
	t_socket_data$state = 3; 	# bind|listen
	ret_val = 1;
	socket_lookup[index] = t_socket_data;

	# since the error cnodition will not allow for continuation,
	#   directly call the registrar.
	if ( inf$key == "SYS_NET_ERR" ) {
		network_register_listener(inf);
		}

	return ret_val;
	} # syscall_bind end


function syscall_connect(inf: AUDITD_CORE::Info) : count
	{
	# connect(int socket, const struct sockaddr *address, socklen_t address_len);
	local ret_val = 0;
	local t_socket_data: socket_data;

	# track error conditions for identity
	if ( inf$key == "SYS_NET_ERR" ) {

		local cmd: connMetaData;
		local cmdIndex = fmt("%s%s", inf$node, inf$i$idv[AUDITD_CORE::v_auid]);

		if ( cmdIndex in connMetaDataTable )
			cmd = connMetaDataTable[cmdIndex];
                else
                        cmd = init_cmd();

                local t_index = fmt("%s|%s", inf$s_host, inf$s_serv);

                if ( t_index !in cmd$connect_err_set ) {

                        add cmd$connect_err_set[t_index];

			if ( ++cmd$connect_err_count == SYS_NET_CONNECT_THRESHOLD ) {

				local t_cec = "";
				for ( l in cmd$connect_err_set ) {
					t_cec = fmt("%s %s", t_cec, l);
					}

				NOTICE([$note=AUDITD_POLICY_NetError,
					$msg = fmt("NetError %s {%s}  for %s %s %s", 
					inf$node, t_cec, SYS_NET_CONNECT_THRESHOLD, inf$i$idv[AUDITD_CORE::v_uid], 
					inf$i$idv[AUDITD_CORE::v_gid])]);
				}
			#
			# Now do host scan detection
			if ( inf$s_host !in cmd$host_scan ) {

				add cmd$host_scan[inf$s_host];
			
				if ( |cmd$host_scan| == SYS_NET_HOSTSCAN_THRESHOLD ) {

					local t_chs = "";
					for ( l2 in cmd$host_scan ) {
						t_chs = fmt("%s %s", t_chs, l2);
						}

					NOTICE([$note=AUDITD_POLICY_HostScan,
						$msg = fmt("Host scan %s scan {%s} %s hosts for %s %s", 
						inf$node, t_chs, SYS_NET_HOSTSCAN_THRESHOLD, 
						inf$i$idv[AUDITD_CORE::v_uid], inf$i$idv[AUDITD_CORE::v_gid])]);

					} # end SYS_NET_HOSTSCAN_THRESHOLD

				}

			#
			# Now do port scan detection
			if ( inf$s_serv !in cmd$port_scan ) {

				add cmd$port_scan[inf$s_serv];
			
				if ( |cmd$port_scan| == SYS_NET_PORTSCAN_THRESHOLD ) {

					local t_cps = "";
					for ( l3 in cmd$port_scan ) {
						t_cps = fmt("%s %s", t_cps, l3);
						}

					NOTICE([$note=AUDITD_POLICY_PortScan,
						$msg = fmt("Port scan %s {%s}  %s ports for %s %s", 
						inf$node, t_cps, SYS_NET_PORTSCAN_THRESHOLD, 
						inf$i$idv[AUDITD_CORE::v_uid], inf$i$idv[AUDITD_CORE::v_gid])]);

					} # end SYS_NET_PORTSCAN_THRESHOLD

				}

			 } # end of t_index test

		connMetaDataTable[cmdIndex] = cmd;
		}

	# see socket function for argument details
	local index = fmt("%s%s%s%s", inf$node, inf$ses, inf$pid, inf$a0);

	if ( index in socket_lookup )
		t_socket_data = socket_lookup[index];
	else {
		return ret_val;
		}

	t_socket_data$r_addr_info = inf$s_host;
	t_socket_data$r_port_info = inf$s_serv;
	t_socket_data$ts = inf$ts;
	t_socket_data$state = 3; 	# bind|listen
	ret_val = 1;

	socket_lookup[index] = t_socket_data;

	return ret_val;
	} # syscall_connect end


function syscall_listen(inf: AUDITD_CORE::Info) : count
	{
	# listen(int socket, int backlog);
	local ret_val = 0;
	local t_socket_data: socket_data;

	# track error conditions for identity
	if ( inf$key == "SYS_NET_ERR" ) {

		local cmd: connMetaData;
		local cmdIndex = fmt("%s%s", inf$node, inf$i$idv[AUDITD_CORE::v_auid]);

		if ( cmdIndex in connMetaDataTable )
			cmd = connMetaDataTable[cmdIndex];
                else
                        cmd = init_cmd();

                local t_index = fmt("%s|%s", t_socket_data$domain, t_socket_data$s_type);

                if ( t_index !in cmd$listen_err_set ) {

                        add cmd$listen_err_set[t_index];

			if ( ++cmd$listen_err_count == SYS_NET_LISTEN_THRESHOLD ) {

				NOTICE([$note=AUDITD_POLICY_NetError,
					$msg = fmt("Listen error count [%s] [%s] for %s %s", 
					SYS_NET_LISTEN_THRESHOLD, cmd$listen_err_set, inf$i$idv[AUDITD_CORE::v_uid], 
					inf$i$idv[AUDITD_CORE::v_gid])]);
				}

			} # end of t_index test

		connMetaDataTable[cmdIndex] = cmd;
		}

	ret_val = 1;
	
	return ret_val;
	} # syscall_listen end


function network_register_listener(inf: AUDITD_CORE::Info) : count
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
	local conn_log: connection_log;

	local index = fmt("%s%s%s%s", inf$node, inf$ses, inf$pid, inf$a0);

	if ( index in socket_lookup )
		t_socket_data = socket_lookup[index];
	else
		return ret_val;
print fmt("t_socket_data: %s", t_socket_data);
	# sanity check the data
	if ( t_socket_data$domain == "PF_INET" || t_socket_data$domain == "PF_INET6" ) {
		ret_val = 1;
		}
	else {
		return ret_val;
		}

	ret_val = 1;

	# ptype for building a connection object, log_protocol for logging.
	local ptype = "NULL";
	local log_protocol = "NULL";
	local sp = t_socket_data$s_prot;

	if ( sp == "UNSET" ) {
		# The protocol was not explicitly set at socket gen time so 
		#   we do a little figgurin' based on the type
		#
		if ( t_socket_data$s_type == "SOCK_STREAM" ) {
			ptype = "tcp";
			log_protocol = "TCP";
			}
		else if ( t_socket_data$s_type == "SOCK_DGRAM" ) {
			ptype = "udp";
			log_protocol = "UDP";
			}
		else if ( t_socket_data$s_type == "SOCK_RAW" ) {
			ptype = "udp";
			log_protocol = "ICMP";
			}
		else {
			ptype="udp";
			log_protocol = "UNKNOWN";
			}
		}
	else if (( sp == "TCP" ) || ( sp == "UDP" )) { 

		ptype = to_lower(sp);
		log_protocol = sp;
		}
	else {
		log_protocol = sp;
		}


	# test and create the port sets
	# resp ports
	if ( ptype != "NULL" )
		conn_log$cid$resp_p = AUDITD_CORE::s_port( fmt("%s/%s", t_socket_data$r_port_info, ptype));
	else
		conn_log$cid$resp_p = AUDITD_CORE::s_port( fmt("0/%s", ptype));

	# orig ports
	if ( ptype != "NULL" )
		conn_log$cid$orig_p = AUDITD_CORE::s_port( fmt("%s/%s", t_socket_data$o_port_info, ptype));
	else
		conn_log$cid$orig_p = AUDITD_CORE::s_port( fmt("0/%s", ptype));

	# IP Addresses
	# resp host
	if ( t_socket_data$r_addr_info != "NULL" )
		conn_log$cid$resp_h = to_addr( fmt("%s", t_socket_data$r_addr_info) );
	else
		conn_log$cid$resp_h = to_addr("0.0.0.0");

	# orig host
	if ( t_socket_data$o_addr_info != "NULL" )
		conn_log$cid$orig_h = to_addr( fmt("%s", t_socket_data$o_addr_info) );
	else
		conn_log$cid$orig_h = to_addr("0.0.0.0");

	conn_log$ts =           inf$ts;
	conn_log$state = 	inf$key;
	conn_log$log_id = 	inf$i$log_id;
	conn_log$protocol = 	log_protocol;
	conn_log$ses = 		inf$i$ses;
	conn_log$node = 	inf$i$node;
	conn_log$uid = 		inf$i$idv[AUDITD_CORE::v_uid];
	conn_log$gid = 		inf$i$idv[AUDITD_CORE::v_gid];
	conn_log$euid = 	inf$i$idv[AUDITD_CORE::v_euid];
	conn_log$egid = 	inf$i$idv[AUDITD_CORE::v_egid]; 	

	Log::write(LOGLIST, conn_log);
	#delete socket_lookup[index];

	return ret_val;
	}


function network_register_conn(inf: AUDITD_CORE::Info) : count
	{
	# Log network connection data to assist in mapping user activity with 
	#  an external network facing bro.
	#
	local ret_val = 0;
	local t_socket_data: socket_data;
	local cid: conn_id;
	local conn_log: connection_log;

	# For the time being we focus on succesful connect() syscalls - in
	#  this event the "error" code will be 0.
	#if ( to_int(inf$ext) != 0 )
	#	return ret_val;	

	local index = fmt("%s%s%s%s", inf$node, inf$ses, inf$pid, inf$a0);

	if ( index in socket_lookup ) {
		t_socket_data = socket_lookup[index];
		}
	else
		return ret_val;

	# sanity check the data: make sure that it is IP based
	if ( t_socket_data$domain == "PF_INET" || t_socket_data$domain == "PF_INET6" ) {
		ret_val = 1;
		}
	else {
		return ret_val;
		}

	# and that there is some sort of destination addressing to work with
	if ( (t_socket_data$r_addr_info == "NULL") || (t_socket_data$r_port_info == "NULL")) {
		return ret_val;
		}

	ret_val = 1;

	# ptype for building a connection object, log_protocol for logging.
	local ptype = "NULL";
	local log_protocol = "NULL";
	local sp = t_socket_data$s_prot;

	if ( sp == "UNSET" ) {
		# The protocol was not explicitly set at socket gen time so 
		#   we go a little figgurin' based on the type
		#
		if ( t_socket_data$s_type == "SOCK_STREAM" ) {
			ptype = "tcp";
			log_protocol = "TCP";
			}
		else if ( t_socket_data$s_type == "SOCK_DGRAM" ) {
			ptype = "udp";
			log_protocol = "UDP";
			}
		else if ( t_socket_data$s_type == "SOCK_RAW" ) {
			ptype = "udp";
			log_protocol = "ICMP";
			}
		else {
			ptype="udp";
			log_protocol = "UNKNOWN";
			}
		}
	else if (( sp == "TCP" ) || ( sp == "UDP" )) {
 
		ptype = to_lower(sp);
		log_protocol = sp;
		}
	else {
		log_protocol = sp;
		}

	# test and create the port sets
	# resp ports
	if ( ptype != "NULL" )
		conn_log$cid$resp_p = AUDITD_CORE::s_port( fmt("%s/%s", t_socket_data$r_port_info, ptype));
	else
		conn_log$cid$resp_p = AUDITD_CORE::s_port( fmt("0/%s", ptype));

	# orig ports
	if ( ptype != "NULL" )
		conn_log$cid$orig_p = AUDITD_CORE::s_port( fmt("%s/%s", t_socket_data$o_port_info, ptype));
	else
		conn_log$cid$orig_p = AUDITD_CORE::s_port( fmt("0/%s", ptype));

	# IP Addresses
	# resp host
	if ( t_socket_data$r_addr_info != "NULL" )
		conn_log$cid$resp_h = to_addr( fmt("%s", t_socket_data$r_addr_info) );
	else
		conn_log$cid$resp_h = to_addr("0.0.0.0");

	# orig host
	if ( t_socket_data$o_addr_info != "NULL" )
		conn_log$cid$orig_h = to_addr( fmt("%s", t_socket_data$o_addr_info) );
	else
		conn_log$cid$orig_h = to_addr("0.0.0.0");

	conn_log$ts = 		inf$ts;
	conn_log$state = 	inf$key;
	conn_log$log_id =       inf$i$log_id;
	conn_log$protocol = 	log_protocol;
	conn_log$ses = 		inf$ses;
	conn_log$node = 	inf$i$node;
	conn_log$uid = 		inf$i$idv[AUDITD_CORE::v_uid];
	conn_log$gid = 		inf$i$idv[AUDITD_CORE::v_gid];
	conn_log$euid = 	inf$i$idv[AUDITD_CORE::v_euid];
	conn_log$egid = 	inf$i$idv[AUDITD_CORE::v_egid]; 	

	Log::write(LOGCONN, conn_log);
	#delete socket_lookup[index];

	return 0;
	}


function file_error(inf: AUDITD_CORE::Info)
	{
	# AUDITD_FileMetadata
	#

	local t_fmd: fileMetaData;
	local id = AUDITD_CORE::get_identity_id(inf$ses, inf$node);

	if ( id in fileMetaDataTable ) {
		t_fmd = fileMetaDataTable[id];
		}

	switch ( inf$key ) {

		case "SYS_FILE_OPEN_ERR":

			if ( t_fmd$open_error < SYS_FILE_OPEN_THRESHOLD ) 
				t_fmd$open_error_set = fmt("%s %s", t_fmd$open_error_set, inf$path_name);

			if ( ++t_fmd$open_error == SYS_FILE_OPEN_THRESHOLD ) {
				NOTICE([$note=AUDITD_FileMetadata,
					$msg=fmt("SYS_FILE_OPEN_ERR %s %s %s errors %s", inf$i$log_id, inf$i$idv[1], SYS_FILE_OPEN_THRESHOLD, t_fmd$open_error_set )]);
				}
			break;

		case "SYS_FILE_CREATE_ERR":

			if ( t_fmd$create_error < SYS_FILE_CREATE_THRESHOLD ) 
				t_fmd$create_error_set = fmt("%s /%s", t_fmd$create_error_set, inf$path_name);

			if ( ++t_fmd$create_error == SYS_FILE_CREATE_THRESHOLD ) {
				NOTICE([$note=AUDITD_FileMetadata,
					$msg=fmt("SYS_FILE_CREATE_ERR %s %s %s errors %s", inf$i$log_id, inf$i$idv[1], SYS_FILE_CREATE_THRESHOLD, t_fmd$create_error_set )]);
				}
			break;

		case "SYS_FILE_MOD_ERR":

			if ( t_fmd$mod_error < SYS_FILE_MOD_THRESHOLD ) 
				t_fmd$mod_error_set = fmt("%s /%s", t_fmd$mod_error_set, inf$path_name);

			if ( ++t_fmd$mod_error == SYS_FILE_MOD_THRESHOLD ) {
				NOTICE([$note=AUDITD_FileMetadata,
					$msg=fmt("SYS_FILE_MOD_ERR %s %s %s errors %s", inf$i$log_id, inf$i$idv[1], SYS_FILE_MOD_THRESHOLD, t_fmd$mod_error_set )]);
				}
			break;

		case "SYS_FILE_PERM_ERR":

			if ( t_fmd$mod_error < SYS_FILE_MOD_THRESHOLD ) 
				t_fmd$mod_error_set = fmt("%s /%s", t_fmd$mod_error_set, inf$path_name);

			if ( ++t_fmd$mod_error == SYS_FILE_MOD_THRESHOLD ) {
				NOTICE([$note=AUDITD_FileMetadata,
					$msg=fmt("SYS_FILE_MOD_ERR %s %s %s errors %s", inf$i$log_id, inf$i$idv[1], SYS_FILE_MOD_THRESHOLD, t_fmd$mod_error_set )]);
				}
			break;

		case "SYS_FILE_DELETE_ERR":

			if ( t_fmd$delete_error < SYS_FILE_DELETE_THRESHOLD ) 
				t_fmd$delete_error_set = fmt("%s /%s", t_fmd$delete_error_set, inf$path_name);

			if ( ++t_fmd$delete_error == SYS_FILE_DELETE_THRESHOLD ) {
				NOTICE([$note=AUDITD_FileMetadata,
					$msg=fmt("SYS_FILE_DELETE_ERR %s %s %s errors %s", inf$i$log_id, inf$i$idv[1], SYS_FILE_DELETE_THRESHOLD, t_fmd$delete_error_set )]);
				}
			break;

		default:
			break;

		}

	fileMetaDataTable[id] = t_fmd;

	}


# Look for a unexpected transformation of the identity subvalues
#  returning a vector of changes.
#
# NOTE: the record provided by AUDITD_CORE::identityState[] has *not* yet been synced 
#  to the current living record, so changes will be reflected in the diff
#  between the live record and the historical.
#
# NOTE2: Since it is not possible to know what is the cause of the transition,
#  this function only identifies the existance of a non-whitelisted uid.
#
# NOTE3: In the event that the reporting is appening in a non-login situation
#  there will be no session id.  In this case we just bail since attribution 
#  at this point is a little murky.
#
function process_identity(new_info: AUDITD_CORE::Info) : vector of string
	{
	# return value is a map of 
	local ret_val: vector of string = vector("0", ":", ":", ":", ":", ":", ":", ":", ":");
	local n = 0;

	# no session, identity is a bit up in the air ...
	if ( new_info$ses == -1 ) {
		return ret_val;
		}

	# In this case the record is either new or corrupt.
	if ( |new_info$i$idv| == 0 ) {
		#print fmt("ID check skip zero: %s", new_info);
		return ret_val;
		}

	# even for legitimate records we will only be looking at identity transition between 
	#   USER_START and USER_END record types	
	# The test for > 1000 as well provides a dynamic lock to keep user drift off
	#
	if ( (new_info$i$id_test < 2) || (new_info$i$id_test > 1000) ) {
		#print fmt("ID check skip: id_test==F");	
		return ret_val;
		}
	
	if ( new_info$i$idv[AUDITD_CORE::v_uid] == NULL_ID ) {
		#print fmt("ID check skip NULL: %s", new_info);
		return ret_val;
		}

	# Now loop through the various identities, looking for changes
	#
	for ( ndx in new_info$i$p_idv ) {
		# Compare older identity, against the newer and check the identities against whitelists
		# Skip idv[0] since that is not a OS identity 
		if ( (ndx > 0) && identity_atomic(new_info$i$p_idv[ndx], new_info$i$idv[ndx]) ) {

			# transition up or down, second test for up avoids root -> root?
			if ( (new_info$i$idv[ndx] in UpList) && (new_info$i$p_idv[ndx] !in UpList) ) {
				# transition to root
				new_info$i$id_flag[ndx] = T;
				# see if exec is in white list, else run timer test
				if ( new_info$exe ! in ExeWhitelist ) {
					local did = fmt("%s -> %s", new_info$i$p_idv[ndx], new_info$i$idv[ndx]);
					schedule id_test_delay { AUDITD_POLICY::identity_time_test(new_info$ses, new_info$node, ndx, new_info$exe, did) };
					}

				#print fmt(" dID UP: %s %s->%s", AUDITD_CORE::translate_id(ndx), new_info$i$p_idv[ndx], new_info$i$idv[ndx]);

				}
			else {
				# not in UpList
				new_info$i$id_flag[ndx] = F;
				#print fmt(" dID DOWN: %s %s->%s", AUDITD_CORE::translate_id(ndx), new_info$i$p_idv[ndx], new_info$i$idv[ndx]);
				}

			local token = fmt("%s:%s", new_info$i$p_idv[ndx], new_info$i$idv[ndx]);
			ret_val[ndx] = token;
			# ret_val[0] contains number of changed values
			++n;
			ret_val[0] = fmt("%s", n);
		
			} # end if
		} # end for loop

	return ret_val;
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

function exec_history(inf: AUDITD_CORE::Info) : history_rec
	{
	# Mostly this is a library function to track execution
	#  to look into in the event of a permission transition
	#
	
	local id = fmt("%s:%s_%s", inf$node, inf$ses, inf$pid);
	local xvalue = fmt("%s_%s", inf$syscall, inf$exe);
	local t_hrec: history_rec;
 
	if ( id !in execution_history ) {
		# new identity
		t_hrec$exec_hist = vector("NULL", "NULL", "NULL", "NULL", "NULL");
		t_hrec$exec_count = 0;
		t_hrec$exec_hist[0] = xvalue;
		}
	else {
		t_hrec = execution_history[id];
		# calculate new position in table
		++t_hrec$exec_count;
		local n = t_hrec$exec_count % execution_history_length;
		#print fmt("exec history [%s]: %s %s %s", n, xvalue, id, inf$i$idv);	
		t_hrec$exec_hist[n] = xvalue;
		}

	execution_history[id] = t_hrec;
	return t_hrec;
	}

function sort_exec_history(hrec: history_rec) : vector of string
	{
	local miniloop: vector of count = vector(0,1,2,3,4);
	local ret_val = vector("NULL", "NULL", "NULL", "NULL", "NULL");

	for ( i in miniloop ) {

		if ( (hrec$exec_count - i) > 0 ) {
			ret_val[i] = hrec$exec_hist[((hrec$exec_count - i) % execution_history_length)];
			}
		}

	return ret_val;
	}




function transition_whitelist(trans: string) : bool
	{
	# default value is unsafe
	local ret_val = F;

	# Form of the test uses the current identity syscall_exe with the
	#   exe being the absolute path provided to the system call
	#   identity_transition_wl
	if ( trans in identity_transition_wl )
		ret_val = T;

	return ret_val;
	}


function process_wrapper(inf: AUDITD_CORE::Info) : count
	{
	# There are many things to be done with the execution chain.  This is the wrapper
	#   for that set of things to do.
	# If the session bit has not been set, this will get dumped since those activities 
	#   tend to be more system internal related.
	#
	local ret_val = 0;

	if ( exec_blacklist_test )
		exec_pathcheck(inf$exe);

	local xh = exec_history(inf);

	# track id drift
	if ( identity_drift_test ) {
		# vector of string
		local change_value = process_identity(inf);
		}

	return ret_val;
	}

function process_place(inf: AUDITD_CORE::Info) : count
	{
	# Look and see if location policy is active, if so process a quick check
	#   against the curent blacklist
	#
	local ret_val = 0;

	if ( run_location_check ) {
		if ( location_blacklist in inf$cwd )

		NOTICE([$note=AUDITD_POLICY_UserLocation,
			$msg=fmt("user identity %s in %s", inf$i$idv, inf$cwd)]);
	
		}

	return ret_val;
	}

# ----- # ----- #
#      Events
# ----- # ----- #

event clear_exec_hist(id: string)
        {
        
        if ( id in execution_history ) {
                delete execution_history[id];
                }
        }


event identity_time_test(ses: int, node: string, n: int, exe: string, did: string)
	{
	local t_id = AUDITD_CORE::get_identity_id(ses, node);

	if ( t_id in AUDITD_CORE::identityState ) {

		local t_idState = AUDITD_CORE::identityState[t_id];
	
		# test if currently in elevated state
		if ( t_idState$id_flag[n] ) {

			NOTICE([$note=AUDITD_IDTransform,
				$msg = fmt("%s %s %s %s", node, AUDITD_CORE::translate_id(n), did, exe)]);

			}

		} # end t_id in identityState

	} # end event

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

function auditd_policy_dispatcher(inf: AUDITD_CORE::Info)
	{
	# This makes routing decisions for policy based on AUDITD_CORE::Info content.  It is
	#  a bit of a kluge, but will have to do for now.

	# Initial filtering based on action and key values
	#  ex: {PLACE_OBJ, PATH} .
	# Key is defined in audit.rules
	#
	local action = inf$action;
	local key    = inf$key;
	local syscall = inf$syscall;		

	local net_syscall_set = set( "connect", "bind", "listen", "socket", "socketpair", "accept", "accept4") &redef;
	local file_error_set = set( "SYS_FILE_OPEN_ERR", "SYS_FILE_CREATE_ERR", "SYS_FILE_MOD_ERR", "SYS_FILE_DELETE_ERR", "SYS_FILE_PERM_ERR" ) &redef;

	switch ( action ) {
		case "EXECVE":
			process_wrapper(inf);
			break;

		case "GENERIC":
			process_wrapper(inf);
			break;

		case "PLACE":
			# make sure user is not anywhere they are not supposed to be
			process_place(inf); 
			break;

		case "SADDR":
			# the SADDR data will be passed over in the network system
			#  call information.
			#
			break;

		case "SYSCALL":
			# A great deal of heavy lifting takes place in the SYSCALL action type
			#
			process_wrapper(inf);

			# Process successful network related system calls
			#
			if ( (syscall in net_syscall_set) && ((inf$key == "SYS_NET") || (inf$key == "SYS_NET_ERR")) ) { 
				switch( syscall ) {
					# ---------- #
					# from syscalls: bind, connect, accept, accept4, listen, socketpair, socket
					# key: SYS_NET
					case "connect":		# initiate a connection on a socket (C/S)
						if ( (inf$s_type == "inet") || (inf$s_type == "inet6") ) {
							syscall_connect(inf);
							network_register_conn(inf);
							}
						break;

					case "bind": 		# bind a name/address to a socket (S)
						if ( (inf$s_type == "inet") || (inf$s_type == "inet6") ) {
							syscall_bind(inf);
							}
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
				
       				        break;
	
					} # end net_syscall_set switch
				}

			# File system related activities re key names:
			# SYS_FILE_OPEN : open error EACCES|EPERM
			# SYS_FILE_CREATE : new file/dir/link/dev error EACCES|EPERM
			# SYS_FILE_MOD_FAIL : modify fail error EACCES|EPERM
			# SYS_FILE_DELETE_FAIL : delete error EACCES|EPERM
			#
			# SYS_FILE_PERM : set perms on file/dir/etc
			# SYS_FILE_XPERM : set extended attributes on file/dir/etc
			#

			if ( key in file_error_set ) {
				file_error(inf);
				}
			break;
		case "USER":
			#process_wrapper(inf);
			break;
        	}

	

	} # event end

event bro_init()
	{
	Log::create_stream(AUDITD_POLICY::LOGCONN, [$columns=connection_log]);
	local filter_c: Log::Filter = [$name="default", $path="auditd_host_conn"];
	Log::add_filter(LOGCONN, filter_c);

	Log::create_stream(AUDITD_POLICY::LOGLIST, [$columns=connection_log]);
	local filter_l: Log::Filter = [$name="default", $path="auditd_host_listener"];
	Log::add_filter(LOGLIST, filter_l);

	}
