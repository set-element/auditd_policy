
module AUDITD_POLICY;

export {
	redef enum Log::ID += { LOGCONN };
        redef enum Log::ID += { LOGLIST };

	redef enum Notice::Type += {
		AUDITD_SocketOpen,
		AUDITD_POLICY_NetError,
		AUDITD_POLICY_HostScan,
		AUDITD_POLICY_PortScan,
		};

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

	# host_conn_log is a logging construct that holds some of the socket_data
	#  info as well as type fixed data like addr/port and identity info
	#
	type host_conn_log: record {
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
	global network_register_listener: function(inf: AUDITD_CORE::Info): count;
	global syscall_connect: function(inf: AUDITD_CORE::Info) : count;
	#
	# Interval that ports and hosts live in the local CMD object
	global cmd_flush_interval: interval = 90 sec &redef;

	# Network metadata
	#  here metadata can be both unix socket or inet
	# Also for tracking scanning info - the lists here
	#  are only for failed conns
	#
	# Something to hold the port list
	type port_rec: record {
		p: set[string];
	};

	# Per-host data about network activity
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
		port_scan: table[string] of port_rec;
	};

	global connMetaDataTable: table[string] of connMetaData;
	global connMetaDataHostWL: set[string] &redef;
	global connMetaDataPortWL: set[string] &redef;



	global SYS_NET_BIND_THRESHOLD =     10 &redef;
	global SYS_NET_SOCKET_THRESHOLD =   50 &redef;
	global SYS_NET_CONNECT_THRESHOLD =  50 &redef;
	global SYS_NET_LISTEN_THRESHOLD =    5 &redef;
	global SYS_NET_HOSTSCAN_THRESHOLD = 10 &redef;
	global SYS_NET_PORTSCAN_THRESHOLD = 10 &redef;

} # end export

# ----- # ----- #
#      Config
# ----- # ----- #
redef net_listen_syscalls += { "bind", "accept", };

# ----- # ----- #
#      Functions and Events
# ----- # ----- #
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

# Fill out an empty connMetaData object
function init_cmd() : connMetaData
	{
	local t_cmd: connMetaData;

	local t_bind_err_set: set[string];
	local t_socket_err_set: set[string];
	local t_connect_err_set: set[string];
	local t_listen_err_set: set[string];
	local t_host_scan: set[string];
	local t_port_scan: table[string] of port_rec;

	t_cmd$bind_err_set = t_bind_err_set;
	t_cmd$socket_err_set = t_socket_err_set;
	t_cmd$connect_err_set = t_connect_err_set;
	t_cmd$listen_err_set = t_listen_err_set;
	t_cmd$host_scan = t_host_scan;
	t_cmd$port_scan = t_port_scan;

	return t_cmd;
	}

event delete_conn_md_host(index: string, host: string)
	{
	local cmd: connMetaData;
	
	if ( host in connMetaDataHostWL )
		return;

	if ( index in connMetaDataTable) {
		cmd = connMetaDataTable[index];

		if ( host in cmd$host_scan )
			delete cmd$host_scan[host];

		connMetaDataTable[index] = cmd;
		}
	}

function add_conn_md_host(index: string, host: string) : count
	{
	local cmd: connMetaData;
	local ret_val = 0;

	if (index in connMetaDataTable) {
		# the base cmd object exists
		#  what about the host?
		cmd = connMetaDataTable[index];

		if ( host !in cmd$host_scan) {
			add cmd$host_scan[host];
			ret_val = |cmd$host_scan[host]|;

			# set timer to remove inserted host
			schedule cmd_flush_interval { delete_conn_md_host(index, host) };
			connMetaDataTable[index] = cmd;
			}
		}

	return ret_val;
	}

# For the port controls it is worth remembering that the host
#  and port scanning are in different tables.

event delete_conn_md_port(index: string, host: string, prt: string)
	{
		local cmd: connMetaData;

		if ( prt in connMetaDataPortWL )
			return;

		if ( index in connMetaDataTable) {
			cmd = connMetaDataTable[index];

			#  port_scan: table[string] of port_rec;
			if ( host in cmd$port_scan ) {
				local pr = cmd$port_scan[host];

				if ( prt in pr$p ) {
					delete pr$p[prt];
					cmd$port_scan[host] = pr;
					}
				}
			connMetaDataTable[index] = cmd;
		}
	}
function add_cmd_port(index: string, host: string, prt: string) : count
	{
	local cmd: connMetaData;
	local ret_val = 0;

	if (index in connMetaDataTable) {
		# the base cmd object exists
		#  what about the host?
		local t = connMetaDataTable[index]$port_scan;

		# t is table[string] of record port_rec
		# port_rec holds a set of string
		if (host in t) {
			# not new host
			if ( prt !in t[host]$p ) {
				# add the port only if new
				add t[host]$p[prt];
				schedule cmd_flush_interval { delete_conn_md_port(index, host, prt) };
				connMetaDataTable[index] = cmd;
				ret_val = |t[host]$p|;
				}
			}
		else {
			# new host
			local t_pr: port_rec;
			add t_pr$p[prt];
			schedule cmd_flush_interval { delete_conn_md_port(index, host, prt) };
			connMetaDataTable[index] = cmd;
			ret_val = 1;
			}

		} # end index in ...

	return ret_val;
	}

function syscall_socket(inf: AUDITD_CORE::Info) : count
	{
	# socket(int domain, int type, int protocol)
	#  a0: domain: PF_LOCAL|PF_UNIX=1  PF_INET=2  PF_INET6=10
	#
	#  a1: type: SOCK_STREAM=1    SOCK_DATAGRAM=2   SOCK_RAW=3
	#
	#  a2: protocol: 0   = IPPROTO_IP, Dummy protocol for TCP
	#		 1   = IPPROTO_ICMP,
	#		 4   = IPPROTO_IPIP, IPIP tunnels
	# 		 6   = IPPROTO_TCP
	#		 17  = IP_PROTOCOL_UDP
	#		 41  = IPPROTO_IPV6, IPv6-in-IPv4 tunnelling
	#		 255 = IPPROTO_RAW, Raw IP packets
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
		# unwanted socket domain type, exit
		return ret_val;
		}

	# identify type, bail if not stream|dgram|raw socket
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
	else if ( inf$a2 == "ff") {
		t_socket_data$s_prot = "RAW";
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
					$msg = fmt("Socket error count %s [%s] [%s] for %s %s",
						inf$i$log_id, SYS_NET_SOCKET_THRESHOLD, cmd$socket_err_set,
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
					$msg = fmt("Bind error count %s [%s] [%s] for %s %s",
					inf$i$log_id, SYS_NET_BIND_THRESHOLD, cmd$bind_err_set, inf$i$idv[AUDITD_CORE::v_uid],
					inf$i$idv[AUDITD_CORE::v_gid])]);
				}

			} # end of t_index test

			connMetaDataTable[cmdIndex] = cmd;
		} # end SYS_NET_ERR

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
    local t_index = fmt("%s|%s", inf$s_host, inf$s_serv);

	local cmd: connMetaData;
	local cmdIndex = fmt("%s%s", inf$node, inf$i$idv[AUDITD_CORE::v_auid]);

	if ( cmdIndex in connMetaDataTable )
		cmd = connMetaDataTable[cmdIndex];
    else
    	cmd = init_cmd();

	# track error conditions for identity
	# this will only apply to the normal socket
	#  activity since sendto() has no real error code
	#
	if ( inf$key == "SYS_NET_ERR" ) {

    	if ( t_index !in cmd$connect_err_set )
	        add cmd$connect_err_set[t_index];

		if ( ++cmd$connect_err_count == SYS_NET_CONNECT_THRESHOLD ) {

			local t_cec = "";
			for ( l in cmd$connect_err_set ) {
				t_cec = fmt("%s %s", t_cec, l);
				}

			NOTICE([$note=AUDITD_POLICY_NetError,
				$msg = fmt("NetError %s %s {%s}  for %s %s %s",
				inf$i$log_id, inf$node, t_cec, SYS_NET_CONNECT_THRESHOLD, inf$i$idv[AUDITD_CORE::v_uid],
				inf$i$idv[AUDITD_CORE::v_gid])]);

			} # end SYS_NET_CONNECT_THRESHOLD

		} # end SYS_NET_ERR

	#
	# Now do host scan detection
	# is this a new host??
	if ( add_conn_md_host(cmdIndex,inf$s_host) == SYS_NET_HOSTSCAN_THRESHOLD ) {

		local t_chs = "";
		for ( l2 in cmd$host_scan ) {
			t_chs = fmt("%s %s", t_chs, l2);
			}

		NOTICE([$note=AUDITD_POLICY_HostScan,
			$msg = fmt("ID %s %s @ %s %s scan {%s} %s hosts",
			inf$i$idv[AUDITD_CORE::v_uid], inf$i$idv[AUDITD_CORE::v_gid],
			inf$node, inf$i$log_id, t_chs, SYS_NET_HOSTSCAN_THRESHOLD)]);

		} # end SYS_NET_HOSTSCAN_THRESHOLD

	#
	# Now do port scan detection
	#
	if ( add_cmd_port(cmdIndex,inf$s_host,inf$s_serv) == SYS_NET_PORTSCAN_THRESHOLD ) {

		local t_cps = "";
		for ( l3 in cmd$port_scan ) {
			t_cps = fmt("%s %s", t_cps, l3);
			}

		NOTICE([$note=AUDITD_POLICY_PortScan,
			$msg = fmt("%s %s @ %s %s scan {%s} %s ports",
			inf$i$idv[AUDITD_CORE::v_uid], inf$i$idv[AUDITD_CORE::v_gid],
			inf$node, inf$i$log_id, t_cps, SYS_NET_PORTSCAN_THRESHOLD)]);

		} # end SYS_NET_PORTSCAN_THRESHOLD


	connMetaDataTable[cmdIndex] = cmd;

	# see socket function for argument details
	local index = fmt("%s%s%s%s", inf$node, inf$ses, inf$pid, inf$a0);

	if ( index in socket_lookup )
		t_socket_data = socket_lookup[index];
	else
		return ret_val;

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
					$msg = fmt("Listen error count %s [%s] [%s] for %s %s",
					inf$i$log_id, SYS_NET_LISTEN_THRESHOLD, cmd$listen_err_set, inf$i$idv[AUDITD_CORE::v_uid],
					inf$i$idv[AUDITD_CORE::v_gid])]);

				} # end SYS_NET_LISTEN_THRESHOLD

			} # end of t_index test

		connMetaDataTable[cmdIndex] = cmd;
		} # end SYS_NET_ERR

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
	local conn_log: host_conn_log;

	local index = fmt("%s%s%s%s", inf$node, inf$ses, inf$pid, inf$a0);

	if ( index in socket_lookup )
		t_socket_data = socket_lookup[index];
	else
		return ret_val;

	# sanity check the data
	if ( t_socket_data$domain == "PF_INET" || t_socket_data$domain == "PF_INET6" ) {
		ret_val = 1;
		}
	else {
		return ret_val;
		}

	ret_val = 1;

	# ptype for building a connection object, log_protocol for logging.
	local ptype = "NULL";			# protocol type
	local log_protocol = "NULL";		# name we give the protocol
	local sp = t_socket_data$s_prot;	# 

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
	# resp/orig ports
	if ( ptype != "NULL" ) {
		conn_log$cid$resp_p = AUDITD_CORE::s_port( fmt("%s/%s", t_socket_data$r_port_info, ptype));
		conn_log$cid$orig_p = AUDITD_CORE::s_port( fmt("%s/%s", t_socket_data$o_port_info, ptype));
		}
	else {
		conn_log$cid$resp_p = AUDITD_CORE::s_port( fmt("0/%s", ptype));
		conn_log$cid$orig_p = AUDITD_CORE::s_port( fmt("%s/%s", inf$s_serv, log_protocol));
		}

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
		conn_log$cid$orig_h = to_addr( fmt("%s", inf$s_host) );

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
	local conn_log: host_conn_log;

	# For the time being we focus on succesful connect() syscalls - in
	#  this event the "error" code will be 0.
	#if ( to_int(inf$ext) != 0 )
	#	return ret_val;

	local index = fmt("%s%s%s%s", inf$node, inf$ses, inf$pid, inf$a0);

	if ( index in socket_lookup )
		t_socket_data = socket_lookup[index];
	#else
	#	return ret_val;

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

	# orig/resp ports
	if ( ptype != "NULL" ) {
		conn_log$cid$resp_p = AUDITD_CORE::s_port( fmt("%s/%s", t_socket_data$r_port_info, ptype));
		conn_log$cid$orig_p = AUDITD_CORE::s_port( fmt("%s/%s", t_socket_data$o_port_info, ptype));
		}
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

event bro_init()
	{
	Log::create_stream(AUDITD_POLICY::LOGCONN, [$columns=host_conn_log]);
	local filter_c: Log::Filter = [$name="default", $path="auditd_host_conn"];
	Log::add_filter(LOGCONN, filter_c);

	Log::create_stream(AUDITD_POLICY::LOGLIST, [$columns=host_conn_log]);
	local filter_l: Log::Filter = [$name="default", $path="auditd_host_listener"];
	Log::add_filter(LOGLIST, filter_l);
	}
