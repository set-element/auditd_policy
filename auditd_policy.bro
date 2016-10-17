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
@load auditd_policy/auditd_net

module AUDITD_POLICY;

export {
	redef enum Notice::Type += {
		AUDITD_IDTransform,
		AUDITD_IDTransformSkip,
		AUDITD_ExecPathcheck,
		AUDITD_Longtime,
		AUDITD_FileMetadata,
		AUDITD_POLICY_UserLocation,
		};

	# tag for file loaded
	const AUDITD_POLICY_LOAD = T;

	# List of identities which are consitered ok to be seen translating
	#  between one another.
	#
	global whitelist_to_id: set[string] = { "NULL", "-1", } &redef;
	global whitelist_from_id: set[string] = { "NULL", "-1" } &redef;

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

	global auditd_execve: function(i: AUDITD_CORE::Info);
	global auditd_generic: function(i: AUDITD_CORE::Info);
	global auditd_place: function(i: AUDITD_CORE::Info);
	global auditd_saddr: function(i: AUDITD_CORE::Info);
	global auditd_syscall: function(i: AUDITD_CORE::Info);
	global auditd_user: function(i: AUDITD_CORE::Info);

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

# ----- # ----- #
#      Functions
# ----- # ----- #

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
				$msg = fmt("%s %s %s %s %s", t_idState$log_id, node, AUDITD_CORE::translate_id(n), did, exe)]);

			}

		} # end t_id in identityState

	} # end event

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

	local net_syscall_set = set( "connect", "bind", "listen", "socket", "socketpair", "accept", "accept4", "sendto") &redef;
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
			if ( (syscall in net_syscall_set) && ((inf$key == "SYS_NET") || (inf$key == "SYS_NET_ERR") || (inf$key == "SYS_NET_SENDTO")) ) {
				switch( syscall ) {
					# ---------- #
					# from syscalls: bind, connect, accept, accept4, listen, socketpair, socket
					# key: SYS_NET
					case "connect":		# initiate a connection on a socket (C/S)
						if ( (inf$s_type == "inet") || (inf$s_type == "inet6") ) {
							AUDITD_POLICY::syscall_connect(inf);
							network_register_conn(inf);
							}
						break;

					case "sendto":		# for now treat like a connect()
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

