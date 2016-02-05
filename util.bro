# util.bro  Scott Campbell 11/29/13
	
# 
# Various utility functions and constants used throughout the auditd infrastructure
#  scripts.  For the time being this is not part of any particular name space 
#  but that will change when things settle out a bit.
#

module AUDITD_CORE;

@load host_core/health_check

export {
	const INFO_NULL  = "NULL";

        type identity: record {
                ses:		int &default=-1;		# numeric session id or 'unset'
                node:		string &default=INFO_NULL;      # what host is this happening on
                idv:		vector of string &log;          # vector of identity values for current action
                p_idv:		vector of string;               # vector for *previous* action
		id_test:	count &default = 0;		# flag for identity transition checking: 0=F,1=F, >=2=T
		id_flag:	vector of bool;			# mark changed idenity components: T=heightened, F=otherwise
                };

        type Info: record {
                ts:        time   &log;                         #
                i:         identity &log;                       # identity structure defined above
                index:     string &log &default=INFO_NULL;      # identifier provided by key in getid()
                node:      string &log &default=INFO_NULL;      # what host is this happening on
                pid:       int    &log &default=-1;             # curent pid
                ses:       int    &log &default=-1;             # numeric session id or 'unset'
                action:    string &log &default=INFO_NULL;      # class of action (ex: 'SYSCALL_OBJ'), also ERROR_FLAG
                key:       string &log &default=INFO_NULL;      # subtype of class (ex: 'SYS_NET')
                syscall:   string &log &default=INFO_NULL;      # syscall name
                comm:      string &log &default=INFO_NULL;      # name as appears in 'ps'
                exe:       string &log &default=INFO_NULL;      # full exe name + path

                msg:       string &log &default=INFO_NULL;
                s_type:    string &log &default=INFO_NULL;      # name or file type socket
                s_host:    string &log &default=INFO_NULL;      # *where* the socket type is pointing
                s_serv:    string &log &default=INFO_NULL;      # service it is pointing to
                path_name: string &log &default=INFO_NULL;      # gen 1x per path element passed to syscall
                cwd:       string &log &default=INFO_NULL;      # current working direct at time of syscall
                a0:        string &log &default=INFO_NULL;      # argument0 to syscall
                a1:        string &log &default=INFO_NULL;      # ..
                a2:        string &log &default=INFO_NULL;      # ..
                arg_t:     string &log &default=INFO_NULL;      # for exec, *total* set of args
                ppid:      int    &log &default=-1;             # parent pid
                tty:       string &log &default=INFO_NULL;      # tty type or NO_TTY
                terminal:  string &log &default=INFO_NULL;      # terminal data or NO_TERM
                success:   string &log &default=INFO_NULL;      # if syscall succedded or not
                ext:       string &log &default=INFO_NULL;      # exit code for call
                ouid:      string &log &default=INFO_NULL;      # uid on file system inode
                ogid:      string &log &default=INFO_NULL;      # gid on file system inode
                };


	### --- ## --- ###
	# Data structs and constants
	### --- ## --- ###

	# Make bookeepng easier - note vector counting starts at zero!

	## -- identity info (process) --
	const v_auid  = 0;	# audit id, immutable even if id changes	
	const v_uid   = 1;	# user id
	const v_gid   = 2;	# group id
	const v_euid  = 3;	# effective user id
	const v_egid  = 4;	# effective group id
	const v_suid  = 5;	# set user id
	const v_sgid  = 6;	# set group id
	## -- identity info (file system) --
	const v_fsuid = 7;	# file system user id
	const v_fsgid = 8;	# file system group id

	const ident_type: table[int] of string = { [0] = "auid", [1] = "uid", [2] = "gid", [3] = "euid", [4] = "egid", [5] = "suid", [6] = "sgid", [7] = "fsuid", [8] = "fsgid" };

	# End of data structs

	## regx to test data types
	global kv_splitter: pattern = / / &redef;
	global count_match: pattern = /^[0-9]{1,16}$/;
	global int_match: pattern = /^[\-]{0,1}[0-9]{1,16}$/;
	global port_match: pattern  = /^[0-9]{1,5}\/(tcp|udp|icmp)$/;
	global time_match: pattern  = /^[0-9]{9,10}.[0-9]{0,6}$/;
	global ip_match: pattern    = /((\d{1,2})|(1\d{2})|(2[0-4]\d)|(25[0-5]))/;

	global index_match: pattern = /^[0-9]{1,10}:[0-9]{1,3}:[0-9]{1,3}$/;

	global v16: vector of count = vector(2,3,4,5,6,7,8,9,10,11,12,13,14,15,16);
	global v2s: vector of count = vector(2,4,6);

        const ID_DEFAULT = "-1";
        const zero_int: int = 0;

	## These are token values that will represent a failed conversion
	#   when I grow up I am going to use a data type that includes both 
	#   a return value and an error code.
	#
	const ADDR_CONV_ERROR: addr = 127.4.3.2;
	const TIME_CONV_ERROR: time = double_to_time( to_double("0.000001"));
	const PORT_CONV_ERROR: port = 0/tcp;
	const INT_CONV_ERROR: int   = -100;
	const STRING_CONV_ERROR: string = "SCERROR";

	#
	const DATA_NULL:          count = 3;
	const DATA_PATTERN_ERROR: count = 2;
	const DATA_CONV_ERROR:    count = 1;
	const DATA_NOERROR:       count = 0;

	### --- SOCKET --- ###
	# The socket type will be used as a proxy for holding 
	#  information about a socket oriented event.
	#
	# for a0 of socket call define the /domain/
	#
	const AF_UNIX: count = 1; # local to host (pipes)
	const AF_INET: count = 2; # internetwork: UDP, TCP, etc.

	# For a1 of the socket call, you define the socket /type/
	#  this is both a handy reference and a way of making the data
	#  more human readable....
	#
	const SOCK_STREAM: count = 1;	# stream socket 
	const SOCK_DGRAM: count  = 2;	# datagram socket
	const SOCK_RAW: count    = 3;	# raw-protocol interface
	#
	### --- END SOCKET --- ###

	#
	# Return data structure which includes both an (non)error code
	#   as well as the raw data types.
	type time_return: record {
		data: time &default = TIME_CONV_ERROR;
		ret: count &default = DATA_NULL;
		};

	type string_return: record {
		data: string &default = STRING_CONV_ERROR;
		ret: count &default = DATA_NULL;
		};


        global actionState: table[string] of Info;
        global identityState: table[string] of identity;

        global action_delete_delay = 5 min &redef;

        # exported functions and events
        global get_action_id: function(index: string, node: string) : string;
        global get_identity_id: function(ses: int, node: string) : string;

        global get_action_obj: function(index: string, node: string) : Info;
        global get_identity_obj: function(ses: int, node: string, pid: int, ppid: int) : identity;

        global sync_identity: function(index: string, node: string) : Info;
        global copy_identity: function(index: string, node: string) : Info;

        global update_action: function(i: Info);
        global build_identity: function(auid: string, uid: string, gid: string, euid: string, egid: string, fsuid: string, fsgid: string, suid: string, sgid: string) : vector of string;
	global lock_id_test: function(ses: int, node: string) : count;
	global activate_id_test: function(ses: int, node: string) : count;
	global disable_id_test: function(ses: int, node: string) : count;
        global update_identity: function(ses: int, node: string, pid: int, ppid: int, tvid: vector of string) : count;

        global delete_item: event(key: string);
        global delete_action: function(index: string, node: string);
        global string_test: function(s: string) : bool;
        global int_test: function(i: int) : bool;
        global time_test: function(t: time) : bool;
	global s_port: function(s: string) : port;
	global s_int: function(s: string) : int;
	global s_addr: function(s: string) : addr;
	global s_string: function(s: string) : string_return;
	global s_time: function(s: string) : time_return;
        global last_record: function(index: string): count;
	global translate_id: function(id: int) : string;

	} # end export

## ----- functions ----- ##
#
# utility functions for converting string types to native values
#   as well as the Info and identity data structures and the data
#   tables shared by all other policies ...
#

function translate_id(id: int) : string
	{
	local ret_val = "UNKNOWN";

	if ( id in ident_type )
		ret_val = ident_type[id];

	return ret_val;
	}

function s_time(s: string) : time_return
	{
	# default return value is 0.00000 which is the error token
	local ret_val: time_return;

	local mpr = match_pattern(s, time_match);

	if ( mpr$matched ) {
		ret_val$ret = DATA_NOERROR;
		ret_val$data  = double_to_time( to_double(s));
		}
	else {
		ret_val$ret = DATA_PATTERN_ERROR;
		print fmt("TIME PATTERN ERROR: %s", s);
		}

	return ret_val;
	}

function s_string(s: string) : string_return
	{
	# substitute '+' with a space
	local sub_s = subst_string( s, "+", " ");
	local ret_str: string_return;

	# Note that the value of ret_string should be consitered dangerous
	#  as the content can contain terminal control characters etc etc.
	ret_str$data = raw_unescape_URI( sub_s );

	# remove backspace characters and some other goop.  Most of this
	#  is driven from the iSSHD code, but you might as well keep it
	#  around in case there is hyjinx in the air re user input ...
	ret_str$data = edit(ret_str$data, "\x08");
	ret_str$data = edit(ret_str$data, "\x7f");
	# goop
	ret_str$data = gsub(ret_str$data, /\x0a/, "");
	ret_str$data = gsub(ret_str$data, /\x1b\x5b\x30\x30\x6d/, "");
	ret_str$data = gsub(ret_str$data, /\x1b\x5b./, "");

	# now scrape out all the binary goo that might still
	#   be sitting around waiting to cause problems for us ....
	ret_str$data = escape_string(ret_str$data);	
	ret_str$ret = DATA_NOERROR;

	return ret_str;
	}


function s_count(s: string) : count
	{
	local ret_val: count = 0;

	local mpr = match_pattern(s, count_match);

	if ( mpr$matched )
		ret_val =  to_count(s);
	else 
		print fmt("COUNT PATTERN ERROR: %s", s);

	return ret_val;
	}

function s_addr(s: string) : addr
	{
	local ret_val:addr = ADDR_CONV_ERROR;

	local mpr = match_pattern(s, ip_match);

	if ( mpr$matched ) {
		ret_val = to_addr(s);
		}
	else {
		print fmt("ADDR PATTERN ERROR: %s", s);
		}

	return ret_val;
	}

function s_port(s: string) : port
	{
	local ret_val = PORT_CONV_ERROR;

	# test to see if the "value" component is missing the protocol string
	local t_port = s;
	local p_pm = match_pattern( t_port, port_match );

	if ( p_pm$matched ) {
		ret_val = to_port(t_port);
		}	
	else {
		local c_pm = match_pattern( t_port, count_match );

		if ( c_pm$matched ) {
			t_port = fmt("%s/tcp", t_port);
			ret_val = to_port(t_port);
			}
		}

	return ret_val;
	}

function s_int(s: string) : int
	{
	local ret_val:int = INT_CONV_ERROR;

	local i_pm = match_pattern( s, int_match );

	if ( i_pm$matched )
		ret_val = to_int(s);
	else
		print fmt("INT PATTERN ERROR: %s", s);

	return ret_val;
	}


function get_action_id(index: string, node: string) : string
{
        # This function returnes the action-id ( index_major:node )
        # In the event of the index value not being of the expected form
        #   the function returns "NULL" rather than an indeterminant quantity.
        #

        # This function should never return this value.
        local ret = INFO_NULL;

        # take index value (a:b:c) and split it up
        local i = split_string(index, /:/);

        # weed out corrupt data
        if ( |i| == 3 ) {
                local i_major = to_count(i[0]);
                ret = fmt("%s%s", i_major, node);
                }

        return ret;

} # function get_action_id end

function get_identity_id(ses: int, node: string) : string
{
        # This function returns the identity-id (huh?!?)
        local ret = INFO_NULL;
        ret = fmt("%s%s", ses,node);
        return ret;
}



function get_action_obj(index: string, node: string) : Info
{
        local key = get_action_id(index,node);
        local t_Info: Info;

        #print fmt("index: %s key: %s", index, key);

        # error state test - the action
        if ( key == INFO_NULL ) {
                t_Info$action = "ERROR_STATE";
                return t_Info;
                }

        # If the key is been registered use it, else
        #  use t_Info.
        if ( key in actionState ) {
                t_Info = actionState[key];
                }
        else {
                # add the key instance
                t_Info$node = node;
                t_Info$index = index;
                actionState[key] = t_Info;
                }

        return t_Info;

} # end get_action_obj


function get_identity_obj(ses: int, node: string, pid: int, ppid: int) : identity
{
        local key = get_identity_id(ses, node);
        local t_identity: identity;

        if ( key in identityState )
                t_identity = identityState[key];
	#else {
	#	# Look up the identity of the parent object instead
        #	local alt_key = get_identity_id(ses, node, ppid);

	#	if ( alt_key in identityState )
        #        	t_identity = identityState[alt_key];
	#	}

        return t_identity;
} # end get_identity_obj

function last_record(index: string): count
{
        # test the index field to see if this is the last record in a series
        #  3:2:2 means index:total_records:record_index
        # so in this case the result would be true
        #
        # /^[0-9]{1,10}:[0-9]{1,3}:[0-9]{1,3}$/
        local ret = 0;

        local mpr = match_pattern(index, index_match);

        if ( mpr$matched ) {
                local index_split = split_string(index, /:/);

                if ( index_split[1] == index_split[2] )
                        ret = 1;
                }
        else
                print fmt("INDEX pattern match for: %s", index);

        return ret;
}

function test_update(v: string): bool
{
        local ret_val = F;
        if ( (v != INFO_NULL) && (v != "-1") )
                ret_val = T;

        return ret_val;
}

function update_action(i: Info)
{
        # Update the indexed Info obj with the provided t_Info
        local key = get_action_id(i$index,i$node);
        # update the record values for new *non-default* entries
        if ( key in actionState ) {

                local i_old = actionState[key];

                if ( test_update(i$index) )
                        i_old$index = i$index;

                if ( test_update(i$node) )
                        i_old$node = i$node;

                local tpid = fmt("%s", i$pid);
                if ( test_update(tpid) )
                        i_old$pid = i$pid;

                local tses = fmt("%s", i$ses);
                if ( test_update(tses) )
                        i_old$ses = i$ses;

                if ( test_update(i$action) )
                        i_old$action = i$action;

                if ( test_update(i$key) )
                        i_old$key = i$key;

                if ( test_update(i$syscall) )
                        i_old$syscall = i$syscall;

                if ( test_update(i$comm) )
                        i_old$comm = i$comm;

                if ( test_update(i$exe) )
                        i_old$exe = i$exe;

                if ( test_update(i$msg) )
                        i_old$msg = i$msg;
                if ( test_update(i$s_type) )
                        i_old$s_type = i$s_type;

                if ( test_update(i$s_host) )
                        i_old$s_host = i$s_host;

                if ( test_update(i$s_serv) )
                        i_old$s_serv = i$s_serv;

                if ( test_update(i$path_name) )
                        i_old$path_name = i$path_name;

                if ( test_update(i$cwd) )
                        i_old$cwd = i$cwd;

                if ( test_update(i$a0) )
                        i_old$a0 = i$a0;

                if ( test_update(i$a1) )
                        i_old$a1 = i$a1;

                if ( test_update(i$a2) )
                        i_old$a2 = i$a2;

                if ( test_update(i$arg_t) )
                        i_old$arg_t = i$arg_t;

                local tppid = fmt("%s", i$ppid);
                if ( test_update(tppid) )
                        i_old$ppid = i$ppid;

                if ( test_update(i$tty) )
                        i_old$tty = i$tty;

                if ( test_update(i$terminal) )
                        i_old$terminal = i$terminal;

                if ( test_update(i$success) )
                        i_old$success = i$success;

                if ( test_update(i$ext) )
                        i_old$ext = i$ext;

                if ( test_update(i$ouid) )
                        i_old$ouid = i$ouid;

                if ( test_update(i$ogid) )
                        i_old$ogid = i$ogid;

                actionState[key] = i_old;
                }
        else {
                print fmt("UPDATE ERROR for index %s", key);
                }
}

function copy_identity(index: string, node: string) : Info
{
        # Take identity and sync it with the action structure
        local t_Info = get_action_obj(index,node);
        local t_identity = get_identity_obj(t_Info$ses, t_Info$node, t_Info$pid, t_Info$ppid);

        t_Info$i = t_identity;
        return t_Info;
}

function sync_identity(index: string, node: string) : Info
{
        # Take identity and sync it with the action structure
        local t_Info = get_action_obj(index,node);
        local t_identity = get_identity_obj(t_Info$ses, t_Info$node, t_Info$pid, t_Info$ppid);

        t_Info$i = t_identity;

        local key = get_action_id(t_Info$index,t_Info$node);
        actionState[key] = t_Info;

        return t_Info;
}

function delete_action(index: string, node: string)
{
        # remove action obj
        local key = get_action_id(index,node);

        if ( key in actionState )
                schedule action_delete_delay { delete_item(key) };
}

function string_test(s: string) : bool
{
        # Here we test for an error condition on the input framework conversion,
        #   or a default value in the field (which could write over pre-existing
        #   data.
        local ret = T;

        if ( (s == STRING_CONV_ERROR) || (s == ID_DEFAULT) || (s == INFO_NULL) )
                ret = F;

        return ret;
}


function int_test(i: int) : bool
{
        # Here we test for an error condition on the input framework conversion,
        #   or a default value in the field (which could write over pre-existing
        #   data.
        local ret = T;

        if ( (i == INT_CONV_ERROR) || (i == -1) )
                ret = F;

        return ret;
}

function time_test(t: time) : bool
{
        # Here we test for an error condition on the input framework conversion,
        #   or a default value in the field (which could write over pre-existing
        #   data.
        #
        local ret = T;

        if ( t == TIME_CONV_ERROR )
                ret = F;

        return ret;
}

function build_identity(auid: string, uid: string, gid: string, euid: string, egid: string, fsuid: string, fsgid: string, suid: string, sgid: string) : vector of string
{
        # simple function to take the big blob of text identities and put them into a more
        #  useful form for consumption by other heuristics.
        #
        local t_idv: vector of string = vector(auid, uid, gid, euid, egid, suid, sgid, fsuid, fsgid);
        #local t_identity: identity;

        #t_identity$ses = ses;
        #t_identity$node = node;
        #t_identity$idv = t_idv;

        return t_idv;
}

# This function locks the identity checking out for a given session
#
function lock_id_test(ses: int, node: string) : count
{
	local key = get_identity_id(ses, node);
	local t_identity: identity;

	if ( key == INFO_NULL )
		return 2;

	if ( key in identityState ) {
		t_identity = identityState[key];
		}

	t_identity$id_test = 10000;

	identityState[key] = t_identity;
	return 0;
}

function activate_id_test(ses: int, node: string) : count
{
	local key = get_identity_id(ses, node);
	local t_identity: identity;

	if ( key == INFO_NULL )
		return 2;

	if ( key in identityState ) {
		t_identity = identityState[key];
		}

	++t_identity$id_test;

	identityState[key] = t_identity;
	return 0;
}

function disable_id_test(ses: int, node: string) : count
{
	local key = get_identity_id(ses, node);
	local t_identity: identity;

	if ( key == INFO_NULL )
		return 2;

	if ( key in identityState ) {
		t_identity = identityState[key];
		}

	if ( t_identity$id_test > 1 ) {
		--t_identity$id_test;
		}
	else {
		t_identity$id_test = 0;
		}

	identityState[key] = t_identity;
	return 0;
}

function update_identity(ses: int, node: string, pid: int, ppid: int, tvid: vector of string) : count
{
        # Update values for the identity object.  If the obj is not in the
        #   identityState table, create it
        local key = get_identity_id(ses, node);
        local t_identity: identity;

        if ( key == INFO_NULL )
                return 2;

        # Pull up old data if it exists
        if ( key in identityState ) {
                t_identity = identityState[key];
                }
        #else
        #       print fmt("key %s NOT in identityState", key);

        # now update the values
        if ( int_test(ses) )
                t_identity$ses = ses;

        if ( string_test(node) )
                t_identity$node = node;

        # if the action is not the first, copy current
        #  set to the prev vector container
        if ( |t_identity$idv| > 1  ) {
                for ( i in t_identity$idv )
                        t_identity$p_idv[i] = t_identity$idv[i];
                        }

        # move through identity vector
        for ( i in tvid ) {
                if ( (tvid[i] != "-1") && (tvid[i] != INFO_NULL))
                        t_identity$idv[i] = tvid[i];
                }

        identityState[key] = t_identity;
        #print fmt("ID UPDATE: %s -> %s", t_identity$p_idv, t_identity$idv);

        return 0;
} # end update_identity

event delete_item(key: string)
{
        # This is used to do the actual removing of records from the
        #   actionState table
        #
        if ( key in actionState )
                delete actionState[key];
}


event bro_init()
{
#	if ( AUDITD_IN_STREAM::DATANODE )
#		schedule measure_interval { measure() };

}
