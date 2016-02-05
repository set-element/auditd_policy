# auditd_core.bro
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
@load auditd_policy/auditd_policy

module AUDITD_CORE;

export {

	# AUDITD_CORE log stream identifier
	redef enum Log::ID += { LOG };

	global idLibraryWhitelist: set[string] = set("/usr/sbin/crond") &redef;
	}

event auditd_execve(index: string, action: string, ts: time, node: string, ses: int, pid: int, argc: int, argument: string)
	{
	# Beta event
	# look up the related record
	local t_Info = get_action_obj(index,node);

	# update field values if they are not error or default values
	
	if ( string_test(action) )
		t_Info$action = action;
	
	#if ( time_test(ts) )
		t_Info$ts = ts;
	
	if ( int_test(ses) )
		t_Info$ses = ses;

	if ( int_test(pid) )
		t_Info$pid = pid;
	
	if ( string_test(argument) )
		t_Info$arg_t = argument;

	update_action(t_Info);

	# if the last record, print it and clean up the action state
	if ( last_record(index) == 1 ) {
		t_Info = sync_identity(index,node);
		Log::write(LOG, t_Info);

		AUDITD_POLICY::auditd_policy_dispatcher(t_Info);

		delete_action(index,node);
		}

	} # end auditd_execve


event auditd_generic(index: string, action: string, ts: time, node: string, ses: int, pid: int, auid: string, comm: string, exe: string, a0: string, a1: string, a2: string, uid: string, gid: string, euid: string, egid: string, fsuid: string, fsgid: string, suid: string, sgid: string, ppid: int, tty: string, terminal: string, success: string, ext: string)
	{
	# Alpha event
	# look up the related record
	local t_Info = get_action_obj(index,node);

	# update field values if they are not error or default values
	#
	if ( string_test(index) )
		t_Info$index = index;

	if ( string_test(action) )
		t_Info$action = action;
	
	#if ( time_test(ts) )
		t_Info$ts = ts;
	
	if ( int_test(ses) )
		t_Info$ses = ses;

	if ( int_test(pid) )
		t_Info$pid = pid;

	# ----- #
	
	if ( string_test(comm) )
		t_Info$comm = comm;

	if ( string_test(exe) )
		t_Info$exe = exe;

	if ( string_test(a0) )
		t_Info$a0 = a0;

	if ( string_test(a1) )
		t_Info$a1 = a1;

	if ( string_test(a2) )
		t_Info$a2 = a2;

	if ( int_test(ppid) )
		t_Info$ppid = ppid;

	if ( string_test(tty) )
		t_Info$tty = tty;

	if ( string_test(terminal) )
		t_Info$terminal = terminal;

	if ( string_test(success) )
		t_Info$success = success;

	if ( string_test(ext) )
		t_Info$ext = ext;

	# identification
	local t_id = build_identity(auid, uid, gid, euid, egid, fsuid, fsgid, suid, sgid);
	update_identity(ses,node,pid,ppid,t_id);

	update_action(t_Info);

	# if the last record, print it
	if ( last_record(index) == 1 ) {
		t_Info = sync_identity(index,node);
		Log::write(LOG, t_Info);

		AUDITD_POLICY::auditd_policy_dispatcher(t_Info);

		delete_action(index,node);
		}

	} # end auditd_generic event

event auditd_place(index: string, action: string, ts: time, node: string, ses: int, pid: int, cwd: string, path_name: string, inode: int, mode: int, ouid: string, ogid: string)
	{
	# Beta event
	# ouid/ogid: Refer to the UID and GID of the inode itself. 
	#
	# look up the related record
	local t_Info = get_action_obj(index,node);

	# update field values if they are not error or default values
	if ( int_test(ses) )
		t_Info$ses = ses;

		t_Info$ts = ts;
	if ( string_test(cwd) )	
		t_Info$cwd = cwd;

	if ( string_test(path_name) )
		t_Info$path_name = path_name;

	if ( string_test(ouid) )
		t_Info$ouid = ouid;

	if ( string_test(ogid) )
		t_Info$ogid = ogid;

	update_action(t_Info);

	# if the last record, print it
	if ( last_record(index) == 1 ) {
		t_Info = sync_identity(index,node);
		Log::write(LOG, t_Info);

		AUDITD_POLICY::auditd_policy_dispatcher(t_Info);

		delete_action(index,node);
		}

	} # end event auditd_place

event auditd_saddr(index: string, action: string, ts: time, node: string, ses: int, pid: int, saddr: string)
	{

	# most of the work here will be in decoding the saddr structure
	#
	# common types:
	# 	inet host 1.2.3.4 serv:123
	# 	local /dev/filename
	# 	netlink /dev/log
	#
	# will be broken out into the following structures
	#
	# 	type : {inet host|local|netlink}
	# 	host : {file|device|ip} identifies where
	# 	serv : {port} (optional) identifies what
	#
	
	local t_Info = get_action_obj(index,node);
		t_Info$ts = ts;

	# decode the saddr structure
	local t_saddr = unescape_URI(saddr);
	local split_saddr = split_string(t_saddr, / / );

	local stype = split_saddr[0];
	local host = split_saddr[1];

	#print fmt("auditd_saddr saddr: %s", saddr);

	if ( |split_saddr| > 2 ) {
		local serv = split_saddr[2];
		local t_serv = split_string( serv, /:/ );
		}

	local t_host = split_string( host, /:/ );

	# make decisions based on field 1
	if ( stype == "inet" ) {

		if ( string_test(stype) )
			t_Info$s_type = stype;

		if ( string_test(t_host[1]) )
			t_Info$s_host = t_host[1];

		if ( string_test(t_serv[1]) )
			t_Info$s_serv = t_serv[1];

		print fmt("          INIT: %s %s %s", t_Info$s_type, t_Info$s_host, t_Info$s_serv);
		}
	else if ( stype == "local" ) {
	
		if ( string_test(stype) )	
			t_Info$s_type = stype;

		if ( string_test(host) )
			t_Info$s_host = host;

		} 
	else if ( stype == "netlink" ) {

		if ( string_test(stype) )	
			t_Info$s_type = stype;

		if ( string_test(t_host[2]) )
			t_Info$s_host = t_host[1];
		
		}

	update_action(t_Info);

	# if the last record, print it
	if ( last_record(index) == 1 ) {
		t_Info = sync_identity(index,node);
		Log::write(LOG, t_Info);

		AUDITD_POLICY::auditd_policy_dispatcher(t_Info);

		delete_action(index,node);
		}

	} # end event auditd_saddr


event auditd_syscall(index: string, action: string, ts: time, node: string, ses: int, pid: int, auid: string, syscall: string, key: string, comm: string, exe: string, a0: string, a1: string, a2: string, uid: string, gid: string, euid: string, egid: string, fsuid: string, fsgid: string, suid: string, sgid: string, ppid: int, tty: string, success: string, ext: string)
	{
	# look up the related record
	local t_Info = get_action_obj(index,node);

	# update field values if they are not error or default values
	if ( string_test(index) )
		t_Info$index = index;

	if ( string_test(action) )
		t_Info$action = action;

	#if ( time_test(ts) )
		t_Info$ts = ts;	

	if ( int_test(ses) )
		t_Info$ses = ses;

	if ( int_test(pid) )
		t_Info$pid = pid;
	#

	if ( string_test(syscall) )
		t_Info$syscall = syscall;

	if ( string_test(key) )
		t_Info$key = key;

	if ( string_test(comm) )
		t_Info$comm = comm;

	if ( string_test(exe) )
		t_Info$exe = exe;

	if ( string_test(a0) )
		t_Info$a0 = a0;

	if ( string_test(a1) )
		t_Info$a1 = a1;

	if ( string_test(a2) )
		t_Info$a2 = a2;

	if ( int_test(ppid) )
		t_Info$ppid = ppid;

	if ( string_test(tty) )
		t_Info$tty = tty;

	if ( string_test(success) )
		t_Info$success = success;

	if ( string_test(ext) )
		t_Info$ext = ext;

	# identification
	local t_id = build_identity(auid, uid, gid, euid, egid, fsuid, fsgid, suid, sgid);
	update_identity(ses,node,pid,ppid,t_id);
	
	update_action(t_Info);

	# if the last record, print it
	if ( last_record(index) == 1 ) {
		t_Info = sync_identity(index,node);
		Log::write(LOG, t_Info);

		AUDITD_POLICY::auditd_policy_dispatcher(t_Info);

		delete_action(index,node);
		}

	} # end event auditd_syscall

event auditd_user(index: string, action: string, ts: time, node: string, ses: int, pid: int, auid: string, euid: string, egid: string, fsuid: string, fsgid: string, suid: string, sgid: string, uid: string, gid: string, exe: string, terminal: string, success: string, ext: string, msg: string)
	{
	# look up the related record
	local t_Info = get_action_obj(index,node);

	# for now just update the field values
	# only update the action for some types
	if ( string_test(index) )
		t_Info$index = index;

	if ( string_test(action) )
		t_Info$action = action;

	#if ( time_test(ts) )
		t_Info$ts = ts;

	if ( int_test(ses) )
		t_Info$ses = ses;

	if ( int_test(pid) )
		t_Info$pid = pid;

	# ----- #

	if ( string_test(msg) )
		t_Info$msg = msg;

	if ( string_test(exe) )
		t_Info$exe = exe;
	
	if ( string_test(terminal) )
		t_Info$terminal = terminal;

	if ( string_test(success) )
		t_Info$success = success;

	if ( string_test(ext) )
		t_Info$ext = ext;

	# identification
	local t_id = build_identity(auid, uid, gid, euid, egid, fsuid, fsgid, suid, sgid);
	update_identity(ses,node,pid,0,t_id);

	# turn on/off identity transition checking
	if ( action == "USER_START" )
		{
		if ( exe in idLibraryWhitelist ) {
			lock_id_test(ses, node);
			}

		activate_id_test(ses, node);
		}

	if ( action == "USER_END" ) 
		{
		#print fmt("disable id test for %s", uid);
		disable_id_test(ses, node); 
		}

	update_action(t_Info);

	# if the last record, print it
	if ( last_record(index) == 1 ) {
		t_Info = sync_identity(index,node);
		Log::write(LOG, t_Info);

		AUDITD_POLICY::auditd_policy_dispatcher(t_Info);

		delete_action(index,node);
		}

	}
	

event bro_init() &priority = 5
{
	Log::create_stream(AUDITD_CORE::LOG, [$columns=Info]);
	local filter_c: Log::Filter = [$name="default", $path="auditd_core];
	Log::add_filter(LOG, filter_c);
}
