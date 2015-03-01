# auditd_input_stream.bro
#  Scott Campbell
#
# note on syntax: The traditional "thing that happens" in auditd is called an 'event' 
#  which is clearly an issue, so I am renaming them 'action'.  Actions are composed of
#  of records, which are themselves composed of fields.
#
# note: to address the NULL = '-1' issue with counts, ints and whatnot, there will be 
#       no use of count types in the event stream.  Makes life just that much simpler!
#       For user identificaton just ue a string type since the id will normally be a
#       legitimate account.
#
@load auditd_policy/util

@load frameworks/communication/listen
@load base/frameworks/input

module AUDITD_IN_STREAM;

export {

	redef InputAscii::empty_field = "EMPTY";
	global kv_splitter: pattern = / /;

	type lineVals: record {
		d: string;
	};

	const data_file = "/home/bro/logs/RAW/AUDIT_DATA_0" &redef;
	#const data_file = "/tmp/ad" &redef;
	const DATANODE = F &redef;

	const dispatcher: table[string] of function(_data: string): count &redef;
	}

function execve_f(data: string) : count
	{
	# data format:
	# 1492:2 EXECVE_OBJ EXECVE 1357649135.905 3 %20/bin/csh%20-f%20/usr/common/usg/bin/nersc_host
	local parts = split(data, kv_splitter);

	if ( |parts| < 9 ) {
		print fmt("execve_f parse error for %s", data);
		return 1;
		}

	local index = AUDITD_CORE::s_string( parts[1] );	# form a:b, a=action count, b=which record in action
	local flavor = AUDITD_CORE::s_string( parts[2] );	# base object type
	local action = AUDITD_CORE::s_string( parts[3] );	# the thing that happens, also called 'event' in traditional auditd docs
	local ts = AUDITD_CORE::s_time( parts[4] );		# time of record
	local node = AUDITD_CORE::s_string( parts[5] );
	local ses = AUDITD_CORE::s_int( parts[6] );		# login session ID
	local pid = AUDITD_CORE::s_int( parts[7] );		# Process id
	#
	local argc = AUDITD_CORE::s_int( parts[8] );		# number of arguments for exec (starts at 1)
	local argument = AUDITD_CORE::s_string( parts[9] );	# total argument string

	#event auditd_execve(index$data, action$data, ts$data, node$data, ses, pid, argc, argument$data);
	#event AUDITD_CORE::auditd_execve(index, action, ts, node, ses, pid, argc, argument);

	return 0;
	}

function generic_f(data: string) : count
	{
	# 65465:2 GENERIC_OBJ FD_PAIR 1357648201.328 mndlint01 0 NULL NULL NULL NULL NULL NULL -1 -1 -1 -1 -1 -1
	# -1 -1 -1 -1 NULL NULL NULL 0
	local parts = split(data, kv_splitter);

	if ( |parts| < 27 ) {
		print fmt("generic_f parse error for %s", data);
		return 1;
		}

	local index = AUDITD_CORE::s_string( parts[1] );	# form a:b, a=action count, b=which record in action
	local flavor = AUDITD_CORE::s_string( parts[2] );	# base object type
	local action = AUDITD_CORE::s_string( parts[3] );	# the thing that happens, also called 'event' in traditional auditd docs
	local ts = AUDITD_CORE::s_time( parts[4] );		# time of record
	local node = AUDITD_CORE::s_string( parts[5] );	# host data originated from
	#
	local auid = AUDITD_CORE::s_string( parts[6] );
	local key = AUDITD_CORE::s_string( parts[7] ); 
	local comm = AUDITD_CORE::s_string( parts[8] );
	local exe = AUDITD_CORE::s_string( parts[9] );
	local a0 = AUDITD_CORE::s_string( parts[10] );
	local a1 = AUDITD_CORE::s_string( parts[11] );
	local a2 = AUDITD_CORE::s_string( parts[12] );
	local uid = AUDITD_CORE::s_string( parts[13] );
	local gid = AUDITD_CORE::s_string( parts[14] );
	local euid = AUDITD_CORE::s_string( parts[15] );
	local egid = AUDITD_CORE::s_string( parts[16] );
	local fsuid = AUDITD_CORE::s_string( parts[17] );
	local fsgid = AUDITD_CORE::s_string( parts[18] );
	local suid = AUDITD_CORE::s_string( parts[19] );
	local sgid = AUDITD_CORE::s_string( parts[20] );
	local pid = AUDITD_CORE::s_int( parts[21] );
	local ppid = AUDITD_CORE::s_int( parts[22] );
	local ses = AUDITD_CORE::s_int( parts[23] );
	local tty = AUDITD_CORE::s_string( parts[24] );
	local terminal = AUDITD_CORE::s_string( parts[25] );
	local success = AUDITD_CORE::s_string( parts[26] );
	local ext = AUDITD_CORE::s_string( parts[27] );	

	event auditd_generic(index$data, action$data, ts$data, node$data, ses, pid, auid$data, comm$data, exe$data, a0$data, a1$data, a2$data, uid$data, gid$data, euid$data, egid$data, fsuid$data, fsgid$data, suid$data, sgid$data, ppid, tty$data, terminal$data, success$data, ext$data);

	return 0;
	}

function place_f(data: string) : count
	{
	# 13:2 PLACE_OBJ CWD 1357669891.417 mndlint01 /chos/global/project/projectdirs/mendel/ganglia NULL -1 -1
	# 13:3 PLACE_OBJ PATH 1357669891.417 mndlint01 NULL rrds/Mendel%20Compute/mc0867.nersc.gov/.cpu_idle.rrd.
	#                       6ITCyp 252651183 0100600 unknown(65534) unknown(65533)
	local parts = split(data, kv_splitter);

	if ( |parts| < 13 ) {
		print fmt("place_f parse error for %s", data);
		return 1;
		}
	local index = AUDITD_CORE::s_string( parts[1] );	# form a:b, a=action count, b=which record in action
	local flavor = AUDITD_CORE::s_string( parts[2] );	# base object type
	local action = AUDITD_CORE::s_string( parts[3] );	# the thing that happens, also called 'event' in traditional auditd docs
	local ts = AUDITD_CORE::s_time( parts[4] );		# time of record
	local node = AUDITD_CORE::s_string( parts[5] );	# host data originated from
	local ses = AUDITD_CORE::s_int( parts[6] );
	local pid = AUDITD_CORE::s_int( parts[7] );
	#
	local cwd = AUDITD_CORE::s_string( parts[8] );
	local path_name = AUDITD_CORE::s_string( parts[9] );
	local inode = AUDITD_CORE::s_int( parts[10] );
	local mode = AUDITD_CORE::s_int( parts[11] );
	local ouid = AUDITD_CORE::s_string( parts[12] );
	local ogid = AUDITD_CORE::s_string( parts[13] );

	event auditd_place(index$data, action$data, ts$data, node$data, ses, pid, cwd$data, path_name$data, inode, mode, ouid$data, ogid$data);
	return 0;
	}

function saddr_f(data: string) : count
	{
	# 1433:2 SADDR_OBJ SOCKADDR 1357670401.886 netlink%20pid%3A0
	# 24142:2 SADDR_OBJ SOCKADDR 1357648977.688 inet%20host%3A208.45.140.197%20serv%3A80
	local parts = split(data, kv_splitter);

	if ( |parts| < 8 ) {
		print fmt("saddr_f parse error for %s", data);
		return 1;
		}
	local index = AUDITD_CORE::s_string( parts[1] );	# form a:b, a=action count, b=which record in action
	local flavor = AUDITD_CORE::s_string( parts[2] );	# base object type
	local action = AUDITD_CORE::s_string( parts[3] );	# the thing that happens, also called 'event' in traditional auditd docs
	local ts = AUDITD_CORE::s_time( parts[4] );		# time of record
	local node = AUDITD_CORE::s_string( parts[5] );	# host data originated from
	local ses = AUDITD_CORE::s_int( parts[6] );
	local pid = AUDITD_CORE::s_int( parts[7] );
	#
	local saddr = AUDITD_CORE::s_string( parts[8] );	# address object (local or inet)

	event auditd_saddr(index$data, action$data, ts$data, node$data, ses, pid, saddr$data);
	return 0;
	}

function syscall_f(data: string) : count
	{
	# 9:1 SYSCALL_OBJ SYSCALL 1357669891.416 mndlint01 root chmod SYS_FILE_PERM rsync /usr/bin/rsync 7ffff282
	#                           1570 1a4 8000 root root root root root root root root 19220 19206 NO_TTY chmod yes 0
	local parts = split(data, kv_splitter);

	if ( |parts| < 27 ) {
		print fmt("syscall_f parse error for %s", data);
		return 1;
		}
	local index = AUDITD_CORE::s_string( parts[1] );	# form a:b, a=action count, b=which record in action
	local flavor = AUDITD_CORE::s_string( parts[2] );	# base object type
	local action = AUDITD_CORE::s_string( parts[3] );	# the thing that happens, also called 'event' in traditional auditd docs
	local ts = AUDITD_CORE::s_time( parts[4] );		# time of record
	local node = AUDITD_CORE::s_string( parts[5] );
	#
	local ses = AUDITD_CORE::s_int( parts[6] );		# login session ID
	local auid = AUDITD_CORE::s_string( parts[7] );
	local syscall = AUDITD_CORE::s_string( parts[8] );
	local key = AUDITD_CORE::s_string( parts[9] ); 
	local comm = AUDITD_CORE::s_string( parts[10] );
	local exe = AUDITD_CORE::s_string( parts[11] );
	local a0 = AUDITD_CORE::s_string( parts[12] );
	local a1 = AUDITD_CORE::s_string( parts[13] );
	local a2 = AUDITD_CORE::s_string( parts[14] );
	local uid = AUDITD_CORE::s_string( parts[15] );
	local gid = AUDITD_CORE::s_string( parts[16] );
	local euid = AUDITD_CORE::s_string( parts[17] );
	local egid = AUDITD_CORE::s_string( parts[18] );
	local fsuid = AUDITD_CORE::s_string( parts[19] );
	local fsgid = AUDITD_CORE::s_string( parts[20] );
	local suid = AUDITD_CORE::s_string( parts[21] );
	local sgid = AUDITD_CORE::s_string( parts[22] );
	local pid = AUDITD_CORE::s_int( parts[23] );
	local ppid = AUDITD_CORE::s_int( parts[24] );
	local tty = AUDITD_CORE::s_string( parts[25] );
	#local terminal = AUDITD_CORE::s_string( parts[26] );
	local success = AUDITD_CORE::s_string( parts[26] );
	local ext = AUDITD_CORE::s_string( parts[27] );

	event auditd_syscall(index$data, action$data, ts$data, node$data, ses, pid, auid$data, syscall$data, key$data, comm$data, exe$data, a0$data, a1$data, a2$data, uid$data, gid$data, euid$data, egid$data, fsuid$data, fsgid$data, suid$data, sgid$data, ppid, tty$data, success$data, ext$data);
	return 0;
	}

function user_f(data: string) : count
	{
	# 2500:1 USER_OBJ USER_ACCT 1357649165.26 mndlint01 0 scottc -1 -1 -1 -1 -1 -1 -1 scottc NULL 0 /chos/dev
	#                           /pts/1 /bin/su
	local parts = split(data, kv_splitter);

	if ( |parts| < 20 ) {
		print fmt("user_f parse error for %s", data);
		return 1;
		}
	local index = AUDITD_CORE::s_string( parts[1] );	# form a:b, a=action count, b=which record in action
	local flavor = AUDITD_CORE::s_string( parts[2] );	# base object type
	local action = AUDITD_CORE::s_string( parts[3] );	# the thing that happens, also called 'event' in traditional auditd docs
	local ts = AUDITD_CORE::s_time( parts[4] );		# time of record
	local node = AUDITD_CORE::s_string( parts[5] );
	#
	local ses = AUDITD_CORE::s_int( parts[6] );
	local auid = AUDITD_CORE::s_string( parts[7] );
	local egid = AUDITD_CORE::s_string( parts[8] );
	local euid = AUDITD_CORE::s_string( parts[9] );
	local fsgid = AUDITD_CORE::s_string( parts[10] );
	local fsuid = AUDITD_CORE::s_string( parts[11] );
	local gid = AUDITD_CORE::s_string( parts[12] );
	local suid = AUDITD_CORE::s_string( parts[13] );
	local sgid = AUDITD_CORE::s_string( parts[14] );
	local uid = AUDITD_CORE::s_string( parts[15] );
	local pid = AUDITD_CORE::s_int( parts[16] );
	local success = AUDITD_CORE::s_string( parts[17] );
	local ext = AUDITD_CORE::s_string( parts[18] );
	local terminal = AUDITD_CORE::s_string( parts[19] );
	local exe = AUDITD_CORE::s_string( parts[20] );
	#local msg = AUDITD_CORE::s_string( parts[21] );
	local msg = AUDITD_CORE::s_string("NODATA");

	event auditd_user(index$data, action$data, ts$data, node$data, ses, pid, auid$data, euid$data, egid$data, fsuid$data, fsgid$data, suid$data, sgid$data, uid$data, gid$data, exe$data, terminal$data, success$data, ext$data, msg$data);
	return 0;
	}

redef dispatcher += {
	["EXECVE_OBJ"] = execve_f,
	["GENERIC_OBJ"] = generic_f,
	["PLACE_OBJ"] = place_f,
	["SADDR_OBJ"] = saddr_f,
	["SYSCALL_OBJ"] = syscall_f,
	["USER_OBJ"] = user_f,
	};

event line(description: Input::EventDescription, tpe: Input::Event, LV: lineVals)
	{
	# Each line is fed to this event where it is digested and sent to the dispatcher 
	#  for appropriate processing

	# Data line looks like:
	# 9:1 SYSCALL_OBJ SYSCALL 1357669891.416 mndlint01 ...
	# ID, GENERAL-TYPE, TYPE, TIME, HOST ...
	# Each of the general types has a given structure, and the index ties all
	#  related 
	local parts = split(LV$d, kv_splitter);

	local event_name = "NULL";

	# the event line needs to have a minimum number of space delimited fields
	#   if they are not here, skip the line
	if ( |parts| > 7 ) {
		event_name = parts[2];

		if ( event_name in dispatcher ) 
			dispatcher[event_name](LV$d);
		}

	}


event init_datastream()
	{
	if ( DATANODE && (file_size(data_file) != -1.0) ) {
		Input::add_event([$source=data_file, $reader=Input::READER_RAW, $mode=Input::TSTREAM, $name="auditd", $fields=lineVals, $ev=line]);
		}	

	}

event bro_init()
	{
	schedule 1 sec { init_datastream() };
	}

