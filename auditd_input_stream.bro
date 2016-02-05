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
@load host_core/health_check

@load frameworks/communication/listen
@load base/frameworks/input

module AUDITD_IN_STREAM;

export {

        redef enum Notice::Type += {
                AUDITD_INPUT_LowTransactionRate,
                AUDITD_INPUT_HighTransactionRate,
                };

	redef InputAscii::empty_field = "EMPTY";
	global kv_splitter: pattern = / /;

	type lineVals: record {
		d: string;
	};

	const data_file = "/home/bro/logs/RAW/AUDIT_DATA_0" &redef;
	#const data_file = "/tmp/ad" &redef;
	const DATANODE = F &redef;
	# Offset controls the behavior of the file reader.  An offset of "-1" 
	#   will behave like a "tail -0f" command, while a "0" will read the entire 
	#   file before tailing it...
	const data_file_offset = "-1";

	const dispatcher: table[string] of function(_data: string): count &redef;

        # track the transaction rate - notice on transition between low and high water rates
        # this is count per input_test_interval
        const input_count_test = T &redef;
        const input_low_water:count = 1 &redef;
        const input_high_water:count = 10000 &redef;
        const input_test_interval:interval = 60 sec &redef;
        # track input rate ( events/input_test_interval)
        global input_count: count = 1 &redef;
        global input_count_prev: count = 1 &redef;
        global input_count_delta: count = 0 &redef;
        #  0=pre-init, 1=ok, 2=in low error
        global input_count_state: count = 0 &redef;

	}

function execve_f(data: string) : count
	{
	# data format:
	# 1492:2 EXECVE_OBJ EXECVE 1357649135.905 3 %20/bin/csh%20-f%20/usr/common/usg/bin/nersc_host
	local parts = split_string(data, kv_splitter);

	if ( |parts| < 9 ) {
		print fmt("execve_f parse error for %s", data);
		return 1;
		}

	local index = AUDITD_CORE::s_string( parts[0] );	# form a:b, a=action count, b=which record in action
	local flavor = AUDITD_CORE::s_string( parts[1] );	# base object type
	local action = AUDITD_CORE::s_string( parts[2] );	# the thing that happens, also called 'event' in traditional auditd docs
	local ts = AUDITD_CORE::s_time( parts[3] );		# time of record
	local node = AUDITD_CORE::s_string( parts[4] );
	local ses = AUDITD_CORE::s_int( parts[5] );		# login session ID
	local pid = AUDITD_CORE::s_int( parts[6] );		# Process id
	#
	local argc = AUDITD_CORE::s_int( parts[7] );		# number of arguments for exec (starts at 1)
	local argument = AUDITD_CORE::s_string( parts[8] );	# total argument string

	#event auditd_execve(index$data, action$data, ts$data, node$data, ses, pid, argc, argument$data);
	#event AUDITD_CORE::auditd_execve(index, action, ts, node, ses, pid, argc, argument);

	return 0;
	}

function generic_f(data: string) : count
	{
	# 65465:2 GENERIC_OBJ FD_PAIR 1357648201.328 mndlint01 0 NULL NULL NULL NULL NULL NULL -1 -1 -1 -1 -1 -1
	# -1 -1 -1 -1 NULL NULL NULL 0
	local parts = split_string(data, kv_splitter);

	if ( |parts| < 27 ) {
		print fmt("generic_f parse error for %s", data);
		return 1;
		}

	local index = AUDITD_CORE::s_string( parts[0] );	# form a:b, a=action count, b=which record in action
	local flavor = AUDITD_CORE::s_string( parts[1] );	# base object type
	local action = AUDITD_CORE::s_string( parts[2] );	# the thing that happens, also called 'event' in traditional auditd docs
	local ts = AUDITD_CORE::s_time( parts[3] );		# time of record
	local node = AUDITD_CORE::s_string( parts[4] );	# host data originated from
	#
	local auid = AUDITD_CORE::s_string( parts[5] );
	local key = AUDITD_CORE::s_string( parts[6] ); 
	local comm = AUDITD_CORE::s_string( parts[7] );
	local exe = AUDITD_CORE::s_string( parts[8] );
	local a0 = AUDITD_CORE::s_string( parts[9] );
	local a1 = AUDITD_CORE::s_string( parts[10] );
	local a2 = AUDITD_CORE::s_string( parts[11] );
	local uid = AUDITD_CORE::s_string( parts[12] );
	local gid = AUDITD_CORE::s_string( parts[13] );
	local euid = AUDITD_CORE::s_string( parts[14] );
	local egid = AUDITD_CORE::s_string( parts[15] );
	local fsuid = AUDITD_CORE::s_string( parts[16] );
	local fsgid = AUDITD_CORE::s_string( parts[17] );
	local suid = AUDITD_CORE::s_string( parts[18] );
	local sgid = AUDITD_CORE::s_string( parts[19] );
	local pid = AUDITD_CORE::s_int( parts[20] );
	local ppid = AUDITD_CORE::s_int( parts[21] );
	local ses = AUDITD_CORE::s_int( parts[22] );
	local tty = AUDITD_CORE::s_string( parts[23] );
	local terminal = AUDITD_CORE::s_string( parts[24] );
	local success = AUDITD_CORE::s_string( parts[25] );
	local ext = AUDITD_CORE::s_string( parts[26] );	

	event auditd_generic(index$data, action$data, ts$data, node$data, ses, pid, auid$data, comm$data, exe$data, a0$data, a1$data, a2$data, uid$data, gid$data, euid$data, egid$data, fsuid$data, fsgid$data, suid$data, sgid$data, ppid, tty$data, terminal$data, success$data, ext$data);

	return 0;
	}

function place_f(data: string) : count
	{
	# 13:2 PLACE_OBJ CWD 1357669891.417 mndlint01 /chos/global/project/projectdirs/mendel/ganglia NULL -1 -1
	# 13:3 PLACE_OBJ PATH 1357669891.417 mndlint01 NULL rrds/Mendel%20Compute/mc0867.nersc.gov/.cpu_idle.rrd.
	#                       6ITCyp 252651183 0100600 unknown(65534) unknown(65533)
	local parts = split_string(data, kv_splitter);

	if ( |parts| < 13 ) {
		print fmt("place_f parse error for %s", data);
		return 1;
		}
	local index = AUDITD_CORE::s_string( parts[0] );	# form a:b, a=action count, b=which record in action
	local flavor = AUDITD_CORE::s_string( parts[1] );	# base object type
	local action = AUDITD_CORE::s_string( parts[2] );	# the thing that happens, also called 'event' in traditional auditd docs
	local ts = AUDITD_CORE::s_time( parts[3] );		# time of record
	local node = AUDITD_CORE::s_string( parts[4] );	# host data originated from
	local ses = AUDITD_CORE::s_int( parts[5] );
	local pid = AUDITD_CORE::s_int( parts[6] );
	#
	local cwd = AUDITD_CORE::s_string( parts[7] );
	local path_name = AUDITD_CORE::s_string( parts[8] );
	local inode = AUDITD_CORE::s_int( parts[9] );
	local mode = AUDITD_CORE::s_int( parts[10] );
	local ouid = AUDITD_CORE::s_string( parts[11] );
	local ogid = AUDITD_CORE::s_string( parts[12] );

	event auditd_place(index$data, action$data, ts$data, node$data, ses, pid, cwd$data, path_name$data, inode, mode, ouid$data, ogid$data);
	return 0;
	}

function saddr_f(data: string) : count
	{
	# 1433:2 SADDR_OBJ SOCKADDR 1357670401.886 netlink%20pid%3A0
	# 24142:2 SADDR_OBJ SOCKADDR 1357648977.688 inet%20host%3A208.45.140.197%20serv%3A80
	# 6631974:2:2 SADDR_OBJ SOCKADDR 1430353738.133 orange-m.nersc.gov 64003 8055 inet%20host%3A127.0.0.1%20serv%3A53
	local parts = split_string(data, kv_splitter);

	if ( |parts| < 8 ) {
		print fmt("saddr_f parse error for %s", data);
		return 1;
		}
	local index = AUDITD_CORE::s_string( parts[0] );	# form a:b, a=action count, b=which record in action
	local flavor = AUDITD_CORE::s_string( parts[1] );	# base object type
	local action = AUDITD_CORE::s_string( parts[2] );	# the thing that happens, also called 'event' in traditional auditd docs
	local ts = AUDITD_CORE::s_time( parts[3] );		# time of record
	local node = AUDITD_CORE::s_string( parts[4] );	# host data originated from
	local ses = AUDITD_CORE::s_int( parts[5] );
	local pid = AUDITD_CORE::s_int( parts[6] );
	#
	local saddr = AUDITD_CORE::s_string( parts[7] );	# address object (local or inet)

	event auditd_saddr(index$data, action$data, ts$data, node$data, ses, pid, saddr$data);
	return 0;
	}

function syscall_f(data: string) : count
	{
	# 9:1 SYSCALL_OBJ SYSCALL 1357669891.416 mndlint01 root chmod SYS_FILE_PERM rsync /usr/bin/rsync 7ffff282
	#                           1570 1a4 8000 root root root root root root root root 19220 19206 NO_TTY chmod yes 0
	local parts = split_string(data, kv_splitter);

	if ( |parts| < 27 ) {
		print fmt("syscall_f parse error for %s", data);
		return 1;
		}
	local index = AUDITD_CORE::s_string( parts[0] );	# form a:b, a=action count, b=which record in action
	local flavor = AUDITD_CORE::s_string( parts[1] );	# base object type
	local action = AUDITD_CORE::s_string( parts[2] );	# the thing that happens, also called 'event' in traditional auditd docs
	local ts = AUDITD_CORE::s_time( parts[3] );		# time of record
	local node = AUDITD_CORE::s_string( parts[4] );
	#
	local ses = AUDITD_CORE::s_int( parts[5] );		# login session ID
	local auid = AUDITD_CORE::s_string( parts[6] );
	local syscall = AUDITD_CORE::s_string( parts[7] );
	local key = AUDITD_CORE::s_string( parts[8] ); 
	local comm = AUDITD_CORE::s_string( parts[9] );
	local exe = AUDITD_CORE::s_string( parts[10] );
	local a0 = AUDITD_CORE::s_string( parts[11] );
	local a1 = AUDITD_CORE::s_string( parts[12] );
	local a2 = AUDITD_CORE::s_string( parts[13] );
	local uid = AUDITD_CORE::s_string( parts[14] );
	local gid = AUDITD_CORE::s_string( parts[15] );
	local euid = AUDITD_CORE::s_string( parts[16] );
	local egid = AUDITD_CORE::s_string( parts[17] );
	local fsuid = AUDITD_CORE::s_string( parts[18] );
	local fsgid = AUDITD_CORE::s_string( parts[19] );
	local suid = AUDITD_CORE::s_string( parts[20] );
	local sgid = AUDITD_CORE::s_string( parts[21] );
	local pid = AUDITD_CORE::s_int( parts[22] );
	local ppid = AUDITD_CORE::s_int( parts[23] );
	local tty = AUDITD_CORE::s_string( parts[24] );
	#local terminal = AUDITD_CORE::s_string( parts[24] );
	local success = AUDITD_CORE::s_string( parts[25] );
	local ext = AUDITD_CORE::s_string( parts[26] );

	event auditd_syscall(index$data, action$data, ts$data, node$data, ses, pid, auid$data, syscall$data, key$data, comm$data, exe$data, a0$data, a1$data, a2$data, uid$data, gid$data, euid$data, egid$data, fsuid$data, fsgid$data, suid$data, sgid$data, ppid, tty$data, success$data, ext$data);
	return 0;
	}

function user_f(data: string) : count
	{
	# 2500:1 USER_OBJ USER_ACCT 1357649165.26 mndlint01 0 scottc -1 -1 -1 -1 -1 -1 -1 scottc NULL 0 /chos/dev
	#                           /pts/1 /bin/su
	local parts = split_string(data, kv_splitter);

	if ( |parts| < 20 ) {
		print fmt("user_f parse error for %s", data);
		return 1;
		}
	local index = AUDITD_CORE::s_string( parts[0] );	# form a:b, a=action count, b=which record in action
	local flavor = AUDITD_CORE::s_string( parts[1] );	# base object type
	local action = AUDITD_CORE::s_string( parts[2] );	# the thing that happens, also called 'event' in traditional auditd docs
	local ts = AUDITD_CORE::s_time( parts[3] );		# time of record
	local node = AUDITD_CORE::s_string( parts[4] );
	#
	local ses = AUDITD_CORE::s_int( parts[5] );
	local auid = AUDITD_CORE::s_string( parts[6] );
	local egid = AUDITD_CORE::s_string( parts[7] );
	local euid = AUDITD_CORE::s_string( parts[8] );
	local fsgid = AUDITD_CORE::s_string( parts[9] );
	local fsuid = AUDITD_CORE::s_string( parts[10] );
	local gid = AUDITD_CORE::s_string( parts[11] );
	local suid = AUDITD_CORE::s_string( parts[12] );
	local sgid = AUDITD_CORE::s_string( parts[13] );
	local uid = AUDITD_CORE::s_string( parts[14] );
	local pid = AUDITD_CORE::s_int( parts[15] );
	local success = AUDITD_CORE::s_string( parts[16] );
	local ext = AUDITD_CORE::s_string( parts[17] );
	local terminal = AUDITD_CORE::s_string( parts[18] );
	local exe = AUDITD_CORE::s_string( parts[19] );
	#local msg = AUDITD_CORE::s_string( parts[20] );
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

event auditdLine(description: Input::EventDescription, tpe: Input::Event, LV: lineVals)
	{
	# Each line is fed to this event where it is digested and sent to the dispatcher 
	#  for appropriate processing
	++input_count;

	# Data line looks like:
	# 9:1 SYSCALL_OBJ SYSCALL 1357669891.416 mndlint01 ...
	# ID, GENERAL-TYPE, TYPE, TIME, HOST ...
	# Each of the general types has a given structure, and the index ties all
	#  related 
	local parts = split_string(LV$d, kv_splitter);

	local event_name = "NULL";

	# the event line needs to have a minimum number of space delimited fields
	#   if they are not here, skip the line
	if ( |parts| > 7 ) {
		event_name = parts[1];

		if ( event_name in dispatcher ) 
			dispatcher[event_name](LV$d);
		}

	}

event transaction_rate()
        {
        # Values for input_count_state:
        #  0=pre-init, 1=ok, 2=in error
        # We make the assumption here that the low_water < high_water
        # Use a global for input_count_delta so that the value is consistent across
        #   anybody looking at it.
        input_count_delta = input_count - input_count_prev;
        #print fmt("%s Log delta: %s", network_time(),delta);

        # rate is too low - send a notice the first time
        if (input_count_delta <= input_low_water) {

                # only send the notice on the first instance
                if ( input_count_state != 2 ) {
                        NOTICE([$note=AUDITD_INPUT_LowTransactionRate,
                                $msg=fmt("event rate %s per %s", input_count_delta, input_test_interval)]);

                        input_count_state = 2; # 2: transaction rate
                        }

                # Now reset the reader
                #schedule 1 sec { stop_reader() };
                #schedule 10 sec { start_reader() };
                }

        # rate is too high - send a notice the first time
        if (input_count_delta >= input_high_water) {

                # only send the notice on the first instance
                if ( input_count_state != 2 ) {
                        NOTICE([$note=AUDITD_INPUT_HighTransactionRate,
                                $msg=fmt("event rate %s per %s", input_count_delta, input_test_interval)]);

                        input_count_state = 2; # 2: transaction rate
                        }
                }

        # rate is ok
        if ( (input_count_delta > input_low_water) && (input_count_delta < input_high_water) ) {
                input_count_state = 1;
                }

        # rotate values
        input_count_prev = input_count;

	local thh: HOST_HEALTH::Info;

	thh$ts = network_time();
	thh$origin = "AUDITD";
	thh$recPerSec = input_count_delta;
	thh$longLive = |AUDITD_CORE::identityState|;
	thh$shortLive = |AUDITD_CORE::actionState|;

	Log::write(HOST_HEALTH::LOG, thh);

        # reschedule this all over again ...
        #if ( DATANODE )
        #	schedule input_test_interval { transaction_rate() };
        }


function init_datastream()
	{
	if ( DATANODE && (file_size(data_file) != -1.0) ) {

		local config_strings: table[string] of string = {
			["offset"] = data_file_offset,
			};

		Input::add_event([$source=data_file, $config=config_strings, $reader=Input::READER_RAW, $mode=Input::STREAM, $name="auditd", $fields=lineVals, $ev=auditdLine]);


		# start rate monitoring for event stream
		#schedule input_test_interval { transaction_rate() };
		}	

	}

event bro_init()
	{
	init_datastream();
	}

