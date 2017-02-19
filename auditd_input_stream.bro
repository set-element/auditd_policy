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

        redef enum Notice::Type += {
                AUDITD_INPUT_LowTransactionRate,
                AUDITD_INPUT_HighTransactionRate,
		AUDITD_INPUT_DataReset,
                };

	redef InputAscii::empty_field = "EMPTY";
	global kv_splitter: pattern = / /;

	type lineVals: record {
		d: string;
	};

	const data_file = "/" &redef;
	const DATANODE = F &redef;

	const fluentd_offset = 1 &redef;
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

	# semiphore for in-fr restart
	global stop_sem = 0;

	global start_reader: event();
	global stop_reader: event();

	}

function execve_f(data: string) : count
	{
	# data format:
	# 1492:2 EXECVE_OBJ EXECVE 1357649135.905 3 %20/bin/csh%20-f%20/usr/common/usg/bin/nersc_host
	# NERSCAUD 11193291:5:2 EXEC_OBJ EXECVE 1473900370.877 crt-insec-w1.nersc.gov 56408 8809 2 NULL
	local parts = split_string(data, kv_splitter);

	#if ( |parts| < 7 ) {
	#	print fmt("execve_f parse error for %s", data);
	#	return 1;
	#	}

	local index = AUDITD_CORE::s_string( parts[0+fluentd_offset] );		# form a:b, a=action count, b=which record in action
	local flavor = AUDITD_CORE::s_string( parts[1+fluentd_offset] );	# base object type
	local action = AUDITD_CORE::s_string( parts[2+fluentd_offset] );	# the thing that happens, also called 'event' in traditional auditd docs
	local ts = AUDITD_CORE::s_time( parts[3+fluentd_offset] );		# time of record
	local node = AUDITD_CORE::s_string( parts[4+fluentd_offset] );
	local ses = AUDITD_CORE::s_int( parts[5+fluentd_offset] );		# login session ID
	local pid = AUDITD_CORE::s_int( parts[6+fluentd_offset] );		# Process id
	#
	local argc = AUDITD_CORE::s_int( parts[7+fluentd_offset] );		# number of arguments for exec (starts at 1)
	local argument = AUDITD_CORE::s_string( parts[8+fluentd_offset] );	# total argument string

	event AUDITD_CORE::auditd_execve(index$data, action$data, ts$data, node$data, ses, pid, argc, argument$data);

	#event AUDITD_CORE::auditd_execve(index, action, ts, node, ses, pid, argc, argument);

	return 0;
	}

function generic_f(data: string) : count
	{
	# 65465:2 GENERIC_OBJ FD_PAIR 1357648201.328 mndlint01 0 NULL NULL NULL NULL NULL NULL -1 -1 -1 -1 -1 -1
	# -1 -1 -1 -1 NULL NULL NULL 0
	local parts = split_string(data, kv_splitter);

	#if ( |parts| < 25 ) {
	#	print fmt("generic_f parse error for %s", data);
	#	return 1;
	#	}

	local index = AUDITD_CORE::s_string( parts[0+fluentd_offset] );	# form a:b, a=action count, b=which record in action
	local flavor = AUDITD_CORE::s_string( parts[1+fluentd_offset] );	# base object type
	local action = AUDITD_CORE::s_string( parts[2+fluentd_offset] );	# the thing that happens, also called 'event' in traditional auditd docs
	local ts = AUDITD_CORE::s_time( parts[3+fluentd_offset] );		# time of record
	local node = AUDITD_CORE::s_string( parts[4+fluentd_offset] );	# host data originated from
	#
	local auid = AUDITD_CORE::s_string( parts[5+fluentd_offset] );
	local key = AUDITD_CORE::s_string( parts[6+fluentd_offset] ); 
	local comm = AUDITD_CORE::s_string( parts[7+fluentd_offset] );
	local exe = AUDITD_CORE::s_string( parts[8+fluentd_offset] );
	local a0 = AUDITD_CORE::s_string( parts[9+fluentd_offset] );
	local a1 = AUDITD_CORE::s_string( parts[10+fluentd_offset] );
	local a2 = AUDITD_CORE::s_string( parts[11+fluentd_offset] );
	local uid = AUDITD_CORE::s_string( parts[12+fluentd_offset] );
	local gid = AUDITD_CORE::s_string( parts[13+fluentd_offset] );
	local euid = AUDITD_CORE::s_string( parts[14+fluentd_offset] );
	local egid = AUDITD_CORE::s_string( parts[15+fluentd_offset] );
	local fsuid = AUDITD_CORE::s_string( parts[16+fluentd_offset] );
	local fsgid = AUDITD_CORE::s_string( parts[17+fluentd_offset] );
	local suid = AUDITD_CORE::s_string( parts[18+fluentd_offset] );
	local sgid = AUDITD_CORE::s_string( parts[19+fluentd_offset] );
	local pid = AUDITD_CORE::s_int( parts[20+fluentd_offset] );
	local ppid = AUDITD_CORE::s_int( parts[21+fluentd_offset] );
	local ses = AUDITD_CORE::s_int( parts[22+fluentd_offset] );
	local tty = AUDITD_CORE::s_string( parts[23+fluentd_offset] );
	local terminal = AUDITD_CORE::s_string( parts[24+fluentd_offset] );
	local success = AUDITD_CORE::s_string( parts[25+fluentd_offset] );

	local ext: AUDITD_CORE::string_return;
	ext$data = "NULL";

	#if ( |parts| > 26 ) {
	#	ext = AUDITD_CORE::s_string( parts[26+fluentd_offset] );	
	#	print fmt("parts = %s ; %s", |parts|, parts[27] );
	#	}
	#else
	#	ext = AUDITD_CORE::s_string("NULL");
		
	event AUDITD_CORE::auditd_generic(index$data, action$data, ts$data, node$data, ses, pid, auid$data, comm$data, exe$data, a0$data, a1$data, a2$data, uid$data, gid$data, euid$data, egid$data, fsuid$data, fsgid$data, suid$data, sgid$data, ppid, tty$data, terminal$data, success$data, ext$data);

	return 0;
	}

function place_f(data: string) : count
	{
	# 13:2 PLACE_OBJ CWD 1357669891.417 mndlint01 /chos/global/project/projectdirs/mendel/ganglia NULL -1 -1
	# 13:3 PLACE_OBJ PATH 1357669891.417 mndlint01 NULL rrds/Mendel%20Compute/mc0867.nersc.gov/.cpu_idle.rrd.
	#                       6ITCyp 252651183 0100600 unknown(65534) unknown(65533)
	# NERSCAUD 11193291:5:3 PLACE_OBJ CWD 1473900370.877 crt-insec-w1.nersc.gov 56408 8809 %2Froot (null) NULL (null) NULL NULL
	# NERSCAUD 11193291:5:4 PLACE_OBJ PATH 1473900370.877 crt-insec-w1.nersc.gov 56408 8809 (null) %2Fbin%2Fcat 1048628 file%2C755 root root
	local parts = split_string(data, kv_splitter);

	#if ( |parts| < 11 ) {
	#	print fmt("place_f parse error for %s", data);
	#	return 1;
	#	}
	local index = AUDITD_CORE::s_string( parts[0+fluentd_offset] );	# form a:b, a=action count, b=which record in action
	local flavor = AUDITD_CORE::s_string( parts[1+fluentd_offset] );	# base object type
	local action = AUDITD_CORE::s_string( parts[2+fluentd_offset] );	# the thing that happens, also called 'event' in traditional auditd docs
	local ts = AUDITD_CORE::s_time( parts[3+fluentd_offset] );		# time of record
	local node = AUDITD_CORE::s_string( parts[4+fluentd_offset] );	# host data originated from
	local ses = AUDITD_CORE::s_int( parts[5+fluentd_offset] );
	local pid = AUDITD_CORE::s_int( parts[6+fluentd_offset] );
	#
	local cwd = AUDITD_CORE::s_string( parts[7+fluentd_offset] );
	local path_name = AUDITD_CORE::s_string( parts[8+fluentd_offset] );
	local inode = AUDITD_CORE::s_int( parts[9+fluentd_offset] );
	local mode = AUDITD_CORE::s_int( parts[10+fluentd_offset] );
	local ouid = AUDITD_CORE::s_string( parts[11+fluentd_offset] );
	local ogid = AUDITD_CORE::s_string( parts[12+fluentd_offset] );

	event AUDITD_CORE::auditd_place(index$data, action$data, ts$data, node$data, ses, pid, cwd$data, path_name$data, inode, mode, ouid$data, ogid$data);
	return 0;
	}

function saddr_f(data: string) : count
	{
	# 1433:2 SADDR_OBJ SOCKADDR 1357670401.886 netlink%20pid%3A0
	# 24142:2 SADDR_OBJ SOCKADDR 1357648977.688 inet%20host%3A208.45.140.197%20serv%3A80
	# 6631974:2:2 SADDR_OBJ SOCKADDR 1430353738.133 orange-m.nersc.gov 64003 8055 inet%20host%3A127.0.0.1%20serv%3A53
	local parts = split_string(data, kv_splitter);

	#if ( |parts| < 7 ) {
	#	print fmt("saddr_f parse error for %s", data);
	#	return 1;
	#	}
	local index = AUDITD_CORE::s_string( parts[0+fluentd_offset] );	# form a:b, a=action count, b=which record in action
	local flavor = AUDITD_CORE::s_string( parts[1+fluentd_offset] );	# base object type
	local action = AUDITD_CORE::s_string( parts[2+fluentd_offset] );	# the thing that happens, also called 'event' in traditional auditd docs
	local ts = AUDITD_CORE::s_time( parts[3+fluentd_offset] );		# time of record
	local node = AUDITD_CORE::s_string( parts[4+fluentd_offset] );	# host data originated from
	local ses = AUDITD_CORE::s_int( parts[5+fluentd_offset] );
	local pid = AUDITD_CORE::s_int( parts[6+fluentd_offset] );
	#
	local saddr = AUDITD_CORE::s_string( parts[7+fluentd_offset] );	# address object (local or inet)

	event AUDITD_CORE::auditd_saddr(index$data, action$data, ts$data, node$data, ses, pid, saddr$data);
	return 0;
	}

function syscall_f(data: string) : count
	{
	# 9:1 SYSCALL_OBJ SYSCALL 1357669891.416 mndlint01 root chmod SYS_FILE_PERM rsync /usr/bin/rsync 7ffff282
	#                           1570 1a4 8000 root root root root root root root root 19220 19206 NO_TTY chmod yes 0
	local parts = split_string(data, kv_splitter);

	#if ( |parts| < 25 ) {
	#	print fmt("syscall_f parse error for %s", data);
	#	return 1;
	#	}
	local index = AUDITD_CORE::s_string( parts[0+fluentd_offset] );	# form a:b, a=action count, b=which record in action
	local flavor = AUDITD_CORE::s_string( parts[1+fluentd_offset] );	# base object type
	local action = AUDITD_CORE::s_string( parts[2+fluentd_offset] );	# the thing that happens, also called 'event' in traditional auditd docs
	local ts = AUDITD_CORE::s_time( parts[3+fluentd_offset] );		# time of record
	local node = AUDITD_CORE::s_string( parts[4+fluentd_offset] );
	#
	local ses = AUDITD_CORE::s_int( parts[5+fluentd_offset] );		# login session ID
	local auid = AUDITD_CORE::s_string( parts[6+fluentd_offset] );
	local syscall = AUDITD_CORE::s_string( parts[7+fluentd_offset] );
	local key = AUDITD_CORE::s_string( parts[8+fluentd_offset] ); 
	local comm = AUDITD_CORE::s_string( parts[9+fluentd_offset] );
	local exe = AUDITD_CORE::s_string( parts[10+fluentd_offset] );
	local a0 = AUDITD_CORE::s_string( parts[11+fluentd_offset] );
	local a1 = AUDITD_CORE::s_string( parts[12+fluentd_offset] );
	local a2 = AUDITD_CORE::s_string( parts[13+fluentd_offset] );
	local uid = AUDITD_CORE::s_string( parts[14+fluentd_offset] );
	local gid = AUDITD_CORE::s_string( parts[15+fluentd_offset] );
	local euid = AUDITD_CORE::s_string( parts[16+fluentd_offset] );
	local egid = AUDITD_CORE::s_string( parts[17+fluentd_offset] );
	local fsuid = AUDITD_CORE::s_string( parts[18+fluentd_offset] );
	local fsgid = AUDITD_CORE::s_string( parts[19+fluentd_offset] );
	local suid = AUDITD_CORE::s_string( parts[20+fluentd_offset] );
	local sgid = AUDITD_CORE::s_string( parts[21+fluentd_offset] );
	local pid = AUDITD_CORE::s_int( parts[22+fluentd_offset] );
	local ppid = AUDITD_CORE::s_int( parts[23+fluentd_offset] );
	local tty = AUDITD_CORE::s_string( parts[24+fluentd_offset] );
	#local terminal = AUDITD_CORE::s_string( parts[24+fluentd_offset] );
	local success = AUDITD_CORE::s_string( parts[25+fluentd_offset] );
	local ext = AUDITD_CORE::s_string( parts[26+fluentd_offset] );

	event AUDITD_CORE::auditd_syscall(index$data, action$data, ts$data, node$data, ses, pid, auid$data, syscall$data, key$data, comm$data, exe$data, a0$data, a1$data, a2$data, uid$data, gid$data, euid$data, egid$data, fsuid$data, fsgid$data, suid$data, sgid$data, ppid, tty$data, success$data, ext$data);
	return 0;
	}

function user_f(data: string) : count
	{
	# 2500:1 USER_OBJ USER_ACCT 1357649165.26 mndlint01 0 scottc -1 -1 -1 -1 -1 -1 -1 scottc NULL 0 /chos/dev
	#                           /pts/1 /bin/su
	local parts = split_string(data, kv_splitter);

	#if ( |parts| < 8 ) {
	#	print fmt("user_f parse error for %s", data);
	#	return 1;
	#	}
	local index = AUDITD_CORE::s_string( parts[0+fluentd_offset] );	# form a:b, a=action count, b=which record in action
	local flavor = AUDITD_CORE::s_string( parts[1+fluentd_offset] );	# base object type
	local action = AUDITD_CORE::s_string( parts[2+fluentd_offset] );	# the thing that happens, also called 'event' in traditional auditd docs
	local ts = AUDITD_CORE::s_time( parts[3+fluentd_offset] );		# time of record
	local node = AUDITD_CORE::s_string( parts[4+fluentd_offset] );
	#
	local ses = AUDITD_CORE::s_int( parts[5+fluentd_offset] );
	local auid = AUDITD_CORE::s_string( parts[6+fluentd_offset] );
	local egid = AUDITD_CORE::s_string( parts[7+fluentd_offset] );
	local euid = AUDITD_CORE::s_string( parts[8+fluentd_offset] );
	local fsgid = AUDITD_CORE::s_string( parts[9+fluentd_offset] );
	local fsuid = AUDITD_CORE::s_string( parts[10+fluentd_offset] );
	local gid = AUDITD_CORE::s_string( parts[11+fluentd_offset] );
	local suid = AUDITD_CORE::s_string( parts[12+fluentd_offset] );
	local sgid = AUDITD_CORE::s_string( parts[13+fluentd_offset] );
	local uid = AUDITD_CORE::s_string( parts[14+fluentd_offset] );
	local pid = AUDITD_CORE::s_int( parts[15+fluentd_offset] );
	local success = AUDITD_CORE::s_string( parts[16+fluentd_offset] );
	local ext = AUDITD_CORE::s_string( parts[17+fluentd_offset] );
	local terminal = AUDITD_CORE::s_string( parts[18+fluentd_offset] );
	local exe = AUDITD_CORE::s_string( parts[19+fluentd_offset] );
	#local msg = AUDITD_CORE::s_string( parts[20+fluentd_offset] );
	local msg = AUDITD_CORE::s_string("NODATA");

	event AUDITD_CORE::auditd_user(index$data, action$data, ts$data, node$data, ses, pid, auid$data, euid$data, egid$data, fsuid$data, fsgid$data, suid$data, sgid$data, uid$data, gid$data, exe$data, terminal$data, success$data, ext$data, msg$data);
	return 0;
	}

redef dispatcher += {
	["EXEC_OBJ"] = execve_f,
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
	# NERSCAUD 11192999:2:2 SADDR_OBJ SOCKADDR 1473899932.905 crt-insec-w1.nersc.gov 33878 8715 in
	# 9:1 SYSCALL_OBJ SYSCALL 1357669891.416 mndlint01 ...
	# ID, GENERAL-TYPE, TYPE, TIME, HOST ...
	# Each of the general types has a given structure, and the index ties all
	#  related 
	local parts = split_string(LV$d, kv_splitter);

	local event_name = "NULL";

	# the event line needs to have a minimum number of space delimited fields
	#   if they are not here, skip the line
	if ( |parts| > 7 ) {
		event_name = parts[1 + fluentd_offset];
		
		if ( event_name in dispatcher ) 
			dispatcher[event_name](LV$d);
		else {
			local msg = fmt("BAD EVENT NAME: %s", event_name);
			event reporter_info(network_time(), msg, peer_description);
			}
		}

	}

event stop_reader()
        {

        if ( stop_sem == 0 ) {
                Input::remove("auditd");
                stop_sem = 1;

                NOTICE([$note=AUDITD_INPUT_DataReset,$msg=fmt("stopping reader")]);
                }
        }

event start_reader()
        {
        if ( stop_sem == 1 ) {
                local config_strings: table[string] of string = {
                        ["offset"] = "-1",
                        };

		Input::add_event([$source=data_file, $config=config_strings, $reader=Input::READER_RAW, $mode=Input::STREAM, $name="auditd", $fields=lineVals, $ev=auditdLine]);

                NOTICE([$note=AUDITD_INPUT_DataReset,$msg=fmt("starting reader")]);
                stop_sem = 0;
                }
        }


event transaction_rate()
        {
        # Values for input_count_state:
        #  0=pre-init, 1=ok, 2=in error
        # We make the assumption here that the low_water < high_water
        # Use a global for input_count_delta so that the value is consistent across
        #   anybody looking at it.

	if ( ! DATANODE ) {
		return;
		}

	if ( input_count_prev <  10 ) {
		input_count_prev = input_count;
		schedule input_test_interval { transaction_rate() };
		return;
	}

        input_count_delta = input_count - input_count_prev;
        #print fmt("%s Log delta: %s", network_time(),input_count_delta);

        # rate is too low - send a notice the first time
        if (input_count_delta <= input_low_water) {

                # only send the notice on the first instance
                if ( input_count_state != 2 ) {
                        NOTICE([$note=AUDITD_INPUT_LowTransactionRate,
                                $msg=fmt("event rate %s per %s", input_count_delta, input_test_interval)]);

                        input_count_state = 2; # 2: transaction rate
                        }

                # Now reset the reader
		event reporter_info(network_time(), "stopping reader", peer_description);
                schedule 1 sec { AUDITD_IN_STREAM::stop_reader() };

		event reporter_info(network_time(), "starting reader in 10s", peer_description);
                schedule 10 sec { AUDITD_IN_STREAM::start_reader() };

        	schedule 70 sec { transaction_rate() };
		input_count_prev = input_count;
		return;
                }

        # rate is too high - send a notice the first time
        if (input_count_delta >= input_high_water) {

                # only send the notice on the first instance
                if ( input_count_state != 2 ) {
                        NOTICE([$note=AUDITD_INPUT_HighTransactionRate,
                                $msg=fmt("event rate %s per %s", input_count_delta, input_test_interval)]);

                        input_count_state = 2; # 2: transaction rate
                        }
        	schedule input_test_interval { transaction_rate() };
		input_count_prev = input_count;
		return;
                }

        # rate is ok
	input_count_state = 1;
        schedule input_test_interval { transaction_rate() };
        input_count_prev = input_count;

        }

function init_datastream()
	{
	if ( DATANODE && (file_size(data_file) != -1.0) ) {

		local config_strings: table[string] of string = {
			["offset"] = data_file_offset,
			};

		Input::add_event([$source=data_file, $config=config_strings, $reader=Input::READER_RAW, $mode=Input::STREAM, $name="auditd", $fields=lineVals, $ev=auditdLine]);


		# start rate monitoring for event stream
		event reporter_info(network_time(), "init input_test_interval", peer_description);
		schedule input_test_interval { transaction_rate() };
		}	

	}

event bro_init()
	{
	init_datastream();
	}

