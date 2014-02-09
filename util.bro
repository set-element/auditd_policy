# util.bro  Scott Campbell 11/29/13
# 
# Various utility functions and constants used throughout the auditd infrastructure
#  scripts.  For the time being this is not part of any particular name space 
#  but that will change when things settle out a bit.
#

	### --- ## --- ###
	# Data structs and constants
	### --- ## --- ###
	const INFO_NULL  = "NULL";

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

	# End of data structs

	## regx to test data types
	global kv_splitter: pattern = / / &redef;
	global count_match: pattern = /^[0-9]{1,16}$/;
	global int_match: pattern = /^[\-]{0,1}[0-9]{1,16}$/;
	global port_match: pattern  = /^[0-9]{1,5}\/(tcp|udp|icmp)$/;
	global time_match: pattern  = /^[0-9]{9,10}.[0-9]{0,6}$/;
	global ip_match: pattern    = /((\d{1,2})|(1\d{2})|(2[0-4]\d)|(25[0-5]))/;

	global v16: vector of count = vector(2,3,4,5,6,7,8,9,10,11,12,13,14,15,16);
	global v2s: vector of count = vector(2,4,6);

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

## ----- functions ----- ##
#
# utility functions for converting string types to native values
#   as well as the Info and identity data structures and the data
#   tables shared by all other policies ...
#

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


