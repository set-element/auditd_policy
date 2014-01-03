# Accept connection primitives from auditd_policy::network_register_conn()
#  and identify matching network connections.
#
# An interesting problem is that the syscall will get registered immediatly, while
#  more stateful network data may take a while ...


@load auditd_policy/util

module AUDITD_NET;

export {
	# AUDITD_NET log stream identifier
	redef enum Log::ID += { LOG };

	### ----- Data Structs ----- ###
	# Interesting problem here in that we are looking for
	#   correlations between two partial conn_id objects.
	#   [sip,sp] -> [dip,dp] :: index [dip,dp] of 
	type conn_obj: record {
		orig_h: addr &log; 	#
		orig_p: port &log; 	#
		resp_h: addr &log; 	# These may be redundant w/ dest_set indexing data, but
		resp_p: port &log; 	#   makes our life much simpler having them around ...
		node: string &log; 	# node which can be mapped via static table 
					#
		n_ts: time &log; 	# timstamp of initial net data point
		a_ts: time &log; 	# timstamp of initial audit data point
					#

		# id - just tie identifiers together
		net_identity: string &default="NULL" &log;
		sys_identity: string &default="NULL" &log;
		tie_identity: string &default="NULL" &log;

		note: string &default="NULL" &log;
		};

	type dest_set: record {
		# the index here is the source address since there is no real
		#  way to determine the source port from a normal system call.
		dst_set: table[string] of conn_obj;
		};

	# And now a place to put the dest_set
	global dest_library: table[string] of dest_set;

	# table mapping [node] <-> [ip]
	global node_to_ip: table[string] of addr;
	global ip_to_node: table[addr] of string;

	### ----- Config and Constants----- ###
	global filter_tcp_only = T &redef;
	const AUDIT_DATA = 1;
	const NET_DATA = 2;
	global time_window:double = 2.0 &redef;

	### ----- Event/Functions ----- ###
	# Value from audit side
	global audit_conn_register: function(cid: conn_id, inf: Info) : count;
	# Value from net side
	global net_conn_register: function(id: conn_id, ts: time, uid: string) : count;
	global conn_collate: function(cid: conn_id, identity: string, _type: count, ts: time, node: string) : string;

	# A little somthing to tie them all together
	#global conn_collate

	} # end export


### ----- # ----- ###
#      Functions
### ----- # ----- ###
function abs(d: double) : double
	{
	return sqrt(d*d);
	}

function audit_conn_register(cid: conn_id, inf: Info) : count
	{
	local ret_val = 0;
	conn_collate(cid, inf$i$idv[v_auid], AUDIT_DATA, inf$ts, inf$i$node); 

	return ret_val;
	} # syscall_connection end

function net_conn_register(id: conn_id, ts: time, uid: string) : count
	{
	local ret_val = 0;

	conn_collate(id, uid, NET_DATA, ts, ip_to_node[id$orig_h]); 

	return ret_val;
	}


# identity is uniq_id() value, _type is {1==audit, 2==net}
#
function conn_collate(cid: conn_id, identity: string, _type: count, ts: time, node: string) : string
	{
	local ret_val = "NULL";

	# generate the index identity
	# the values have to exist to get this far ...
	local lib_index = fmt("%s%s", cid$resp_h, cid$resp_p);

	local t_ds: dest_set;
	local t_co: conn_obj;

	# dest_set index needs to be calculated
	local ds_index: string;

	if ( _type == AUDIT_DATA ) {
		# need to look up address
		if ( node in node_to_ip ) 
			ds_index = fmt("%s", node_to_ip[node]);
		else
			# This kinda sucks
			ds_index = "0.0.0.0";
		}
	else
		# net type so we can trust the value of orig_h
		ds_index = fmt("%s", cid$orig_h);


	if ( lib_index !in dest_library )
		{
		# There is no dest ip:port pair, so we
		# need to build the whole object set...
		 
		# Start with the conn_obj
		t_co$resp_h = cid$resp_h;
		t_co$resp_p = cid$resp_p;

		if ( _type == AUDIT_DATA ) {
			t_co$sys_identity = identity;
			t_co$orig_h = node_to_ip[node];
			t_co$a_ts = ts;
			}
		else {
			t_co$net_identity = identity;
			t_co$orig_h = cid$orig_h;
			t_co$orig_p = cid$orig_p;
			t_co$n_ts = ts;
			}

		t_co$tie_identity = unique_id("");

		# now drop the t_co in to the t_ds
		# 	
		t_ds$dst_set[ds_index] = t_co;
		
		# and finally register the t_ds into the dest_library
		dest_library[lib_index] = t_ds;
		ret_val = identity;

		} # end index_id !in dest_library
	else {
		# index_id is in the dest_library
		t_ds = dest_library[lib_index];

		# Since t_ds can hold (many) t_co objects - ie many systems might
		#   be connecting to the same service on the same host - we need to 
		#   do a little cheking here.
		#
		if ( ds_index in t_ds$dst_set ) {

			# calc dt
			local dt = _type == AUDIT_DATA ? ( abs(time_to_double(t_co$n_ts) - time_to_double(ts)) ) : ( abs(time_to_double(t_co$a_ts) - time_to_double(ts)) );

			# If there is one value we test and are happy, else we
			#   dig and suffer
			if ( |t_ds$dst_set| == 1 ) {
 
				# The t_co object just might be there 
				t_co = t_ds$dst_set[ds_index];

				if ( _type == AUDIT_DATA ) {
					t_co$a_ts = ts;
					t_co$sys_identity = identity;
					}
				else {
					t_co$n_ts = ts;
					t_co$net_identity = identity;
					}
					
				if ( abs(time_to_double(t_co$n_ts) - time_to_double(t_co$a_ts)) <= time_window ) {

					Log::write(LOG, t_co);
					delete t_ds$dst_set[ds_index];

					}
				}
			else {
				# mmmm, dig dig dig
				local s: table[string] of conn_obj;
				s = t_ds$dst_set;

				for ( i in s ) {

					local dtx = _type == AUDIT_DATA ? ( abs(time_to_double(s[i]$n_ts) - time_to_double(ts)) ) : ( abs(time_to_double(s[i]$a_ts) - time_to_double(ts)) );

					# take first conenction within the time_window frame
					if ( dtx <= time_window ) {
						t_co = s[i];

						if ( _type == AUDIT_DATA ) {
							t_co$a_ts = ts;
							t_co$sys_identity = identity;
							}
						else {
							t_co$n_ts = ts;
							t_co$net_identity = identity;
							}
						Log::write(LOG, s[i]);

						ret_val = s[i]$tie_identity;
						delete t_ds$dst_set[i];

						} # dt < time_window
					} # END: for i in s
				} # END: multi responses 
		} # end index_id in dest_library

	return ret_val;
	} # end function

} # ?!?!?!?!
### ----- # ----- ###
#      Events
### ----- # ----- ###
event bro_init() &priority = 5
{
	  Log::create_stream(AUDITD_NET::LOG, [$columns=Info]);
}

