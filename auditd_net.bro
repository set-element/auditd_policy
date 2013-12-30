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

	type Info: record {
		# 

		};

	### ----- Data Structs ----- ###
	# Interesting problem here in that we are looking for
	#   correlations between two partial conn_id objects.
	#   [sip,sp] -> [dip,dp] :: index [dip,dp] of 
	type conn_obj: record {
		orig_h: addr; 	#
		orig_p: port; 	#
		ts: time; 	# timstamp of initial data point
		node: string; 	# node which can be mapped via static table 

		# id - just tie identifiers together
		net_identity: string &default="NULL";
		sys_identity: string &default="NULL";
		#
		tie_identity: string &default="NULL";
		};

	type dest_set: record {
		# the index here is the source address since there is no real
		#  way to determine the source port from a normal system call.
		dst_set: table[string] of conn_obj;
		};

	# And now a place to put the dest_set
	global dest_library: table[string] of dest_set;

	# table mapping [node] <-> [ip]
	global node_to_ip: table[string] of ip;
	global ip_to_node: table[ip] of string;

	### ----- Config ----- ###
	global filter_tcp_only = T &redef;

	### ----- Event/Functions ----- ###
	# Value from audit side
	global audit_conn_register function(cid: conn_id, inf: Info) : count;
	# Value from net side
	global net_conn_register function(c: connection) : count;

	# A little somthing to tie them all together
	global conn_collate

	} # end export


### ----- # ----- ###
#      Functions
### ----- # ----- ###

function audit_conn_register(cid: conn_id, inf: Info) : count
	{
	local ret_val = 0;


	return ret_val;
	} # syscall_connection end

function net_conn_register(c: connection) : count
	{


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

	if ( _type == 1 ) {
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
		t_co$resp_p = cid$resp_h;

		if ( _type == 1 )
			t_co$sys_identity = identity;
		else
			t_co$net_identity = identity;

		t_co$tie_identity = uniq_id();
		t_co$ts = ts;

		# now drop the t_co in to the t_ds
		t_ds[ds_index] = t_co;
		
		# and finally register the t_ds into the dest_library
		dest_library[lib_index] = t_ds;
		} # end index_id !in dest_library
	else {
		# index_id is in the dest_library
		t_ds = dest_library[lib_index];

		# Since t_ds can hold (many) t_co objects - ie many systems might
		#   be connecting to the same service on the same host - we need to 
		#   do a little cheking here.
		#
		if ( ds_index in t_ds ) {

			# If there is one value we test and are happy, else we
			#   dig and suffer
			if ( |t_ds[ds_index]| == 1 ) {
 
				# The t_co object just might be there 
				t_co = t_ds[ds_index];

				if ( abs( t_co$ts - ts ) <= time_window ) {

					# XXX fill then LOG!
					}
				}
			else {
				# mmmm, dig dig dig
				local s: table[string] of conn_obj;
				s = t_ds[ds_index];

				for ( i in s ) {

					if ( abs( s[i]$ts - ts ) <= time_window ) {

						}
					}


				}

		} # end index_id in dest_library
	} # end function


### ----- # ----- ###
#      Events
### ----- # ----- ###
event bro_init() &priority = 5
{
	  Log::create_stream(AUDITD_NET::LOG, [$columns=Info]);
}

