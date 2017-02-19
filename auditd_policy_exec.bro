# auitd_policy_exec.bro 
# Scott Campbell
# 
# policy related to execution of userspace binaries
#
# Note that this is for all functionality that sits behind 
#   function process_wrapper(inf: AUDITD_CORE::Info) : count

module AUDITD_POLICY;

export {
        redef enum Notice::Type += {
                AUDITD_ExecPathcheck,
                };

        # this tracks rolling execution history of user and is
        #   keyed on the longer lived identity AUDITD_CORE::Info$i$auid value.
        type history_rec: record {
                exec_hist:      vector of string;
                exec_count:     count &default = 0;
                };

        global execution_history_length: count = 5 &redef;
        global execution_history: table[string] of history_rec;

        # -- #

        global clear_exec_hist: event(id: string);

        # # Execution configuration #
        # blacklist of suspicous execution bases
        global exec_blacklist = /^\/dev/ | /^\/var\/run/ &redef;
        global exec_blacklist_test = T &redef;

	global auditd_execve: function(i: AUDITD_CORE::Info);

	}  # end export

# ----- # ----- #
#      Functions
# ----- # ----- #
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

# ----- # ----- #
#      Events
# ----- # ----- #

event clear_exec_hist(id: string)
        {

        if ( id in execution_history ) {
                delete execution_history[id];
                }
        }


