# auitd_policy_kernel.bro
# Scott Campbell
#
# policy related to kernel modification during runtime relating to
#  system calls for:
#  "init_module", "create_module", "query_module", "delete_module"
#

module AUDITD_POLICY;

export {
        redef enum Notice::Type += {
                AUDITD_KernelModLoad,
                AUDITD_KernelModUnoad,
                };

        # -- #

	global kernel_module_process: function(i: AUDITD_CORE::Info);

	}  # end export

function kernel_module_process(i: AUDITD_CORE::Info)
	{
	local syscall = inf$syscall;

	switch( syscall ) {

		case "init_module":
			# init_module - initialize a loadable module entry
			#   init_module() loads the relocated module image into 
			#   kernel space and runs the module’s init function.
			

			break;	

		case "create_module":
			# create_module - create a loadable module entry
			#  create_module()  attempts  to create a loadable module 
			#  entry and reserve the kernel memory that will be needed 
			#  to hold the module.  This system call requires privilege.


			break;

		case "query_module":
			# query_module - query the kernel for various bits pertaining to modules
			#  query_module()  requests information from the kernel about loadable modules.

			break;


		case "delete_module":
			# delete_module - delete a loadable module entry
			#  delete_module() attempts to remove an unused loadable module entry.
			#  This system call requires privilege.


			break;

	} # end kernel_module_process
