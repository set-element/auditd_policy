# This policy should be loaded on to the cluster node
# which is responsable for processing the raw
# isshd data stream. If the policy is not loaded, the
# input framework will not open the file.
#
# To load, modify the etc/node.cfg so by adding the "aux_scripts"
# directive. For example:
#
# [isshd]
# type=worker
# host=sigma-n
# aux_scripts="isshd_policy/init_node"
#
redef AUDITD_IN_STREAM::DATANODE = T;
