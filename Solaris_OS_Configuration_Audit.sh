#!/bin/bash

# Script Name: Solaris OS V_11.4 Security Configuration Review
# Author: Bhupendra Singh Sisodiya  
# Purpose: To systematically review and enhance Solaris security configurations review

# Function to display prompts with a separator
prompt() {
  echo "========================================================"
}

# Redirect output to a file
exec > security_review_output.txt

# Prompt 1: Use the Latest Package Updates
prompt
echo "1. Use the Latest Package Updates"
pkg update -n
prompt

# Prompt 2: Configure TCP Wrappers
prompt
echo "2. Configure TCP Wrappers"
inetadm -p | grep tcp_wrappers
ls /etc/hosts.deny
ls /etc/hosts.allow
prompt

# Prompt 3: Disable Local-only Graphical Login Environment
prompt
echo "3. Disable Local-only Graphical Login Environment"
svcs -Ho state svc:/application/graphical-login/gdm:default
prompt

# Prompt 4: Configure sendmail Service for Local-Only Mode
prompt
echo "4. Configure sendmail Service for Local-Only Mode"
netstat -an | grep LIST | grep ":25[[:space:]]"
prompt

# Prompt 5: Disable RPC Encryption Key
prompt
echo "5. Disable RPC Encryption Key"
svcs -Ho state svc:/network/rpc/keyserv
prompt

# Prompt 6: Configure sendmail Service for Local-Only Mode (Additional Check)
prompt
echo "6. Configure sendmail Service for Local-Only Mode (Additional Check)"
netstat -an | grep LIST | grep ".25 "
netstat -an | grep LIST | grep ".587 "
prompt

# Prompt 7: Disable Generic Security Services (GSS)
prompt
echo "7. Disable Generic Security Services (GSS)"
svcs -Ho state svc:/network/rpc/gss
prompt

# Prompt 8: Disable Apache Service
prompt
echo "8. Disable Apache Service"
svcs -Ho state svc:/network/http:apache24
prompt

# Prompt 9: Disable Kerberos TGT Expiration Warning
prompt
echo "9. Disable Kerberos TGT Expiration Warning"
svcs -Ho state svc:/network/security/ktkt_warn
prompt

# Prompt 10: Disable NIS Client Services
prompt
echo "10. Disable NIS Client Services"
svcs -Ho state svc:/network/nis/client
prompt

# Prompt 11: Disable Removable Volume Manager
prompt
echo "11. Disable Removable Volume Manager"
svcs -Ho state svc:/system/filesystem/rmvolmgr
svcs -Ho state svc:/network/rpc/smserver
prompt

# Prompt 12: Disable automount Service
prompt
echo "12. Disable automount Service"
svcs -Ho state svc:/system/filesystem/autofs
prompt

# Prompt 13: Ensure telnet server is not enabled
prompt
echo "13. Ensure telnet server is not enabled"
svcs -Ho state svc:/network/telnet
prompt

# Prompt 14: Disable Response to Broadcast ICMPv4 Echo Request
prompt
echo "14. Disable Response to Broadcast ICMPv4 Echo Request"
ipadm show-prop -p _respond_to_echo_broadcast -co current ip
ipadm show-prop -p _respond_to_echo_broadcast -co persistent ip
prompt

# Prompt 15: Disable Response to ICMP Broadcast Netmask Requests
prompt
echo "15. Disable Response to ICMP Broadcast Netmask Requests"
ipadm show-prop -p _respond_to_address_mask_broadcast -co current ip
ipadm show-prop -p _respond_to_address_mask_broadcast -co persistent ip
prompt

# Prompt 16: Enable Strong TCP Sequence Number Generation
prompt
echo "16. Enable Strong TCP Sequence Number Generation"
grep "^TCP_STRONG_ISS=" /etc/default/inetinit
echo "To verify this setting is in effect on the running system, use the command:"
echo "# ipadm show-prop -p _strong_iss -co current tcp"
prompt

# Prompt 17: Disable Response to ICMP Broadcast Timestamp Requests
prompt
echo "17. Disable Response to ICMP Broadcast Timestamp Requests"
ipadm show-prop -p _respond_to_timestamp_broadcast -co current ip
ipadm show-prop -p _respond_to_timestamp_broadcast -co persistent ip
prompt

# Prompt 18: Disable Source Packet Forwarding
prompt
echo "18. Disable Source Packet Forwarding"
ipadm show-prop -p _forward_src_routed -co current ipv4
ipadm show-prop -p _forward_src_routed -co persistent ipv4
ipadm show-prop -p _forward_src_routed -co current ipv6
ipadm show-prop -p _forward_src_routed -co persistent ipv6
prompt

# Prompt 19: Disable Directed Broadcast Packet Forwarding
prompt
echo "19. Disable Directed Broadcast Packet Forwarding"
ipadm show-prop -p _forward_directed_broadcasts -co current ip
ipadm show-prop -p _forward_directed_broadcasts -co persistent ip
prompt

# Prompt 20: Restrict Core Dumps to Protected Directory
prompt
echo "20. Restrict Core Dumps to Protected Directory"
coreadm
ls -ld /var/share/cores
prompt

# Prompt 21: Disable Response to ICMP Timestamp Requests
prompt
echo "21. Disable Response to ICMP Timestamp Requests"
ipadm show-prop -p _respond_to_timestamp -co current ip
ipadm show-prop -p _respond_to_timestamp -co persistent ip
prompt

# Prompt 22: Disable Response to Multicast Echo Request
prompt
echo "22. Disable Response to Multicast Echo Request"
ipadm show-prop -p _respond_to_echo_multicast -co current ipv4
ipadm show-prop -p _respond_to_echo_multicast -co persistent ipv4
prompt

# Prompt 23: Ignore ICMP Redirect Messages
prompt
echo "23. Ignore ICMP Redirect Messages"
ipadm show-prop -p _ignore_redirect -co current ipv4
ipadm show-prop -p _ignore_redirect -co persistent ipv4
prompt

# Prompt 24: Set Strict Multihoming
prompt
echo "24. Set Strict Multihoming"
ipadm show-prop -p _strict_dst_multihoming -co current ipv4
ipadm show-prop -p _strict_dst_multihoming -co persistent ipv4
echo "To verify this setting for IPv6 packets, use the commands:"
echo "# ipadm show-prop -p _strict_dst_multihoming -co current ipv6"
echo "# ipadm show-prop -p _strict_dst_multihoming -co persistent ipv6"
prompt

# Prompt 25: Disable ICMP Redirect Messages
prompt
echo "25. Disable ICMP Redirect Messages"
ipadm show-prop -p send_redirects -co current ipv4
ipadm show-prop -p send_redirects -co persistent ipv4
prompt

# Prompt 26: Disable TCP Reverse IP Source Routing
prompt
echo "26. Disable TCP Reverse IP Source Routing"
ipadm show-prop -p _rev_src_routes -co current tcp
ipadm show-prop -p _rev_src_routes -co persistent tcp
prompt

# Prompt 27: Set Maximum Number of Half-open TCP Connections
prompt
echo "27. Set Maximum Number of Half-open TCP Connections"
ipadm show-prop -p _conn_req_max_q -co current tcp
ipadm show-prop -p _conn_req_max_q -co persistent tcp
prompt

# Prompt 28: Set Maximum Number of TCP Retransmission Attempts
prompt
echo "28. Set Maximum Number of TCP Retransmission Attempts"
ipadm show-prop -p _tcp_rexmit_max -co current tcp
ipadm show-prop -p _tcp_rexmit_max -co persistent tcp
prompt

# Prompt 29: Set Maximum Number of TCP Connect Requests per Second
prompt
echo "29. Set Maximum Number of TCP Connect Requests per Second"
ipadm show-prop -p _tcp_conn_req_max_q -co current tcp
ipadm show-prop -p _tcp_conn_req_max_q -co persistent tcp
prompt

# Prompt 30: Set Maximum Number of Connection Requests
prompt
echo "30. Set Maximum Number of Connection Requests"
ipadm show-prop -p _conn_req_max_q -co current tcp
ipadm show-prop -p _conn_req_max_q -co persistent tcp
prompt

# Prompt 31: Enable Source Port Randomization
prompt
echo "31. Enable Source Port Randomization"
ipadm show-prop -p _conn_randomize -co current tcp
ipadm show-prop -p _conn_randomize -co persistent tcp
prompt

# Prompt 32: Disable IPv6 Router Advertisement Daemon
prompt
echo "32. Disable IPv6 Router Advertisement Daemon"
svcs -Ho state svc:/network/ipv6:default
prompt

# Prompt 33: Disable IPv6 Forwarding
prompt
echo "33. Disable IPv6 Forwarding"
ipadm show-prop -p forwarding -co current ipv6
ipadm show-prop -p forwarding -co persistent ipv6
prompt

# Prompt 34: Disable IPv6 Redirects
prompt
echo "34. Disable IPv6 Redirects"
ipadm show-prop -p send_redirects -co current ipv6
ipadm show-prop -p send_redirects -co persistent ipv6
prompt

# Prompt 35: Enable IPv6 Privacy Extensions
prompt
echo "35. Enable IPv6 Privacy Extensions"
ipadm show-prop -p _priv_addr -co current ipv6
ipadm show-prop -p _priv_addr -co persistent ipv6
prompt

# Prompt 36: Set Maximum Number of IPv6 Router Advertisement Requests
prompt
echo "36. Set Maximum Number of IPv6 Router Advertisement Requests"
ipadm show-prop -p _ra_maxinterval -co current ipv6
ipadm show-prop -p _ra_maxinterval -co persistent ipv6
prompt

# Prompt 37: Enable IPv6 Neighbor Discovery
prompt
echo "37. Enable IPv6 Neighbor Discovery"
ipadm show-prop -p _ns_ipprefix -co current ipv6
ipadm show-prop -p _ns_ipprefix -co persistent ipv6
prompt

# Prompt 38: Enable IPv6 Autoconfig on All Interfaces
prompt
echo "38. Enable IPv6 Autoconfig on All Interfaces"
ipadm show-prop -p _auto_config -co current ipv6
ipadm show-prop -p _auto_config -co persistent ipv6
prompt

# Prompt 39: Enable IPv6 Autoconfig on Specific Interfaces
prompt
echo "39. Enable IPv6 Autoconfig on Specific Interfaces"
ipadm show-prop -p _auto_config -co current ipv6
ipadm show-prop -p _auto_config -co persistent ipv6
prompt

# Prompt 40: Enable IPv6 Autoconfig on Specific Interfaces (Additional Check)
prompt
echo "40. Enable IPv6 Autoconfig on Specific Interfaces (Additional Check)"
ipadm show-prop -p _auto_config -co current ipv6
ipadm show-prop -p _auto_config -co persistent ipv6
prompt

# Prompt 41: Enable IPv6 Router Solicitation
prompt
echo "41. Enable IPv6 Router Solicitation"
ipadm show-prop -p _rs_probes -co current ipv6
ipadm show-prop -p _rs_probes -co persistent ipv6
prompt

# Prompt 42: Enable IPv6 Router Solicitation (Additional Check)
prompt
echo "42. Enable IPv6 Router Solicitation (Additional Check)"
ipadm show-prop -p _rs_probes -co current ipv6
ipadm show-prop -p _rs_probes -co persistent ipv6
prompt

# Prompt 43: Enable IPv6 Reverse Path Forwarding
prompt
echo "43. Enable IPv6 Reverse Path Forwarding"
ipadm show-prop -p _ip6_rpf -co current ipv6
ipadm show-prop -p _ip6_rpf -co persistent ipv6
prompt

# Prompt 44: Enable IPv6 Source Address Validation
prompt
echo "44. Enable IPv6 Source Address Validation"
ipadm show-prop -p _src_addr_validate -co current ipv6
ipadm show-prop -p _src_addr_validate -co persistent ipv6
prompt

# Prompt 45: Disable IPv6 Router Solicitation
prompt
echo "45. Disable IPv6 Router Solicitation"
ipadm show-prop -p _rs_probes -co current ipv6
ipadm show-prop -p _rs_probes -co persistent ipv6
prompt

# Prompt 46: Enable IPv6 Router Solicitation (Additional Check)
prompt
echo "46. Enable IPv6 Router Solicitation (Additional Check)"
ipadm show-prop -p _rs_probes -co current ipv6
ipadm show-prop -p _rs_probes -co persistent ipv6
prompt

# Prompt 47: Enable IPv6 Reverse Path Forwarding
prompt
echo "47. Enable IPv6 Reverse Path Forwarding"
ipadm show-prop -p _ip6_rpf -co current ipv6
ipadm show-prop -p _ip6_rpf -co persistent ipv6
prompt

# Prompt 48: Enable IPv6 Source Address Validation
prompt
echo "48. Enable IPv6 Source Address Validation"
ipadm show-prop -p _src_addr_validate -co current ipv6
ipadm show-prop -p _src_addr_validate -co persistent ipv6
prompt

# Prompt 49: Enable IPv6 Source Address Validation (Additional Check)
prompt
echo "49. Enable IPv6 Source Address Validation (Additional Check)"
ipadm show-prop -p _src_addr_validate -co current ipv6
ipadm show-prop -p _src_addr_validate -co persistent ipv6
prompt

# Prompt 50: Disable IPv6 Router Advertisement Daemon (Additional Check)
prompt
echo "50. Disable IPv6 Router Advertisement Daemon (Additional Check)"
svcs -Ho state svc:/network/ipv6:default
prompt

# Prompt 51: Disable IPv6 Forwarding (Additional Check)
prompt
echo "51. Disable IPv6 Forwarding (Additional Check)"
ipadm show-prop -p forwarding -co current ipv6
ipadm show-prop -p forwarding -co persistent ipv6
prompt

# Prompt 52: Disable IPv6 Redirects (Additional Check)
prompt
echo "52. Disable IPv6 Redirects (Additional Check)"
ipadm show-prop -p send_redirects -co current ipv6
ipadm show-prop -p send_redirects -co persistent ipv6
prompt

# Prompt 53: Create Warnings for Standard Login Services
prompt
echo "53. Create Warnings for Standard Login Services"
cat /etc/motd
ls -l /etc/motd
cat /etc/issue
ls -l /etc/issue
prompt

# Prompt 54: Enable a Warning Banner for the FTP service
prompt
echo "54. Enable a Warning Banner for the FTP service"
grep "DisplayConnect" /etc/proftpd.conf
prompt

# Prompt 55: Enable a Warning Banner for the SSH Service
prompt
echo "55. Enable a Warning Banner for the SSH Service"
grep "^Banner" /etc/ssh/sshd_config
prompt

# Prompt 56: Enable a Warning Banner for the GNOME Service
prompt
echo "56. Enable a Warning Banner for the GNOME Service"
cd /etc/gdm/Init
grep "Security Message" Default
prompt

# Prompt 57: Check that the Banner Setting for telnet is Null
prompt
echo "57. Check that the Banner Setting for telnet is Null"
grep "^BANNER" /etc/default/telnetd
prompt

# Prompt 58: Check for Remote Consoles
prompt
echo "58. Check for Remote Consoles"
/usr/sbin/consadm -p
prompt

# Prompt 59: Check for Duplicate User Names
prompt
echo "59. Check for Duplicate User Names"
getent passwd | cut -f1 -d":" | sort -n | uniq -c | while read x ; do
    [ -z "${x}" ] && break
    set - $x
    if [ $1 -gt 1 ]; then
        gids=$(getent passwd | nawk -F: '($1 == n) { print $3 }' n=$2 | xargs)
        echo "Duplicate User Name ($2): ${gids}"
    fi
done
prompt

# Prompt 60: Check That Defined Home Directories Exist
prompt
echo "60. Check That Defined Home Directories Exist"
logins -xo | while read line; do
    user=$(echo ${line} | awk -F: '{ print $1 }')
    home=$(echo ${line} | awk -F: '{ print $6 }')
    if [ ! -d "${home}" ]; then
        echo ${user}
    fi
done
prompt

# Prompt 61: Verify System Account Default Passwords
prompt
echo "61. Verify System Account Default Passwords"
for user in $(logins -s | awk '{ print $1 }'); do
    if [ "${user}" != "root" ]; then
        stat=$(passwd -s ${user} | awk '{ print $2 }')
        if [ "${stat}" != "LK" ] && [ "${stat}" != "NL" ]; then
            echo "Account ${user} is not locked or non-login."
        fi
    fi
done
prompt

# Prompt 62: Verify System File Permissions
prompt
echo "62. Verify System File Permissions"
pkg verify
prompt

# Prompt 63: Ensure Password Fields are Not Empty
prompt
echo "63. Ensure Password Fields are Not Empty"
logins -p
prompt

# Prompt 64: Verify No UID 0 Accounts Exist Other than root
prompt
echo "64. Verify No UID 0 Accounts Exist Other than root"
logins -o | awk -F: '($2 == 0) { print $1 }'
prompt

# Prompt 65: Ensure root PATH Integrity
prompt
echo "65. Ensure root PATH Integrity"
if [ "`echo $PATH | grep :: `" != "" ]; then
    echo "Empty Directory in PATH (::)"
fi
prompt

# Prompt 66: Check Permissions on User Home Directories
prompt
echo "66. Check Permissions on User Home Directories"
for dir in $(logins -ox | awk -F: '($8 == "PS") { print $6 }'); do
    find ${dir} -type d -prune \( -perm -g+w -o -perm -o+r -o -perm -o+w -o -perm -o+x \) -ls
done
prompt

# Prompt 67: Check Permissions on User "." (Hidden) Files
prompt
echo "67. Check Permissions on User \".\" (Hidden) Files"
for dir in $(logins -ox | awk -F: '($8 == "PS") { print $6 }'); do
    find ${dir}/.[A-Za-z0-9]* \! -type l \ \( -perm -20 -o -perm -02 \) -ls
done
prompt

# Prompt 68: Check Permissions on User .netrc Files
prompt
echo "68. Check Permissions on User .netrc Files"
for dir in $(logins -ox | awk -F: '($8 == "PS") { print $6 }'); do
    find ${dir}/.netrc -type f \( -perm -g+r -o -perm -g+w -o -perm -g+x -o -perm -o+r -o -perm -o+w -o -perm -o+x \) -ls 2>/dev/null
done
prompt

# Prompt 69: Check for Presence of User .rhosts Files
prompt
echo "69. Check for Presence of User .rhosts Files"
for dir in $(logins -ox | awk -F: '($8 == "PS") { print $6 }'); do
    find ${dir}/.rhosts -type f -ls 2>/dev/null
done
prompt

# Prompt 70: Check Groups in passwd
prompt
echo "70. Check Groups in passwd"
logins -xo | awk -F: '($3 == "") { print $1 }'
prompt

# Prompt 71: Check That Users Are Assigned Home Directories
prompt
echo "71. Check That Users Are Assigned Home Directories"
logins -xo | while read line; do
    user=$(echo ${line} | awk -F: '{ print $1 }')
    home=$(echo ${line} | awk -F: '{ print $6 }')
    if [ -z "${home}" ]; then
        echo ${user}
    fi
done
prompt

# Prompt 72: Check User Home Directory Ownership
prompt
echo "72. Check User Home Directory Ownership"
logins -xo | awk -F: '($8 == "PS") { print }' | while read line; do
    user=$(echo ${line} | awk -F: '{ print $1 }')
    home=$(echo ${line} | awk -F: '{ print $6 }')
    find ${home} -type d -prune \! -user ${user} -ls
done
prompt

# Prompt 73: Check for Duplicate UIDs
prompt
echo "73. Check for Duplicate UIDs"
logins -d
prompt

# Prompt 74: Check for Duplicate GIDs
prompt
echo "74. Check for Duplicate GIDs"
getent group | cut -f3 -d":" | sort -n | uniq -c | while read x ; do
    [ -z "${x}" ] && break
    set - $x
    if [ $1 -gt 1 ]; then
        grps=$(getent group | nawk -F: '($3 == n) { print $1 }' n=$2 | xargs)
        echo "Duplicate GID ($2): ${grps}"
    fi
done
prompt

# Prompt 75: Check for Duplicate Group Names
prompt
echo "75. Check for Duplicate Group Names"
getent group | cut -f1 -d":" | sort -n | uniq -c | while read x ; do
    [ -z "${x}" ] && break
    set - $x
    if [ $1 -gt 1 ]; then
        gids=$(getent group | nawk -F: '($1 == n) { print $3 }' n=$2 | xargs)
        echo "Duplicate Group Name ($2): ${gids}"
    fi
done
prompt

# Prompt 76: Check for Presence of User .netrc Files
prompt
echo "76. Check for Presence of User .netrc Files"
for dir in $(logins -ox | awk -F: '($8 == "PS") { print $6 }'); do
    ls -l ${dir}/.netrc 2>/dev/null
done
prompt

# Prompt 77: Check for Presence of User .forward Files
prompt
echo "77. Check for Presence of User .forward Files"
for dir in $(logins -ox | awk -F: '($8 == "PS") { print $6 }'); do
    ls -l ${dir}/.forward 2>/dev/null
done
prompt

# Prompt 78: Find World Writable Files
prompt
echo "78. Find World Writable Files"
find / \( -fstype nfs -o -fstype cachefs -o -fstype autofs -o -fstype ctfs -o -fstype mntfs -o -fstype objfs -o -fstype proc \) -prune -o -type f -perm -0002 -print
prompt

# Prompt 79: Find SUID/SGID System Executables
prompt
echo "79. Find SUID/SGID System Executables"
find / \( -fstype nfs -o -fstype cachefs -o -fstype autofs -o -fstype ctfs -o -fstype mntfs -o -fstype objfs -o -fstype proc \) -prune -o -type f \( -perm -4000 -o -perm -2000 \) -print
prompt

# Prompt 80: Find Un-owned Files and Directories
prompt
echo "80. Find Un-owned Files and Directories"
find / \( -fstype nfs -o -fstype cachefs -o -fstype autofs -o -fstype ctfs -o -fstype mntfs -o -fstype objfs -o -fstype proc \) -prune -o \( -nouser -o -nogroup \) -ls
prompt

# Prompt 81: Find Files and Directories with Extended Attributes
prompt
echo "81. Find Files and Directories with Extended Attributes"
find / \( -fstype nfs -o -fstype cachefs -o -fstype autofs -o -fstype ctfs -o -fstype mntfs -o -fstype objfs -o -fstype proc \) -prune -o -xattr -ls
prompt

# Prompt 82: SN.1 Restrict access to suspend feature
prompt
echo "82. SN.1 Restrict access to suspend feature"
poweradm list | grep suspend
prompt

# Prompt 83: Remove Support for Internet Services (inetd)
prompt
echo "83. SN.2 Remove Support for Internet Services (inetd)"
svcs -Ho state svc:/network/inetd
prompt

# End of Script
prompt
echo "--------------------------------End of Script-----------"
prompt