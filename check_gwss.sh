#!/bin/bash

VER=1.9
RES=0
DBGX=0
ARG=$1
LOGFILE=/var/log/gwss.log

SSHKEYS=(stLL7T99UW74W1C34Q9u88FFuxsJco8dpl4Nz97woXg)

function fingerprint () {
	for i in $(cat $1 | sed -n "s/^.*\(ssh-rsa .*\)$/\1/gpI" | xargs -I% bash -c 'ssh-keygen -l -f /dev/stdin <<<"%"' | sed -n "s/^[0-9]\+ [^:]\+:\([^ ]\+\) .*$/\1/gp") ; do
		FOUND="0"
		for j in ${SSHKEYS[@]}; do
			if [ "$i" == "$j" ] ; then
				FOUND="1"
			fi
		done
		if [ "$FOUND" == "0" ] ; then
			return 1
		fi
	done
	return 0
}

if [ $# -gt 1 ] ; then
	echo "Usage: ./check_gwss.sh [-d]"
	exit 3
fi

for i in "$@" ; do
	case $i in
		-d|--debug)
			DBGX=1
			shift
			;;
		*)
			shift # past argument with no value
			;;
	esac
done

function lerr {
	umask 027
	if [ $DBGX -ne 0 ] ; then
		echo -e "ERROR: $1"
	fi
	DT=$(date +"%Y-%m-%d %H:%M")
	echo "$DT ERROR: ${1}" >>${LOGFILE}
	logger -p user.err -t "gwss" "$DT ERROR: ${1}"
}

function lwarn {
	umask 027
	if [ $DBGX -ne 0 ] ; then
		echo -e "WARNING: $1"
	fi
	DT=$(date +"%Y-%m-%d %H:%M")
	echo "$DT WARNING: ${1}" >>${LOGFILE}
	logger -p user.warn -t "gwss" "$DT WARNING: ${1}"
}

function lnotice {
	umask 027
	if [ $DBGX -ne 0 ] ; then
		echo -e "NOTICE: $1"
	fi
	DT=$(date +"%Y-%m-%d %H:%M")
	echo "$DT NOTICE: ${1}" >>${LOGFILE}
	logger -p user.warn -t "gwss" "$DT NOTICE: ${1}"
}

function linfo {
	umask 027
	if [ $DBGX -ne 0 ] ; then
		echo -e "INFO: $1"
	fi
	DT=$(date +"%Y-%m-%d %H:%M")
	echo "$DT INFO: ${1}" >>${LOGFILE}
}

function sinfo {
	if [ $DBGX -ne 0 ] ; then
		echo -e "INFO: $1"
	fi
}

##############
# 2.1.1 Kernel version
##############
CMD="uname -r"
sinfo "$CMD"
UNA=$(uname -r | egrep "5.14.0-[[:digit:]]*.?[[:digit:]]*.?[[:digit:]]*.?el9_[[:digit:]]+.x86_64")
if [ ! -n "${UNA}" ] ; then
	lerr "$CMD: Invalid kernel version"
fi 

##############
# 2.2.1 Standard OS filesystems
##############
aMP1=(/ /boot /var /var/log /opt /home /tmp /var/crash /audit /admin)
aSZ1=(4096 300 2048 2048 2000 1000 2048 2048 240392 128 1024)
CMD="df"
sinfo "$CMD"
j=0
max=${#aMP1[*]}
while [ $j -lt $max ] ; do
	FOUND=""
	for i in $(df -hPm |awk '{print $6,"   ", $2}' |sort -k1|egrep -v "Mounted|dev|proc|sys" | sed -n "s/^\([/a-zA-Z_0-9]\+\)\\s\+\(.\+\)$/\1;\2/gp") ; do
		MP=$(echo $i | cut -f1 -d';')
		SZ=$(echo $i | cut -f2 -d';')

		MP1=${aMP1[$j]}
		SZ1=${aSZ1[$j]}
		if [ "$MP1" == "/var/crash" ] ; then
			SZ1=$(free -m | sed -n "s/^Mem:\s*\([^ ]*\).*$/\1/gp")
		fi

		if [ "$MP" == "$MP1" ] ; then
			FOUND="$MP"

			szmin=$(($SZ1-$SZ1/10))
			szmax=$(($SZ1+$SZ1/2))

			if [ $SZ -le $szmin -o $SZ -ge $szmax ] ; then
				if [ "$MP1" == "/home" -o "$MP1" == "/tmp" ] ; then
					linfo "$CMD: Wrong size for mountpoint $MP ($SZ, expecting $SZ1)"
				else
					lnotice "$CMD: Wrong size for mountpoint $MP ($SZ, expecting $SZ1)"
				fi
			fi
		fi
	done
	if [ "${FOUND}" == "" ] ; then
		grep -q hypervisor /proc/cpuinfo
		if [ $? -ne 0 -a "${aMP1[$j]}" == "/var/crash" ] ; then
			lerr "$CMD: Mountpoint ${aMP1[$j]} missing!"
		fi
	fi
	j=$((j+1))
done

##############
# 2.2.1 Standard OS filesystems
##############
CMD="mount"
sinfo "$CMD"
i=0
while [ $j -lt $max ] ; do
	FOUND=""
	for i in $(mount |awk '{print $3}' |egrep -v "proc|dev|sys" |sort) ; do
		MP1=${aMP1[$j]}
		if [ "$i" == "$MP1" ] ; then
			FOUND="$i"
		fi
	done
        if [ "${FOUND}" == "" ] ; then
                lerr "$CMD: Mountpoint ${aMP1[$j]} missing!"
        fi
        j=$((j+1))
done

CMD="fstab"
sinfo "$CMD"
i=0
while [ $j -lt $max ] ; do
	FOUND=""
	for i in $(cat /etc/fstab |egrep -v ^#|awk '{print $2}' |grep ^[^#]|egrep -v "dev|proc|swap|sys"|sort) ; do
		MP1=${aMP1[$j]}
		if [ "$i" == "$MP1" ] ; then
			FOUND="$i"
		fi
	done
        if [ "${FOUND}" == "" ] ; then
                lerr "$CMD: Mountpoint ${aMP1[$j]} missing!"
        fi
        j=$((j+1))
done

CMD="swap"
sinfo "$CMD"
SWP_WHITELIST=(host1@example.com host2@example.com)

SKIPTEST=0
for j in ${SWP_WHITELIST[@]}; do
    if [ "$HOSTNAME" == "$j" ] ; then
        SKIPTEST=1
    fi
done

if [ $SKIPTEST -ne 1 ] ; then
    SWP=$(free -mt |grep "Swap:" |awk '{print $2}')
    MEM=$(free -mt |grep "Mem:" |awk '{print $2}')
    
    swpmin=$(($MEM-$MEM/10))
    swpmax=$(($MEM+$MEM/10))
    
    if [ $MEM -le 8192 ] ; then
        if [ $SWP -gt $swpmax ] ; then
            lnotice "$CMD: Swap size too large ($SWP > $swpmax)"
        fi
        if [ $SWP -le $swpmin ] ; then
            lnotice "$CMD: Swap size too small ($SWP <= $swpmin)" 
        fi
    else
        if [ $SWP -gt $swpmax ] ; then
            lnotice "$CMD: Swap size too large ($SWP > $swpmax)"
        fi
    fi
fi

##############
# 2.3.1 Kernel parameters
##############
CMD="sysctl"
sinfo "$CMD"
SYSCTL=(net.ipv4.ip_forward net.ipv4.conf.default.proxy_arp net.ipv4.conf.all.proxy_arp net.ipv4.conf.default.rp_filter net.ipv4.conf.all.rp_filter net.ipv4.tcp_syncookies kernel.sysrq kernel.core_uses_pid net.ipv4.conf.all.accept_source_route net.ipv4.conf.default.accept_redirects net.ipv4.conf.all.accept_redirects net.ipv4.icmp_echo_ignore_broadcasts net.ipv4.conf.default.secure_redirects net.ipv4.conf.all.secure_redirects kernel.nmi_watchdog kernel.unknown_nmi_panic kernel.core_pattern net.ipv6.conf.all.disable_ipv6 net.ipv6.conf.default.disable_ipv6 net.ipv6.conf.lo.disable_ipv6)
SYSVAL=(0 0 0 1 1 1 0 1 0 0 0 1 1 1 0 1 /var/cores/core 1 1 1)
# Exceptions
declare SYSEXCEPT=(
        "vpn01.inf.epost-dev.de=0"
        "vpn01.inf.epost-dev.de=3"
        "vpn01.inf.epost-dev.de=4"
        "vpn02.inf.epost-dev.de=0"
        "vpn02.inf.epost-dev.de=3"
        "vpn02.inf.epost-dev.de=4"
        "dhcp01.inf.epost-dev.de=0"
        "dhcp01.inf.epost-dev.de=3"
        "dhcp01.inf.epost-dev.de=4"
        "dhcp02.inf.epost-dev.de=0"
        "dhcp02.inf.epost-dev.de=3"
        "dhcp02.inf.epost-dev.de=4"
        "infra1.inf.epost-dev.de=0"
        "infra2.inf.epost-dev.de=0"
        "infra3.inf.epost-dev.de=0"
        "infra4.inf.epost-dev.de=0"
)
j=0 
max=${#SYSCTL[*]}
while (( j < $max )) ; do
	CURVAL=$(sysctl ${SYSCTL[$j]} 2>/dev/null | cut -f3 -d ' ')
	VAL=${SYSVAL[$j]}

	# Skip exceptions
	SKIP=0
        for i in "${SYSEXCEPT[@]}" ; do
                KEY=$(echo $i | cut -f1 -d=)
                VALUE=$(echo $i | cut -f2 -d=)
                if [ "$KEY" == "$HOSTNAME" -a "$VALUE" == "$j" ] ; then
			SKIP=1
		fi
	done
	
	if [ "$CURVAL" != "$VAL" -a $SKIP -eq 0 ] ; then
		lerr "$CMD: Invalid value for ${SYSCTL[$j]} ($CURVAL, expected $VAL)"
	fi
        j=$((j+1))
done

##############
# 2.4.1 Check LAN cards
##############
CMD="lspci | grep -i ether"
sinfo "$CMD"
NR_ETHER=$(lspci | grep -i ether | wc -l)
grep -q hypervisor /proc/cpuinfo
if [ $? -ne 0 ] ; then
	if [ $NR_ETHER -le 3 ] ; then
		lerr "Check LAN cards: not enough network interfaces ($NR_ETHER)"
	fi
fi

##############
# 2.4.2 Test link up
# Link on all network cards set to start on boot must be up. Network cable is 
# connected to the network interface and switch.
# alias eth0 off
##############
CMD="ip link"
sinfo "$CMD"
#IFDOWN=$(for i in `ip link show | awk -F ": " '{print $2}' | sort | grep -v "lo\|^$" | egrep -v "^\n"`; do ethtool $i 2>/dev/null | grep "Link\ detected" | egrep -H --label=$i "no$" ; done)
NSCRIPTS=`for i in $(egrep -ls "ONBOOT\s*=\s*\"?(Y|Y|y)" /etc/sysconfig/network-scripts/ifcfg*) ; do echo $i ; done`
for j in $NSCRIPTS ; do  
	echo $j | egrep -q "\.bak$"
	if [ $? -eq 0 ] ; then
		continue
	fi

	DEVNAME=$(sed -n "s/^DEVICE\s*=\s*\"\+\([^\"]\+\).*$/\1/gp" $j)
	IFDOWN=$(ethtool $DEVNAME 2>/dev/null | grep "Link\ detected" | egrep -iH --label=$DEVNAME "no$")
	if [ ! -z "${IFDOWN}"  ] ; then
		lerr "${CMD}: ${IFDOWN}"
	fi

	ip link show $DEVNAME | grep -q "UP,LOWER_UP"
	if [ $? -ne 0 ] ; then
		lerr "${CMD}: $DEVNAME not up"
	fi
done

##############
# 2.4.3 Link aggregation
##############
CMD="link aggregation"
sinfo "$CMD"
IFSINGLE=$(ip a | grep "state UP" | grep mq | grep -v bond)
if [ "$IFSINGLE" != "" ] ; then
	lerr "$CMD: Not part of bond: $IFSINGLE"
fi

NSCRIPTS=`for i in $(egrep -ls "BONDING" /etc/sysconfig/network-scripts/ifcfg*) ; do echo $i ; done`
for j in $NSCRIPTS ; do  
	echo $j | egrep -q "\.bak$"
	if [ $? -eq 0 ] ; then
		continue
	fi

	DEVNAME=$(sed -n "s/^DEVICE\s*=\s*\(.*\)$/\1/gp" $j)
	SLAVECOUNT=$(cat /proc/net/bonding/$DEVNAME | grep -c "Slave Interface:")
	if [ $SLAVECOUNT -lt 2 ] ; then
		lerr "${CMD}: Bond ${DEVNAME} not enough interfaces ($SLAVECOUNT)"
	fi
done

##############
# 2.4.5 Name resolving
##############
CMD="name resolving"
sinfo "$CMD"
NS=$(grep nameserver /etc/resolv.conf | egrep -v "(10.175.4.11|10.175.4.12)")
if [ "$NS" != "" ] ; then
	lerr "$CMD: unknown nameserver in resolv.conf: $NS"
fi

##############
# 2.4.6 Chrony (former NTP daemon)
##############
CMD="chrony"
sinfo "$CMD"
systemctl -q is-active chronyd
if [ $? -ne 0 ] ; then
	lerr "$CMD not enabled"
fi

NTPSRV=$(grep ^server /etc/chrony.conf | egrep -v "(ntp1.inf.epost-dev.de|ntp2.inf.epost-dev.de|10.175.4.10)")
if [ "$NTPSRV" != "" -a "$HOSTNAME" != "svc-002.inf.epost-dev.de" -a "$HOSTNAME" != "svc-003.inf.epost-dev.de" ] ; then
	lerr "$CMD: invalid NTP server: $NTPSRV"
fi

##############
# 2.5.1 Running daemons
##############
CMD="running daemons"
sinfo "$CMD"
DMNS=(xinetd sendmail crond rsyslogd sshd chronyd)
j=0 
max=${#DMNS[*]}
while [ $j -lt $max ] ; do
        CURVAL=$(ps -lae | grep ${DMNS[j]})
        if [ "$CURVAL" == "" ] ; then
                linfo "$CMD: ${DMNS[j]} not running"
        fi
        j=$((j+1))
done

##############
# 2.5.2 Kdump
##############
CMD="Kdump"
sinfo "$CMD"
dmidecode -t system | grep -i product | grep -qi poweredge
if [ $? -eq 0 ] ; then
	systemctl status kdump 1>/dev/null 2>&1
	if [ $? -ne 0 ] ; then
		lerr "$CMD: kdump not running"
	else
		MEM=$(free -mt |grep "Mem:" |awk '{print $2}')
		memmax=$(($MEM+$MEM/10))
		if [ $memmax -gt 8192 ] ; then
			egrep -q "path[[:space:]]+/var/crash" /etc/kdump.conf
			if [ $? -ne 0 ] ; then
				lerr "$CMD: invalid path in kdump.conf"
			else
				df -k /var/crash 1>/dev/null 2>&1
				if [ $? -ne 0 ] ; then
					lerr "$CMD: /var/crash missing"
				fi
			fi
		fi
	fi
fi

##############
# 2.6.1 Monitoring
#At least the following items have to be monitored:
#CPU usage
#Memory usage
#Free disk space
##############
CMD="Monitoring"
sinfo "$CMD"
egrep -q "disable[[:space:]]+= no" /etc/xinetd.d/check_mk /etc/xinetd.d/check-mk-agent 2>/dev/null
if [ $? -ne 0 ] ; then
	lerr "$CMD: check_mk missing"
fi

##############
# 2.7.1 Shadow files
##############
CMD="Shadow file"
sinfo "$CMD"
PWP=$(ls -la /etc/shadow | cut -d " " -f 1)
if [[ ! "$PWP" =~ "----------" ]] ; then
	lerr "$CMD: invalid file permissions"
fi

##############
# 2.7.2 Permission of passwd & groups
##############
#-rw-r--r-- 1 root root /etc/passwd 
#-rw-r--r-- 1 root root /etc/group 
#-r-------- 1 root root /etc/gshadow (or ----------)
CMD="passwd & groups"
sinfo "$CMD"
PWP=$(ls -la /etc/passwd | cut -d " " -f 1)
if [[ ! "$PWP" =~ "-rw-r--r--" ]] ; then
        lerr "$CMD: /etc/passwd invalid file permissions ($PWP)"
fi
PWP=$(ls -la /etc/group | cut -d " " -f 1)
if [[ ! "$PWP" =~ "-rw-r--r--" ]] ; then
        lerr "$CMD: /etc/group invalid file permissions ($PWP)"
fi
PWP=$(ls -la /etc/gshadow | cut -d " " -f 1)
if [[ ! "$PWP" =~ "----------" ]] ; then
        lerr "$CMD: /etc/gshadow invalid file permissions ($PWP)"
fi

##############
# 2.7.3 Duplicates in passwd and groups
##############
#Check /etc/passwd and /etc/group, no uid/gid should occur twice. 
#Also, especially check that no other user than "root" has uid=0.
CMD="Duplicates in passwd"
sinfo "$CMD"
egrep -n "^[^:]*:[^:]*:0:" /etc/passwd | egrep -qv "^1:root:"
if [ $? -eq 0 ] ; then
	lerr "$CMD: uid=0 not root"
fi

cat /etc/passwd | cut -d ":" -f 3 | uniq -c | egrep -qv "^[[:space:]]+1[[:space:]]+.*"
if [ $? -eq 0 ] ; then
	lerr "$CMD: duplicate uid in /etc/passwd"
fi

CMD="Duplicates in group"
sinfo "$CMD"
cat /etc/group | cut -d ":" -f 3 | uniq -c | egrep -qv "^[[:space:]]+1[[:space:]]+.*"
if [ $? -eq 0 ] ; then
	lerr "$CMD: duplicate gid in /etc/group"
fi


##############
# 2.7.4 pwck
##############
CMD="pwck"
sinfo "$CMD"
pwck -rq
if [ $? -ne 0 ] ; then
	lerr "$CMD"
fi

##############
# 2.7.4 grpck
##############
CMD="grpck"
sinfo "$CMD"
GRPS=$(grpck -r)
if [ -n "$GRPS" ] ; then
	lerr "$CMD: $GRPS"
fi

##############
# 2.7.5 Remote root login
##############
CMD="Remote login services (rlogin,rsh,rexec)"
sinfo "$CMD"
systemctl --no-pager list-unit-files | egrep -q "rlogin|rsh|rexec"
if [ $? -eq 0 ] ; then
	lerr "$CMD"
fi

CMD="Remote login /etc/securetty (rlogin,rsh,rexec)"
sinfo "$CMD"
egrep -qi "rlogin|rsh|rexec" /etc/securetty
if [ $? -eq 0 ] ; then
	lerr "$CMD"
fi

CMD="Remote login .rhosts"
sinfo "$CMD"
RHF=$(find / \( -path /proc -o -path /dev -o -path /sys -o -path /mnt -o -path /appl \) -prune -o -name ".rhosts" -exec ls -la {} \; 2>/dev/null)
if [ "$RHF" != "" ] ; then
	lerr "$CMD: $RHF"
fi

##############
# 2.7.6 ~root/.rhosts content
##############
if [ -f /root/.rhosts ] ; then
	CMD="~root/.rhosts content"
	sinfo "$CMD"
	RHC=$(cat /root/.rhosts)
	if [ "$RHC" != "" ] ; then
		lerr "$CMD: not empty"
	fi

	CMD="~root/.rhosts permissions"
	sinfo "$CMD"
	RHP=$(ls -la /root/.rhosts | cut -d " " -f 1)
	if [ "$RHP" != "-r?-------." ] ; then
		lerr "$CMD: invalid file permissions ($RHP)"
	fi
fi

##############
# 2.7.7 /etc/hosts.equiv and user .rhosts
##############
CMD="/etc/hosts.equiv and user .rhosts"
sinfo "$CMD"
RH=$(find / \( -path /proc -o -path /dev -o -path /sys -o -path /mnt -o -path /appl \) -prune -o -name .rhosts -print 2>/dev/null)
if [ "$RH" != "" ] ; then
	lerr "$CMD: Unknown .rhosts file: $RH"
fi

if [ -f /etc/hosts.equiv ] ; then
	lerr "$CMD: Unknown hosts.equiv file"
fi

##############
# 2.7.8 umask
##############
CMD=umask
sinfo "$CMD"
UM=$(umask)
if [ "${UM}" != "0027" ] ; then
	lerr "$CMD: Invalid umask (${UM})"
fi

##############
# umask
##############
CMD=grep-umask
sinfo "$CMD"
GUM=$(grep -hi umask /etc/bashrc /etc/profile /etc/skel/.bash_profile /etc/skel/.bashrc /etc/profile.d/* | egrep -v "^[[:space:]]*#" | grep -v 027)
if [ "${GUM}" != "" ] ; then
	lerr "$CMD: Invalid umask setting in bash- / profile-files"
fi

##############
# 2.7.9 FTP
##############
CMD=ftp
sinfo "$CMD"
FTP=$(ps -ae -o cmd | grep ftp | egrep -v "^/usr/libexec/openssh/sftp-server" | egrep -v "(^grep |^egrep )")
if [ "${FTP}" != "" ] ; then
	lerr "$CMD: ftp process is running"
fi

##############
# 2.7.10 Securetty
# Access must be configured only for console and terminal tty1 (used by iLO). 
# The permissions and ownership must be set up to read and write only for root. 
##############
CMD="SecureTTY"
sinfo "$CMD"
STY=$(egrep -v "^(console|tty1|hvc0)$" /etc/securetty | tr "\n" " ")
if [ "$STY" != "" ] ; then
	lerr "$CMD: invalid tty in /etc/securetty: $STY"
fi

PERM=$(ls -ld /etc/securetty | sed -n "s/^\(..........\).*/\1/gp")
if [ "$PERM" != "-rw-------" ] ; then
	lerr "$CMD: Invalid permission for /etc/securetty"
fi

##############
# 2.7.11 Default runlevel
##############
CMD="Default runlevel"
sinfo "$CMD"
DRL=$(systemctl get-default)
if [ "$DRL" != "multi-user.target" -a "$DRL" != "graphical.target" ] ; then
	lerr "$CMD: invalid default runlevel ($DRL)"
fi

##############
# 2.7.12 CTRL-ALT-DEL trap
##############
CMD="CTRL-ALT-DEL trap"
sinfo "$CMD"
#systemctl list-unit-files | grep ctrl-alt-del.target | egrep -q "disabled\s*$"
systemctl is-enabled network.target 1>/dev/null
if [ $? -ne 0 ] ; then
	lerr "$CMD: not disabled"
fi

##############
# 2.7.13 Re-mapped keys CTRL-ALT-F12
# If CTRL-ALT-F12 is pressed, the system reboots.
##############
CMD="Re-mapped keys CTRL-ALT-F12"
sinfo "$CMD"
systemctl --no-pager list-unit-files | egrep -q "dhlkeyboard.service"
if [ $? -eq 0 ] ; then
        lerr "$CMD"
fi

##############
# 2.7.14 Sudo
# Check if the appropriate version of sudo is installed. Also make sure that 
# only 1 instance of sudo exists on the box.
##############
CMD="Sudo version"
sinfo "$CMD"
SV=$(/bin/sudo -V | sed -n "s/^Sudo version \([0-9]\+\.[0-9]\+\).*$/\1/gp")
if [ "$SV" != "1.9" ] ; then
	lerr "$CMD ($SV)"
fi

CMD="Sudo executables"
sinfo "$CMD"
SF=$(find / \( -path /proc -o -path /dev -o -path /sys -o -path /mnt -o -path /appl -o -path /usr/share/gitolite3 -o -path /srv/git/gitolite -o path /opt/rh/gcc-toolset-*/root/usr/bin \) -prune -o -type f -executable -name sudo -print 2>/dev/null | egrep -v "^/usr/bin/sudo$")
if [ "$SF" != "" ] ; then
	lerr "$CMD: More than one executable found"
fi

##############
# 2.7.15 Accounts/Passwords Policy - if applicable
# By the Security standard, the user accounts and passwords are controlled 
# (lifetime, expiration, password strength, etc.).
##############
CMD="Accounts/Passwords Policy"
sinfo "$CMD"

egrep -q "password\s+requisite\s+pam_pwquality.so local_users_only enforce_for_root retry=3 authtok_type= minlen=16 lcredit=-1 ucredit=-1 dcredit=-1 ocredit=0" /etc/pam.d/system-auth
if [ $? -ne 0 ] ; then
	lerr "$CMD: /etc/pam.d/system-auth (requisite)"
fi

egrep -q "password\s+sufficient\s+pam_unix.so sha512 shadow nullok use_authtok try_first_pass" /etc/pam.d/system-auth
if [ $? -ne 0 ] ; then
	lerr "$CMD: /etc/pam.d/system-auth (sufficient)"
fi

egrep -q "password\s+requisite\s+pam_pwquality.so local_users_only enforce_for_root retry=3 authtok_type= minlen=16 lcredit=-1 ucredit=-1 dcredit=-1 ocredit=0" /etc/pam.d/password-auth
if [ $? -ne 0 ] ; then
	lerr "$CMD: /etc/pam.d/password-auth (requisite)"
fi

egrep -q "password\s+sufficient\s+pam_unix.so sha512 shadow nullok use_authtok try_first_pass" /etc/pam.d/password-auth
if [ $? -ne 0 ] ; then
	lerr "$CMD: /etc/pam.d/password-auth (sufficient)"
fi

NONEXPPWD=$(sed -n 's/^\([^:]\+\):[^!:]*:[^:]*:[^:]*::.*/\1/gp' /etc/shadow)
if [ "$NONEXPPWD" != "" ] ; then
	lerr "$CMD: User accounts with non-expiring passwords $NONEXPPWD"
fi

##############
# 2.7.16 $PATH testing
# The $PATH variable for root and other high privileged users should not have a '.' in the $PATH or any world writeable dir
##############
CMD="PATH testing"
sinfo "$CMD"
for path in ${PATH//:/ }; do
	if [ "$path" == "." ] ; then
		lerr "$CMD: . in PATH" 
	fi
	PERM=$(ls -ld -H $path 2>/dev/null | sed -n "s/^........\(.\).*/\1/gp")
	if [ "$PERM" == "w" ] ; then
		lerr "$CMD: $path is world writeable"
	fi
done

##############
# 2.7.17 HOME directories
# By default, home directories should not be readable/traversable by users other than the owner of the directory.
##############
CMD="HOME directories"
sinfo "$CMD"
for hodi in $(ls /home) ; do
	if [ "$hodi" == "lost+found" ] ; then
		continue
	fi
	PERM=$(ls -ld /home/$hodi | sed -n "s/^\(..........\).*/\1/gp")
	if [ "$PERM" != "drwx------" -a "$PERM" != "drwxr-x---" ] ; then
		lerr "$CMD: Invalid permission for $hodi"
	fi
done

##############
# 2.7.18 Root setuid/setgid files
# Only standard scripts/binaries/etc. from build should have setuid/setgid -> "user".
# Under no circumstances can any setuid -> "user" file be writable by group/world.
##############
CMD="Root setuid/setgid files"
sinfo "$CMD"
FOUND=0
for i in 4000 2000 ; do
	for sf in $(find / -not \( -path /proc -prune \) -perm -2000 -user root ! -type d ! -type l ! -type s ! -type c ! -type p -exec ls -ld {} \; 2>/dev/null | grep -E '^.....w.... ' ) ; do
		(( FOUND+=1 ))
	done
	for sf in $(find / -not \( -path /proc -prune \) -perm -2000 -user root ! -type d ! -type l ! -type s ! -type c ! -type p -exec ls -ld {} \; 2>/dev/null | grep -E '^........w. ' ) ; do
		(( FOUND+=1 ))
	done
done
if [ FOUND -gt 0 ] ; then
	lerr "$CMD: $FOUND setuid/setgid file(s) are group/world writeable" 
fi

##############
# 2.7.19 World writable files/directories
# All world writable directories/files other than those standard to system need to be justified.
##############
CMD="World writable files/directories"
sinfo "$CMD"
WWF=$(find / -not \( -path /proc -prune \) -not \( -path /sys -prune \) -not \( -path /tmp -prune \) -not \( -path /var/tmp -prune \) -not \( -path /dev/shm -prune \) -not \( -path /dev/mqueue -prune \) -not \( -path /mnt -prune \) -not \( -path /run/rhnsd.pid -prune \) -type f -perm -o+w -exec ls -l {} \; 2>/dev/null)
WWD=$(find / -not \( -path /proc -prune \) -not \( -path /sys -prune \) -not \( -path /tmp -prune \) -not \( -path /var/tmp -prune \) -not \( -path /dev/shm -prune \) -not \( -path /dev/mqueue -prune \) -not \( -path /mnt -prune \) -not \( -path /opt/rh/gcc-toolset-12/root -prune \) -type d -perm -o+w -exec ls -ld {} \; 2>/dev/null)
if [ "$WWF" != "" ] ; then
	lerr "$CMD: World writable files:\n$WWF"
fi
if [ "$WWD" != "" ] ; then
	lerr "$CMD: World writable directories:\n$WWD"
fi

##############
# 2.7.20 Security of cron entries
# All scripts run from cron should only be writable by respective users.
##############
CMD="Security of cron entries"
sinfo "$CMD"
for i in /var/spool/cron/* ; do
	if [ ! -f "$i" ] ; then
		continue
	fi
	PERM=$(ls -ld $i | sed -n "s/^\(..........\).*/\1/gp")
	if [ "$PERM" != "-rw-------" ] ; then
		lerr "$CMD: Invalid permission for $i"
	fi
	XUID=$(basename $i)
	PUID=$(id -u $XUID)
        PGID=$(id -g $XUID)
	FUID=$(ls -lnd $i | cut -d " " -f 3)
	FGID=$(ls -lnd $i | cut -d " " -f 4)
	if [ $PGID -ne $FGID -o $PUID -ne $FUID ] ; then
		lerr "$CMD: Invalid ownership for $i"
	fi
done

##############
# 2.7.21 Device files outside /dev 
# No block/character device files should be outside /dev
##############
CMD="Device files outside /dev"
sinfo "$CMD"
DEV=$(find / -not \( -path /proc -prune \) -not \( -path /mnt -prune \) -not \( -path /sys/fs/selinux -prune \) -not \( -path /srv/configurations/bind -prune \) -not \( -path /var/named -prune \) -not \( -path /run/systemd/inaccessible -prune \) -not \( -path /run/user/*/systemd/inaccessible -prune \) -and \( -type b -or -type c \) -print 2>/dev/null | grep -v "^\/dev")
if [ "$DEV" != "" ] ; then
	lerr "$CMD: $DEV"
fi

##############
# 2.7.22 Sshd configuration
# SSH daemon must be enabled and properly configured.
##############
CMD="SSHD configuration"
sinfo "$CMD"
egrep -q "^#?SyslogFacility[[:space:]]+AUTH(PRIV)?" /etc/ssh/sshd_config
if [ $? -ne 0 ] ; then
	lerr "$CMD: 'SyslogFacility AUTHPRIV' missing"
fi

egrep -q "^X11Forwarding[[:space:]]+yes" /etc/ssh/sshd_config
if [ $? -ne 0 ] ; then
	lerr "$CMD: 'X11Forwarding yes' missing"
fi

egrep -q "^Subsystem[[:space:]]+sftp[[:space:]]+/usr/libexec/openssh/sftp-server" /etc/ssh/sshd_config
if [ $? -ne 0 ] ; then
	lerr "$CMD: 'Subsystemsftp /usr/libexec/openssh/sftp-server' missing"
fi

egrep -q "^Banner[[:space:]]+/etc/issue.net" /etc/ssh/sshd_config
if [ $? -ne 0 ] ; then
	lerr "$CMD: 'Banner /etc/issue.net' missing"
fi


# UsePAM defaults to yes in sshd / RHEL9
egrep -q "^[[:space:]]+UsePAM[[:space:]]+no" /etc/ssh/sshd_config
if [ $? -eq 0 ] ; then
	lerr "$CMD: 'UsePAM no' not supported"
fi

##############
# 2.7.23 Ssh - authorized_keys
# authorized_keys files should contain only known keys.
##############
CMD="SSH - authorized_keys2"
sinfo "$CMD"
AK=$(find / \( -path /proc -o -path /dev -o -path /sys -o -path /mnt -o -path /opt/puppetlabs/puppet/vendor_modules -o -path /srv/configurations/puppet \) -prune -o -name authorized_keys2 -print 2>/dev/null )
if [ "$AK" != "" ] ; then
	for authkeyfile in $(echo $AK) ; do
		fingerprint $authkeyfile
		if [ $? -ne 0 ] ; then 
			lerr "$CMD: invalid ssh key in $authkeyfile"
		fi
	done
fi

CMD="SSH - authorized_keys"
sinfo "$CMD"
AK=$(find / \( -path /proc -o -path /dev -o -path /sys -o -path /mnt -o -path /opt/puppetlabs/puppet/vendor_modules -o -path /srv/configurations/puppet \) -prune -o -name authorized_keys -print 2>/dev/null )
if [ "$AK" != "" ] ; then
	for authkeyfile in $(echo $AK) ; do
		fingerprint $authkeyfile
		if [ $? -ne 0 ] ; then 
			lerr "$CMD: invalid ssh key in $authkeyfile"
		fi
	done
fi

##############
# 2.7.24 Shell session timeout
# Login sessions should be automatically shutdown after 5 minutes. 
# Verify TMOUT environment variable setting in /etc/profile and root’s profile.
##############
CMD="Shell session timeout"
sinfo "$CMD"
egrep -q "^[[:space:]]*export[[:space:]]*TMOUT=300[[:space:]]*" /etc/profile.d/defaults 2>/dev/null
if [ $? -ne 0 ] ; then
	lerr "$CMD: TMOUT=300 missing in /etc/profile.d/defaults"
fi

##############
# 2.7.25 Firewall standards
# iptables configuration should meet minimal local standards.
##############
CMD="Firewall standards"
sinfo "$CMD"
iptables -nL 2>/dev/null | egrep -qi "chain input.*policy drop*"
if [ $? -ne 0 ] ; then
        iptables -nL INPUT 2>/dev/null | tail -n 1 | egrep -q "^REJECT[[:space:]]*all[[:space:]]*--[[:space:]]*0.0.0.0/0[[:space:]]*0.0.0.0/0[[:space:]]"
        if [ $? -ne 0 ] ; then
                lerr "$CMD: INPUT chain policy is not DROP"
        fi
fi

##############
# 2.7.26 Generic accounts
# Generic accounts (other than standard system ones) should be documented.
##############
CMD="Generic accounts"
sinfo "$CMD"
GA=$(egrep -v "(^root|^adm|^bin|^daemon|^shutdown|^halt|^mail|^operator|^nobody|^systemd-network|^dbus|^polkitd|^tss|^libstoragemgmt|^rpc|^unbound|^radvd|^rpcuser|^nfsnobody|^qemu|^postfix|^sshd|^chrony|^tcpdump|^puppet|^nagios|^sssd|^bacula|^dped|^apache|^rear|^mysql|^lp|^colord|^named|^git|^git-worker|^gitolite3|^openldap|^webldappwd|^e2sys-ilhousekeeper|^radiusd|^clamupdate|^openldap|^geoclue|^rtkit|^pulse|^setroubleshoot|^gdm|^gnome-initial-setup|^avahi|^smmsp|^oracle|^epmd|^squid|^c-icap|^clamav|^splunk|^ftp|^dhcpd|^confluence|^jira|^clamscan|^node-exporter|^node_exporter|^rpmbuild|^openvpn|^systemd-coredump|^systemd-resolve|^sync|^clevis|^cockpit-ws|^insights|^systemd-oom)" /etc/passwd)
if [ "$GA" != "" ] ; then
	lerr "$CMD: Unknown accounts in /etc/passwd:\n$GA"
fi

##############
# 2.7.27 Root and wheel group
# These two special groups are used to grant individuals with higher privileges based only on membership to these groups. 
# Only root user can be member of these groups.
##############
CMD="Root and wheel groups"
sinfo "$CMD"
sed -n '/^root/p; /^bin/p; /^wheel/p' /etc/group | egrep -q "^root:x:0:$"
if [ $? -ne 0 ] ; then
	lerr "$CMD: invalid users in group root"
fi
sed -n '/^root/p; /^bin/p; /^wheel/p' /etc/group | egrep -q "^bin:x:1:$"
if [ $? -ne 0 ] ; then
	lerr "$CMD: invalid users in group bin"
fi
sed -n '/^root/p; /^bin/p; /^wheel/p' /etc/group | egrep -q "^wheel:x:10:dped$"
if [ $? -ne 0 ] ; then
	lerr "$CMD: invalid users in group wheel"
fi

##############
# 2.7.28 Processes are not running under the root
# Java processes (except for appqcime processes) should not run under root 
# and a maximum of 1 httpd/www process may run under root.
##############
CMD="Processes are not running under root"
sinfo "$CMD"
PRJ=$(ps aux |grep "^root"|grep "java" | grep -v grep)
if [ "$PRJ" != "" ] ; then
	lerr "$CMD: java process running under root"
fi

PRH=$(ps aux |grep "^root"|grep "http" | grep -v grep | wc -l)
if [ $PRH -gt 1 ] ; then
	lerr "$CMD: more than one http process running under root"
fi

PRW=$(ps aux |grep "^root"|grep "www" | grep -v grep | wc -l)
if [ $PRW -gt 1 ] ; then
	lerr "$CMD: more than one www process running under root"
fi

##############
# 2.7.29 SELinux disabled
# SELinux mode must be disabled
##############
CMD="SELinux disabled"
sinfo "$CMD"
SEL=$(getenforce)
if [ "$SEL" != "Permissive" -a "$SEL" != "Disabled" ] ; then
	lerr "$CMD: SELinux is not disabled"
fi

##############
# Security-Updates
##############
CMD="Security-Updates"
sinfo "$CMD"
declare -a SECUPD SECIMP SECCRIT
SECUPD=$(timeout 60 yum updateinfo -q --list --updates --security | tr -s ' ' | egrep "Critical|Important" | cut -d ' ' -f 2,3 --output-delimiter=':' | tr "\n" ' ')
if [ -n "$SECUPD" ] ; then
        lerr "$CMD: $SECUPD"
fi

##############
# Restart
##############
CMD="Check-Restart"
sinfo "$CMD"
RES=0
CHECKRESTART=needs-restarting
SERVICES=$($CHECKRESTART -s 2>&1 | egrep -v "Updating Subscription Management|listed more than once|smaps\." | tr "\n" ";")
if [ -n "$SERVICES" ] ; then
        RES=2
        MSG="Services need restarting:$SERVICES"
fi
$($CHECKRESTART -r 1>/dev/null 2>&1)
if [ $? -ne 0 ] ; then
        linfo "Server needs reboot"
fi
if [ $RES -ne 0 ] ; then
        lerr "$CMD: $MSG"
fi

##############
# Cleanup
##############
CMD="Cleanup"
sinfo "$CMD"
RES=0
yum -q clean all
if [ $? -ne 0 ] ; then
        RES=1
        MSG="yum clean all failed;$MSG"
fi
if [ $RES -ne 0 ] ; then
        lerr "$CMD: $MSG"
fi

##############
# Spectre/Meltdown
##############
CMD="Spectre/Meltdown"
sinfo "$CMD"
SPECTRE=/usr/local/bin/spectre-meltdown-checker.sh
if [ -f "${SPECTRE}" ] ; then
	SECUPD=$(${SPECTRE} --no-color --batch 2>&1 | sed -n "s/^\([^ ]* VULN .*\)$/\1/gp")
	if [ -n "$SECUPD" ] ; then
        	lnotice "$CMD: $SECUPD"
	fi
else
	lerr "$CMD: ${SPECTRE} script not found"
fi

exit 0

