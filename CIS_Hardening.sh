#! /bin/bash


echo "==============HySecure Hardening Compliance Script==============="

echo "Remediating Control 1.1.1.1"
# 1.1.1.1 - Ensure mounting of cramfs filesystems is disabled (Scored)
echo "install cramfs /bin/true" >> /etc/modprobe.d/CIS.conf
rmmod cramfs > /dev/null 2>&1

echo "Remediating Control 1.1.1.2"
sleep .1
# 1.1.1.1 - Ensure mounting of freevxfs filesystems is disabled (Scored)
echo "install freevxfs /bin/true" >> /etc/modprobe.d/CIS.conf
rmmod freevxfs > /dev/null 2>&1

echo "Remediating Control 1.1.1.3"
sleep .1
# 1.1.1.1 - Ensure mounting of jffs2 filesystems is disabled (Scored)
echo "install jffs2 /bin/true" >> /etc/modprobe.d/CIS.conf
rmmod jffs2 > /dev/null 2>&1

echo "Remediating Control 1.1.1.4"
sleep .1
# 1.1.1.1 - Ensure mounting of hfs filesystems is disabled (Scored)
echo "install hfs /bin/true" >> /etc/modprobe.d/CIS.conf
rmmod hfs > /dev/null 2>&1

echo "Remediating Control 1.1.1.5"
sleep .1
# 1.1.1.1 - Ensure mounting of hfsplus filesystems is disabled (Scored)
echo "install hfsplus /bin/true" >> /etc/modprobe.d/CIS.conf
rmmod hfsplus > /dev/null 2>&1

echo "Remediating Control 1.1.1.6"
sleep .1
# 1.1.1.6 - Ensure mounting of squashfs filesystems is disabled (Scored)
echo "install squashfs /bin/true" >> /etc/modprobe.d/CIS.conf
rmmod squashfs > /dev/null 2>&1

echo "Remediating Control 1.1.1.7"
sleep .1
# 1.1.1.7 - Ensure mounting of udf filesystems is disabled (Scored)
echo "install udf /bin/true" >> /etc/modprobe.d/CIS.conf
rmmod udf > /dev/null 2>&1

echo "Remediating Control 1.1.1.8"
# 1.1.1.8 - Ensure mounting of FAT filesystems is disabled (Scored)
sleep .1
echo "install vfat /bin/true" >> /etc/modprobe.d/CIS.conf
rmmod vfat > /dev/null 2>&1

echo "Remediating Control 1.1.14"
# 1.1.14  Ensure nodev option set on /home partition 
sleep .1
sed -i "s/\/dev\/mapper\/vg01-lv_fes \/home                   ext4    defaults        1 2/\/dev\/mapper\/vg01-lv_fes \/home                   ext4    defaults nodev        1 2/g" /etc/fstab > /dev/null 2>&1
echo "Modifying fstab entries.."
sed -i "s/home                   ext3    defaults        1 2/home                   ext3    defaults,nodev        1 2/g" /etc/fstab
echo "/tmp	/var/tmp	none	bind	0 0" >> /etc/fstab
echo "tmpfs /dev/shm tmpfs defaults,noexec,nodev,nosuid,size=2G 0 0" >> /etc/fstab
echo "umask 027" >> /etc/sysconfig/init

echo "Remediating Control 1.3.2"
# 1.3.2 AIDE Check
sleep .1
echo "0 5 * * * /usr/sbin/aide --check" >> /etc/crontab

echo "Remediating Control 1.4.1"
# 1.4.1 - Ensure permissions on bootloader config are configured (Scored)
sleep .1
file=/boot/grub2/grub.cfg
perm="600 0 0"
p=$(echo $perm | awk {'print $1'} | sed "s/[^0-9]//g" )
o=$(echo $perm | awk {'print $2'})
g=$(echo $perm | awk {'print $3'})
touch $file
if [[ $o -eq 0 && $g -eq 0 ]]; then
        chown root:root $file
fi
chmod $p $file

echo "Remediating Control 1.5.1"
# 1.5.1 - Ensure core dumps are restricted (Scored)
sleep .1
echo "hard core 0" >> /etc/security/limits.d/CIS.conf
echo "fs.suid_dumpable = 0" >> /etc/sysctl.d/CIS.conf
sysctl -w fs.suid_dumpable=0 > /dev/null 2>&1

#echo "Remediating Control 1.6.1.2"
#1.6.1.2 Ensure the SELinux state is enforcing (Scored)
#sleep .1
#sed -i "s/SELINUX=disabled/SELINUX=enforcing/g" /etc/selinux/config

echo "Remediating Control 1.7.1.4"
sleep .1
chown root:root /etc/motd 
chmod 644 /etc/motd

echo "Remediating Control 1.7.1.5"
# 1.7.1.5 - Ensure permissions on /etc/issue are configured (Scored)
sleep .1
file=/etc/issue
perm="644 0 0"
p=$(echo $perm | awk {'print $1'} | sed "s/[^0-9]//g" )
o=$(echo $perm | awk {'print $2'})
g=$(echo $perm | awk {'print $3'})
touch $file
if [[ $o -eq 0 && $g -eq 0 ]]; then
        chown root:root $file
fi
chmod $p $file

echo "Remediating Control 2.2.2"
#2.2.2 Ensure X Window System is not installed (Scored)
sleep .1
yum --disablerepo=\* remove -y xorg-x11* > /dev/null 2>&1

echo "Remediating Control 3.3.1"
# 3.3.1 - Ensure IPv6 router advertisements are not accepted (Not Scored)
sleep .1
echo net.ipv6.conf.all.accept_ra = 0 >/etc/sysctl.d/CIS.conf
sysctl -w net.ipv6.conf.all.accept_ra=0 > /dev/null 2>&1
sysctl -w net.ipv4.route.flush=1 > /dev/null 2>&1
echo net.ipv6.conf.default.accept_ra = 0 > /etc/sysctl.d/CIS.conf
sysctl -w net.ipv6.conf.default.accept_ra=0 > /dev/null 2>&1
sysctl -w net.ipv4.route.flush=1 > /dev/null 2>&1

echo "Remediating Control 3.3.2"
# 3.3.2 - Ensure IPv6 redirects are not accepted (Not Scored)
sleep .1
echo net.ipv6.conf.all.accept_redirects = 0 >/etc/sysctl.d/CIS.conf
sysctl -w net.ipv6.conf.all.accept_redirects=0 > /dev/null 2>&1
sysctl -w net.ipv4.route.flush=1 > /dev/null 2>&1
echo net.ipv6.conf.default.accept_redirects = 0 >/etc/sysctl.d/CIS.conf
sysctl -w net.ipv6.conf.default.accept_redirects=0 > /dev/null 2>&1
sysctl -w net.ipv4.route.flush=1 > /dev/null 2>&1

echo "Remediating Control 3.5.1"
# 3.5.1 - Ensure DCCP is disabled (Not Scored)
sleep .1
echo "install dccp /bin/true" >> /etc/modprobe.d/CIS.conf

echo "Remediating Control 3.5.2"
# 3.5.2 - Ensure SCTP is disabled (Not Scored)
sleep .1
echo "install sctp /bin/true" >> /etc/modprobe.d/CIS.conf

echo "Remediating Control 3.5.3"
# 3.5.3 - Ensure RDS is disabled (Not Scored)
sleep .1
echo "install rds /bin/true" >> /etc/modprobe.d/CIS.conf

echo "Remediating Control 3.5.4"
# 3.5.4 - Ensure TIPC is disabled (Not Scored)
sleep .1
echo "install tipc /bin/true" >> /etc/modprobe.d/CIS.conf

echo "Remediating Control 4.1.1.2"
# 4.1.1.2 - Ensure system is disabled when audit logs are full (Scored)
sleep .1
cat /etc/audit/auditd.conf | grep -v "space_left_action" | grep -v "action_mail_acct" | grep -v "admin_space_left_action" > /etc/audit/auditd.conf.new
mv /etc/audit/auditd.conf.new /etc/audit/auditd.conf
echo "space_left_action = email" >> /etc/audit/auditd.conf
echo "action_mail_acct = root" >> /etc/audit/auditd.conf
echo "admin_space_left_action = halt" >> /etc/audit/auditd.conf

echo "Remediating Control 4.1.1.3"
# 4.1.1.3 - Ensure audit logs are not automatically deleted (Scored)
sleep .1
cat /etc/audit/auditd.conf | grep -v "max_log_file_action" > /etc/audit/auditd.conf.new
mv /etc/audit/auditd.conf.new /etc/audit/auditd.conf
echo "max_log_file_action = keep_logs" >> /etc/audit/auditd.conf

echo "Remediating Control 4.1.3"
# 4.1.3 - Ensure auditing for processes that start prior to auditd is enabled (Scored)
sleep .1
echo 'GRUB_CMDLINE_LINUX="audit=1"' >> /etc/default/grub
echo 'Accops HySecure' > /etc/system-release
grub2-mkconfig -o /boot/grub2/grub.cfg > /dev/null 2>&1

echo "Remediating Control 4.1.4"
# 4.1.4 - Ensure events that modify date and time information are collected (Scored)
sleep .1
echo "-a always,exit -F arch=b64 -S adjtimex -S settimeofday -k time-change" >> /etc/audit/rules.d/audit.rules
echo "-a always,exit -F arch=b32 -S adjtimex -S settimeofday -S stime -k time-change" >> /etc/audit/rules.d/audit.rules
echo "-a always,exit -F arch=b64 -S clock_settime -k time-change" >> /etc/audit/rules.d/audit.rules
echo "-a always,exit -F arch=b32 -S clock_settime -k time-change" >> /etc/audit/rules.d/audit.rules
echo "-w /etc/localtime -p wa -k time-change" >> /etc/audit/rules.d/audit.rules

echo "Remediating Control 4.1.5"
# 4.1.5 - Ensure events that modify user/group information are collected (Scored)
sleep .1
echo "-w /etc/group -p wa -k identity" >>/etc/audit/rules.d/audit.rules
echo "-w /etc/passwd -p wa -k identity" >>/etc/audit/rules.d/audit.rules
echo "-w /etc/gshadow -p wa -k identity" >>/etc/audit/rules.d/audit.rules
echo "-w /etc/shadow -p wa -k identity" >>/etc/audit/rules.d/audit.rules
echo "-w /etc/security/opasswd -p wa -k identity" >>/etc/audit/rules.d/audit.rules

echo "Remediating Control 4.1.6"
# 4.1.6 - Ensure events that modify the system's network environment are collected (Scored)
sleep .1
echo "-a always,exit -F arch=b64 -S sethostname -S setdomainname -k system-locale" >> /etc/audit/rules.d/audit.rules
echo "-w /etc/issue -p wa -k system-locale" >> /etc/audit/rules.d/audit.rules
echo "-w /etc/issue.net -p wa -k system-locale" >> /etc/audit/rules.d/audit.rules
echo "-w /etc/hosts -p wa -k system-locale" >> /etc/audit/rules.d/audit.rules
echo "-w /etc/sysconfig/network -p wa -k system-locale" >> /etc/audit/rules.d/audit.rules
echo "-w /etc/sysconfig/network-scripts/ -p wa -k system-locale" >> /etc/audit/rules.d/audit.rules


echo "Remediating Control 4.1.7"
# 4.1.7 - Ensure events that modify the system's Mandatory Access Controls are collected (Scored)
sleep .1
echo "-w /etc/selinux/ -p wa -k MAC-policy" >> /etc/audit/rules.d/audit.rules
echo "-w /usr/share/selinux/ -p wa -k MAC-policy" >> /etc/audit/rules.d/audit.rules

echo "Remediating Control 4.1.8"
# 4.1.8 - Ensure login and logout events are collected (Scored)
sleep .1
echo "-w /var/log/lastlog -p wa -k logins" >> /etc/audit/rules.d/audit.rules
echo "-w /var/run/faillog -p wa -k logins" >> /etc/audit/rules.d/audit.rules

echo "Remediating Control 4.1.9"
# 4.1.9 - Ensure session initiation information is collected (Scored)
sleep .1
echo "-w /var/run/utmp -p wa -k session" >> /etc/audit/rules.d/audit.rules
echo "-w /var/log/wtmp -p wa -k logins" >> /etc/audit/rules.d/audit.rules
echo "-w /var/log/btmp -p wa -k logins" >> /etc/audit/rules.d/audit.rules

echo "Remediating Control 4.1.10"
# 4.1.10 - Ensure discretionary access control permission modification events are collected (Scored)
sleep .1
echo "-a always,exit -F arch=b64 -S chmod -S fchmod -S fchmodat -F auid>=500 -F auid!=4294967295 -k perm_mod" >> /etc/audit/rules.d/audit.rules
echo "-a always,exit -F arch=b32 -S chmod -S fchmod -S fchmodat -F auid>=500 -F auid!=4294967295 -k perm_mod" >> /etc/audit/rules.d/audit.rules
echo "-a always,exit -F arch=b64 -S chown -S fchown -S fchownat -S lchown -F auid>=500 -F auid!=4294967295 -k perm_mod" >> /etc/audit/rules.d/audit.rules
echo "-a always,exit -F arch=b32 -S chown -S fchown -S fchownat -S lchown -F auid>=500 -F auid!=4294967295 -k perm_mod" >> /etc/audit/rules.d/audit.rules
echo "-a always,exit -F arch=b64 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid>=500 -F auid!=4294967295 -k perm_mod" >> /etc/audit/rules.d/audit.rules
echo "-a always,exit -F arch=b32 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid>=500 -F auid!=4294967295 -k perm_mod" >> /etc/audit/rules.d/audit.rules

echo "Remediating Control 4.1.11"
# 4.1.11 - Ensure unsuccessful unauthorized file access attempts are collected (Scored)
sleep .1
echo "-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid>=500 -F auid!=4294967295 -k access" >> /etc/audit/rules.d/audit.rules
echo "-a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid>=500 -F auid!=4294967295 -k access" >> /etc/audit/rules.d/audit.rules
echo "-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -F auid>=500 -F auid!=4294967295 -k access ">> /etc/audit/rules.d/audit.rules
echo "-a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -F auid>=500 -F auid!=4294967295 -k access" >> /etc/audit/rules.d/audit.rules

echo "Remediating Control 4.1.12"
# 4.1.12 - Ensure use of privileged commands is collected (Scored)
sleep .1
find / -xdev \( -perm -4000 -o -perm -2000 \) -type f | awk '{print "-a always,exit -F path=" $1 " -F perm=x -F auid>=500 -F auid!=4294967295 -k privileged" }' >> /etc/audit/rules.d/audit.rules

echo "Remediating Control 4.1.13"
# 4.1.13 - Ensure successful file system mounts are collected (Scored)
sleep .1
echo "-a always,exit -F arch=b64 -S mount -F auid>=500 -F auid!=4294967295 -k mounts" >> /etc/audit/rules.d/audit.rules

echo "Remediating Control 4.1.14"
# 4.1.14 - Ensure file deletion events by users are collected (Scored)
sleep .1
echo "-a always,exit -F arch=b64 -S unlink -S unlinkat -S rename -S renameat -F auid>=500 -F auid!=4294967295 -k delete" >> /etc/audit/rules.d/audit.rules
echo "-a always,exit -F arch=b32 -S unlink -S unlinkat -S rename -S renameat -F auid>=500 -F auid!=4294967295 -k delete" >> /etc/audit/rules.d/audit.rules

echo "Remediating Control 4.1.15"
# 4.1.15 - Ensure changes to system administration scope (sudoers) is collected (Scored)
sleep .1
echo "-w /etc/sudoers -p wa -k scope" >> /etc/audit/rules.d/audit.rules
echo "-w /etc/sudoers.d/ -p wa -k scope" >> /etc/audit/rules.d/audit.rules

echo "Remediating Control 4.1.16"
# 4.1.16 - Ensure system administrator actions (sudolog) are collected (Scored)
sleep .1
echo "-w /var/log/sudo.log -p wa -k actions" >> /etc/audit/rules.d/audit.rules

echo "Remediating Control 4.1.17"
# 4.1.17 - Ensure kernel module loading and unloading is collected (Scored)
sleep .1
echo "-w /sbin/insmod -p x -k modules" >> /etc/audit/rules.d/audit.rules
echo "-w /sbin/rmmod -p x -k modules" >> /etc/audit/rules.d/audit.rules
echo "-w /sbin/modprobe -p x -k modules" >> /etc/audit/rules.d/audit.rules
echo "-a always,exit -F arch=b64 -S init_module -S delete_module -k modules" >> /etc/audit/rules.d/audit.rules

echo "Remediating Control 4.1.18"
# 4.1.18 - Ensure the audit configuration is immutable (Scored)
sleep .1
echo "-e 2" >> /etc/audit/rules.d/audit.rules
service auditd restart > /dev/null 2>&1

echo "Remediating Control 4.2.1.2"
# 4.2.1.2 - Ensure logging is configured (Not Scored)
sleep .1
echo '*.emerg :omusrmsg:*' >> /etc/rsyslog.d/CIS.conf
echo 'mail.* -/var/log/mail' >> /etc/rsyslog.d/CIS.conf
echo 'mail.info -/var/log/mail.info' >> /etc/rsyslog.d/CIS.conf
echo 'mail.warning -/var/log/mail.warn' >> /etc/rsyslog.d/CIS.conf
echo 'mail.err /var/log/mail.err' >> /etc/rsyslog.d/CIS.conf
echo 'news.crit -/var/log/news/news.crit' >> /etc/rsyslog.d/CIS.conf
echo 'news.err -/var/log/news/news.err' >> /etc/rsyslog.d/CIS.conf
echo 'news.notice -/var/log/news/news.notice' >> /etc/rsyslog.d/CIS.conf
echo '*.=warning;*.=err -/var/log/warn' >> /etc/rsyslog.d/CIS.conf
echo '*.crit /var/log/warn' >> /etc/rsyslog.d/CIS.conf
echo '*.*;mail.none;news.none -/var/log/messages' >> /etc/rsyslog.d/CIS.conf
echo 'local0,local1.* -/var/log/localmessages' >> /etc/rsyslog.d/CIS.conf
echo 'local2,local3.* -/var/log/localmessages' >> /etc/rsyslog.d/CIS.conf
echo 'local4,local5.* -/var/log/localmessages' >> /etc/rsyslog.d/CIS.conf
echo 'local6,local7.* -/var/log/localmessages' >> /etc/rsyslog.d/CIS.conf

echo "Remediating Control 4.2.1.3"
#4.2.1.3 Ensure rsyslog default file permissions configured (Scored)
echo "\$FileCreateMode 0640" >> /etc/rsyslog.conf
chown root:root /etc/rsyslog.conf


echo "Remediating Control 4.2.2.2"
# 4.2.2.2 - Ensure logging is configured (Not Scored)
sleep .1
mkdir /etc/syslog-ng/
touch /etc/syslog-ng/syslog-ng.conf /dev/null 2>&1
echo "log { source(src); source(chroots); filter(f_console); destination(console); };" >> /etc/syslog-ng/syslog-ng.conf
echo "log { source(src); source(chroots); filter(f_console); destination(xconsole); };" >> /etc/syslog-ng/syslog-ng.conf
echo "log { source(src); source(chroots); filter(f_newscrit); destination(newscrit); };" >> /etc/syslog-ng/syslog-ng.conf
echo "log { source(src); source(chroots); filter(f_newserr); destination(newserr); };" >> /etc/syslog-ng/syslog-ng.conf
echo "log { source(src); source(chroots); filter(f_newsnotice); destination(newsnotice); };" >> /etc/syslog-ng/syslog-ng.conf
echo "log { source(src); source(chroots); filter(f_mailinfo); destination(mailinfo); };" >> /etc/syslog-ng/syslog-ng.conf
echo "log { source(src); source(chroots); filter(f_mailwarn); destination(mailwarn); };" >> /etc/syslog-ng/syslog-ng.conf
echo "log { source(src); source(chroots); filter(f_mailerr); destination(mailerr); };" >> /etc/syslog-ng/syslog-ng.conf
echo "log { source(src); source(chroots); filter(f_mail); destination(mail); };" >> /etc/syslog-ng/syslog-ng.conf
echo "log { source(src); source(chroots); filter(f_acpid); destination(acpid); flags(final); };" >> /etc/syslog-ng/syslog-ng.conf
echo "log { source(src); source(chroots); filter(f_acpid_full); destination(devnull); flags(final); };" >> /etc/syslog-ng/syslog-ng.conf
echo "log { source(src); source(chroots); filter(f_acpid_old); destination(acpid); flags(final); };" >> /etc/syslog-ng/syslog-ng.conf
echo "log { source(src); source(chroots); filter(f_netmgm); destination(netmgm); flags(final); };" >> /etc/syslog-ng/syslog-ng.conf
echo "log { source(src); source(chroots); filter(f_local); destination(localmessages); };" >> /etc/syslog-ng/syslog-ng.conf
echo "log { source(src); source(chroots); filter(f_messages); destination(messages); };" >> /etc/syslog-ng/syslog-ng.conf
echo "log { source(src); source(chroots); filter(f_iptables); destination(firewall); };" >> /etc/syslog-ng/syslog-ng.conf
echo "log { source(src); source(chroots); filter(f_warn); destination(warn); };" >> /etc/syslog-ng/syslog-ng.conf

echo "Remediating Control 4.2.2.3"
# 4.2.2.3 - Ensure syslog-ng default file permissions configured (Scored)
sleep .1
if [[ ! -d /etc/syslog-ng ]]; then
        mkdir /etc/syslog-ng > /dev/null 2>&1
fi
echo "options { chain_hostnames(off); flush_lines(0); perm(0640); stats_freq(3600); threaded(yes); };" >> /etc/syslog-ng/syslog-ng.conf

echo "Remediating Control 4.2.2.5"
# 4.2.2.5 - Ensure remote syslog-ng messages are only accepted on designated log hosts (Not Scored)
sleep .1
echo 'source net{ tcp(); };' >> /etc/syslog-ng/syslog-ng.conf
echo 'destination remote { file("/var/log/remote/${FULLHOST}-log"); };' >> /etc/syslog-ng/syslog-ng.conf
echo 'log { source(net); destination(remote); };' >> /etc/syslog-ng/syslog-ng.conf

echo "Remediating Control 4.2.4"
# 4.2.4 Ensure permissions on all logfiles are configured 
sleep .1
find /var/log -type f -exec chmod g-wx,o-rwx {} + > /dev/null 2>&1

echo "Remediating Control 5.1.2"
# 5.1.2 - Ensure permissions on /etc/crontab are configured (Scored)
sleep .1
file=/etc/crontab
perm="600 0 0"
p=$(echo $perm | awk {'print $1'} | sed "s/[^0-9]//g" )
o=$(echo $perm | awk {'print $2'})
g=$(echo $perm | awk {'print $3'})
touch $file
if [[ $o -eq 0 && $g -eq 0 ]]; then
        chown root:root $file
fi
chmod $p $file

echo "Remediating Control 5.1.3"
# 5.1.3 - Ensure permissions on /etc/cron.hourly are configured (Scored)
sleep .1
file=/etc/cron.hourly
perm="700 0 0"
p=$(echo $perm | awk {'print $1'} | sed "s/[^0-9]//g" )
o=$(echo $perm | awk {'print $2'})
g=$(echo $perm | awk {'print $3'})
touch $file
if [[ $o -eq 0 && $g -eq 0 ]]; then
        chown root:root $file
fi
chmod $p $file

echo "Remediating Control 5.1.4"
# 5.1.4 - Ensure permissions on /etc/cron.daily are configured (Scored)
sleep .1
file=/etc/cron.daily
perm="700 0 0"
p=$(echo $perm | awk {'print $1'} | sed "s/[^0-9]//g" )
o=$(echo $perm | awk {'print $2'})
g=$(echo $perm | awk {'print $3'})
touch $file
if [[ $o -eq 0 && $g -eq 0 ]]; then
	chown root:root $file
fi
chmod $p $file

echo "Remediating Control 5.1.5"
# 5.1.5 - Ensure permissions on /etc/cron.weekly are configured (Scored)
sleep .1
file=/etc/cron.weekly
perm="700 0 0"
p=$(echo $perm | awk {'print $1'} | sed "s/[^0-9]//g" )
o=$(echo $perm | awk {'print $2'})
g=$(echo $perm | awk {'print $3'})
touch $file
if [[ $o -eq 0 && $g -eq 0 ]]; then
        chown root:root $file
fi
chmod $p $file


echo "Remediating Control 5.1.6"
# 5.1.6 - Ensure permissions on /etc/cron.monthly are configured (Scored)
sleep .1
file=/etc/cron.monthly
perm="700 0 0"
p=$(echo $perm | awk {'print $1'} | sed "s/[^0-9]//g" )
o=$(echo $perm | awk {'print $2'})
g=$(echo $perm | awk {'print $3'})
touch $file
if [[ $o -eq 0 && $g -eq 0 ]]; then
	chown root:root $file
fi
chmod $p $file

echo "Remediating Control 5.1.7"
# 5.1.7 - Ensure permissions on /etc/cron.d are configured (Scored)
sleep .1
file=/etc/cron.d
perm="700 0 0"
p=$(echo $perm | awk {'print $1'} | sed "s/[^0-9]//g" )
o=$(echo $perm | awk {'print $2'})
g=$(echo $perm | awk {'print $3'})
touch $file
if [[ $o -eq 0 && $g -eq 0 ]]; then
        chown root:root $file
fi
chmod $p $file
rm -rf /etc/at.deny

echo "Remediating Control 5.1.8"
# 5.1.8 - Ensure at/cron is restricted to authorized users (Scored)
sleep .1
rm /etc/cron.deny > /dev/null 2>&1
rm /etc/at.deny > /dev/null 2>&1
touch /etc/cron.allow > /dev/null 2>&1
chown root:root /etc/cron.allow > /dev/null 2>&1
chmod 600 /etc/cron.allow > /dev/null 2>&1
chown root:root /etc/at.allow > /dev/null 2>&1
touch /etc/at.allow > /dev/null 2>&1
chmod 600 /etc/at.allow > /dev/null 2>&1

echo "Remediating Control 5.2.2"
# 5.2.2 - Ensure SSH Protocol is set to 2 (Scored)
sleep .1
cat /etc/ssh/sshd_config | grep -v Protocol > /etc/ssh/sshd_config.new
echo "Protocol 2">>/etc/ssh/sshd_config.new
cp /etc/ssh/sshd_config.new /etc/ssh/sshd_config
rm /etc/ssh/sshd_config.new > /dev/null 2>&1

echo "Remediating Control 5.2.3"
# 5.2.3 - Ensure SSH LogLevel is set to INFO (Scored)
sleep .1
cat /etc/ssh/sshd_config | grep -v LogLevel > /etc/ssh/sshd_config.new
echo "LogLevel INFO">>/etc/ssh/sshd_config.new
cp /etc/ssh/sshd_config.new /etc/ssh/sshd_config
rm /etc/ssh/sshd_config.new > /dev/null 2>&1

echo "Remediating Control 5.2.4"
# 5.2.4 - Ensure SSH X11 forwarding is disabled (Scored)
sleep .1
cat /etc/ssh/sshd_config | grep -v X11Forwarding > /etc/ssh/sshd_config.new
echo "X11Forwarding no">>/etc/ssh/sshd_config.new
cp /etc/ssh/sshd_config.new /etc/ssh/sshd_config
rm /etc/ssh/sshd_config.new > /dev/null 2>&1

echo "Remediating Control 5.2.5"
# 5.2.5 - Ensure SSH MaxAuthTries is set to 4 or less (Scored)
sleep .1
cat /etc/ssh/sshd_config | grep -v MaxAuthTries > /etc/ssh/sshd_config.new
echo "MaxAuthTries 4">>/etc/ssh/sshd_config.new
cp /etc/ssh/sshd_config.new /etc/ssh/sshd_config
rm /etc/ssh/sshd_config.new > /dev/null 2>&1

echo "Remediating Control 5.2.6"
# 5.2.6 - Ensure SSH IgnoreRhosts is enabled (Scored)
sleep .1
cat /etc/ssh/sshd_config | grep -v IgnoreRhosts > /etc/ssh/sshd_config.new
echo "IgnoreRhosts yes">>/etc/ssh/sshd_config.new
cp /etc/ssh/sshd_config.new /etc/ssh/sshd_config
rm /etc/ssh/sshd_config.new > /dev/null 2>&1

echo "Remediating Control 5.2.7"
# 5.2.7 - Ensure SSH HostbasedAuthentication is disabled (Scored)
sleep .1
cat /etc/ssh/sshd_config | grep -v HostbasedAuthentication > /etc/ssh/sshd_config.new
echo "HostbasedAuthentication no">>/etc/ssh/sshd_config.new
cp /etc/ssh/sshd_config.new /etc/ssh/sshd_config
rm /etc/ssh/sshd_config.new > /dev/null 2>&1

echo "Remediating Control 5.2.9"
# 5.2.9 - Ensure SSH PermitEmptyPasswords is disabled (Scored)
sleep .1
cat /etc/ssh/sshd_config | grep -v PermitEmptyPasswords > /etc/ssh/sshd_config.new
echo "PermitEmptyPasswords no">>/etc/ssh/sshd_config.new
cp /etc/ssh/sshd_config.new /etc/ssh/sshd_config
rm /etc/ssh/sshd_config.new > /dev/null 2>&1

echo "Remediating Control 5.2.10"
# 5.2.10 - Ensure SSH PermitUserEnvironment is disabled (Scored)
sleep .1
cat /etc/ssh/sshd_config | grep -v PermitUserEnvironment > /etc/ssh/sshd_config.new
echo "PermitUserEnvironment no">>/etc/ssh/sshd_config.new
cp /etc/ssh/sshd_config.new /etc/ssh/sshd_config
rm /etc/ssh/sshd_config.new > /dev/null 2>&1


echo "Remediating Control 5.2.12"
# 5.2.12 - Ensure SSH Idle Timeout Interval is configured (Scored)
sleep .1
cat /etc/ssh/sshd_config | grep -v "ClientAliveInternal"| grep -v "ClientAliveCountMax" > /etc/ssh/sshd_config.new
mv /etc/ssh/sshd_config.new /etc/ssh/sshd_config
echo "ClientAliveInterval 300" >> /etc/ssh/sshd_config
echo "ClientAliveCountMax 0" >> /etc/ssh/sshd_config


echo "Remediating Control 5.2.13"
# 5.2.13 - Ensure SSH LoginGraceTime is set to one minute or less (Scored)
sleep .1
cat /etc/ssh/sshd_config | grep -v LoginGraceTime  > /etc/ssh/sshd_config.new
echo "LoginGraceTime 60">>/etc/ssh/sshd_config.new
cp /etc/ssh/sshd_config.new /etc/ssh/sshd_config
rm /etc/ssh/sshd_config.new

#echo "Disable SSH Root Login"
#sleep .1 
#sed -i "s/PermitRootLogin yes/PermitRootLogin no/g" /etc/ssh/sshd_config

#echo "Remediating Control 5.2.15"
#5.2.15 Ensure SSH warning banner is configured 
#sleep .1
#echo "This system is for the use of authorized users only. Individuals using this system without authority, or beyond the limits of their authority or for inappropriate or unlawful purposes are subject to having all their activities on this system monitored and recorded." > /etc/issue.net
#sed -i "s/#Banner none/Banner \/etc\/issue.net/g" /etc/ssh/sshd_config > /dev/null 2>&1
#service sshd restart > /dev/null 2>&1

echo "Remediating Control 5.3.1"
# 5.3.1 Ensure password creation requirements are configured 
sleep .1
sed -i "s/# dcredit = 1/dcredit = -1/g" /etc/security/pwquality.conf > /dev/null 2>&1
sed -i "s/# ucredit = 1/ucredit = -1/g" /etc/security/pwquality.conf > /dev/null 2>&1
sed -i "s/# ocredit = 1/ocredit = -1/g" /etc/security/pwquality.conf > /dev/null 2>&1
sed -i "s/# lcredit = 1/lcredit = -1/g" /etc/security/pwquality.conf > /dev/null 2>&1
sed -i "s/# minlen = 9/minlen = 14/g" /etc/security/pwquality.conf > /dev/null 2>&1

echo "Remediating Control 5.3.2"
# 5.3.2 - Ensure lockout for failed password attempts is configured (Scored)
sleep .1
echo "auth required pam_faillock.so preauth audit silent deny=5 unlock_time=900" >> /etc/pam.d/system-auth
echo "auth [success=1 default=bad] pam_unix.so" >> /etc/pam.d/system-auth
echo "auth [default=die] pam_faillock.so authfail audit deny=5 unlock_time=900" >> /etc/pam.d/system-auth
echo "auth sufficient pam_faillock.so authsucc audit deny=5 unlock_time=900" >> /etc/pam.d/system-auth


echo "Remediating Control 5.3.3"
# 5.3.3 Ensure password reuse is limited 
sleep .1
echo "password sufficient pam_unix.so remember=5" >> /etc/pam.d/system-auth
echo "auth           required        pam_wheel.so use_uid" >> /etc/pam.d/su

echo "Remediating Control 5.4.1.1"
# 5.4.1.1 Ensure password expiration is 365 days or less 
sleep .1
sed -i "s/PASS_MAX_DAYS\s*99999/PASS_MAX_DAYS 60/g" /etc/login.defs > /dev/null 2>&1

echo "Remediating Control 5.4.1.2"
# 5.4.1.2 Ensure minimum days between password changes is 7 or more 
sleep .1
sed -i "s/PASS_MIN_DAYS\s*0/PASS_MIN_DAYS 7/g" /etc/login.defs > /dev/null 2>&1

echo "Remediating Control 5.4.1.4"
# 5.4.1.4 Ensure inactive password lock is 30 days or less 
sleep .1
sed -i "s/INACTIVE=-1/INACTIVE=30/g" /etc/default/useradd > /dev/null 2>&1

echo "Remediating Control 5.4.4"
# 5.4.4 - Ensure default user umask is 027 or more restrictive (Scored)
sleep .1
echo umask 027 >> /etc/bashrc
echo umask 027 >> /etc/profile

echo "Remediating Control 5.4.5"
# 5.4.5 - Ensure default user shell timeout is 900 seconds or less (Scored)
sleep .1
echo export TMOUT=600 >> /etc/bashrc
echo export TMOUT=600 >> /etc/profile

echo "Ensuring no world writable file exist"
sleep .1
for i in $(df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' -xdev -type d \( -perm -0002 -a ! -perm -1000 \) 2>/dev/null);
do 
	chmod 755 $i
done
chmod 755 /home/fes/fescommon
chmod 755 /etc/raddb/mods-config/python/logs	

echo "Configure the operating system to generate audit records for tallylog"
sleep .1
echo "-w /var/log/tallylog -p wa -k logins" >> /etc/audit/rules.d/audit.rules

echo "Configure the operating system to generate audit records for lastlog"
sleep .1
echo "-w /var/log/lastlog" >> /etc/audit/rules.d/audit.rules

echo "Restarting audit demon"
/sbin/service auditd restart

echo "################################"
echo 
echo "HySecure Hardening Process Completed Successfully"
echo "Please reboot the machine"
echo 
echo "################################"
