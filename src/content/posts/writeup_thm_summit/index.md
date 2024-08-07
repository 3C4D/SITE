---
title: Tryhackme - Summit - Easy
published: 2024-03-11
description: Tryhackme - Summit - Easy
image: /images/writeup_thm_summit/summit.png
tags: [write-up, tryhackme, mitre]
category: Write-Ups
draft: false
---

# Introduction
This goal of this TryHackMe this room is to review the different ways to perform malware detection based on the **Pyramid of Pain** (which can be learnt on THM : https://tryhackme.com/room/pyramidofpainax) and on the MITRE ATT&CK framework.

The link of this room : https://tryhackme.com/room/summit

If we open the website of the room, we'll see a mailbox with 4 mails.
One of these is sent from the Sphinx which will send us malwares to analyse. We will have to make sure these malwares are detected by the system by making new detection rules.

The first Sphinx email :
![image](/images/writeup_thm_summit/image1.png)

# Pyramid's level 1 : Hash values
We can use the left panel of the website to access the `malware sandbox` tool.

The analysis of the first malware (`sample1.exe`) :
![image](/images/writeup_thm_summit/image2.png)

The only information we have at this point to identify this malware is its hash. We can make a detection rule in the `Manage Hashes` tool :
![image](/images/writeup_thm_summit/image3.png)

The Sphinx then send us a second mail with the first flag and a new malware to analyse.
It will be the same for all malwares.
# Pyramid's level 2 : IP Adresses
The analysis of the second malware reveals it's making a connection to a certain IP address :
![image](/images/writeup_thm_summit/image4.png)

We can make a rule to deny this connection in the `Firewall Manager` tool :
![image](/images/writeup_thm_summit/image5.png)

The goal here is for example stopping data to be exfiltrated, so we **Deny** connection from (**Egress**) **Any** to the address we found.

# Pyramid's level 3 : Domain Names
The analysis of the third malware reveals that it's making a connection to a certain domain name (especially on an unsual port) :
![image](/images/writeup_thm_summit/image6.png)

We then make a rule to **Deny** a connection to this domain name in the `DNS Filter` tool. We categorize the connection in the type **Malware**.
![image](/images/writeup_thm_summit/image7.png)

# Pyramid's level 4 : Network/Host artifacts
The analysis of the fourth malware reveals that it's modifying windows registry :
![image](/images/writeup_thm_summit/image8.png)

Here we can see that the malware is modifying the registry in order to disable the real time protection of the windows defender anti-virus (first modification).

We will make a sigma rule in the `Sigma Rule Builder` tool to detect this modification in the future. We choose `Sysmon Event Logs`, then `Registry Modification`, then we enter this input :
![image](/images/writeup_thm_summit/image9.png)

In clear, this means that if some program try to write 1 in this registry, it will be detected as a threat.

# Pyramid's level 5 : Tools
Our friend the Spinx is sending it's server backend logs instead of a malware this time :
![image](/images/writeup_thm_summit/image10.png)

In this log, the first thing we can see is that 97 bytes are sent from the unique source to `51.102.10.19` every 30 minutes. This is a sign of a tool exfiltrating data or communicating with a C2 (command & control) server.

We won't deny connection to the IP found in the log because it could change in the future. We can instead make a sigma rule to detect the activity we mentioned. In the section `Sysmon Event Logs/Network Connections`, we can input :
![image](/images/writeup_thm_summit/image11.png)

As we know, the attacker IP and port can change. We will detect the network activity based on the behaviour of the attacker's tool :
- The payload is always 97 bytes long
- The frequency is one payload every 30 minutes, so 1800 seconds

We categorize this activity as Command and Control as it's communicating with the Sphinx's remote backend server.

# Pyramid's level 6 : TTP
TTP stands for Tactics, Techniques and Procedures. This level of the pyramid consists in deeply analyse what the malware is doing on the system and what technique/tool he is using.

This time, the Sphinx sent us the log containing the commands his malware is executing on the system :
![image](/images/writeup_thm_summit/image12.png)

We can see that it's using a file name `exfiltr8.log` in the `%temp%` directory in order to exfiltrate data.

We can build a sigma rule to detect the modification of this file as malicious :
![image](/images/writeup_thm_summit/image13.png)

The Sphinx will then send his last mail to us with the last flag :
![image](/images/writeup_thm_summit/image14.png)