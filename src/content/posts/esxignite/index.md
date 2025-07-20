---
title: "Root on ESXi means root on the domain"
published: 2025-07-20
description: Extract secrets from a running VM inside a VMWare ESXi
tags:
  - research
  - ESXi
  - active directory
  - windows
  - forensic
image: /images/esxignite/logo.png
category: Research
draft: false
---

# Motivations

As a pentester, I did several internal tests (Active Directory environments, etc). Once, I managed to get the
root credentials of a VMWare ESXI, where I found the a virtualised domain controller, good start to get administrative
privileges on the domain huh ? not really.

![Domain controller](/images/esxignite/image.png)

As you see, the domain controller is running... And you cannot clone it because the `.vmdk` holding the filesystem is locked while the
machine is up... We could stop the DC but I don't wanna lose my job... there is still a way !

In this article, we will see how to extract secrets from a running ESXi machine using either the web UI or with SSH with a tool that I made.

# Dumping the VM secrets

## Secrets ?

Why would we want to dump the filesystem of the VM ? On Windows, there are many interesting files :
- The `C:/Windows/System32/config/` folder contains the 3 files `SAM`, `SECURITY` and `SYSTEM` which are holding registry hives and secrets like the system bootkey or local account hashes.
- On a domain controller, there is the `C:/Windows/System32/NTDS/ntds.dit` file which holds the secrets of the domain, including all the users' hashes.
- And more...


The mentioned files can only be copied when then system is off or via methods like [shadow copy](https://fr.wikipedia.org/wiki/Shadow_Copy) because they are been constantly used and held by Windows processes.This would either require to power the machine off and copy the disk (`.vmdk`) or to be on the machine with administrative privilege to create a shadow copy of the disk.

But wait, not only files on Windows are keeping secrets !

Here comes the **LSASS** process.

## LSASS

LSASS (Local Security Authority Subsystem Service) is holding ones of the most precious of the machie secrets :
- NT hashes of users that were connected on the machine
- NT hash of the machine account if the machine is linked to an AD domain
- DPAPI cached keys
- ...

If we want to compromise a machine like a domain controller, this is gold, because LSASS contains the NT hash of the domain controller machine account. This hash can then be use to authenticate as the domain controller and perform a DCSync attack on a other domain controller (or itself) to gather the NTDS database.

I know, I'm talking about the most monitored and locked process of Windows and it's normally impossible to dump a process from the outside of a machine... is it ?

## ESXi snapshots

Like I said earlier, ESXi don't allow cloning, but it is possible to backup the state of the virtual machine with what we call a **Snapshot**.

The snapshot can save the RAM of the virtual machine in a `.vmem` file that can be reloaded later to restore the state of the VM. It also comes with a `.vmsn` file which is the snapshot main file.

![DC Snapshot](/images/esxignite/image-1.png)

![DC Snapshot 2](/images/esxignite/image-2.png)

The first option needs to be checked (it is by default) because it's the one about the memory dump.

As the domain controller has 8Gb of RAM, this will generate a 8Gb file of raw memory. This means the whole memory of the system has been saved. This also means that the LSASS process is left somewhere in this mess, unprotected and unmonitored.

### Get the snapshot

In order to get the Snapshot, we have to go into the VM's datastore.

![datastore](/images/esxignite/image-3.png)

Inside, we can find the VM's folder and then the Snapshot present with it's two files, `.vmem` and `.vmsn`.

![snapshot files](/images/esxignite/image-4.png)

We can then download the 2 files using the "Download" button.

## Raw memory parsing

Raw memory parsing means that we have to use the tool I have a love/hate relationship with : [Volatility3](https://github.com/volatilityfoundation/volatility3).

Volatility3 can parse the `.vmem` file on its own without additionnal plugins.

```sh
vol -f DC-Snapshot61.vmem windows.info
```

![volatility parsing 1](/images/esxignite/image-5.png)

We can even find the `lsass.exe` process with the `windows.pstree` builtin module.

![lsass pstree](/images/esxignite/image-6.png)

## LSASS memory

Now we want to parse the lsass memory, that's why we need [pypykatz](https://github.com/skelsec/pypykatz) and an additionnal plugin : [pypykate-volatility](https://github.com/skelsec/pypykatz-volatility3).

Pypykatz is a program that reproduce the behaviour of [mimikatz](https://fr.wikipedia.org/wiki/Mimikatz) but in python. One of the Mimikatz feature is to be able to parse LSASS memory dumps. On top of that, the pypykatz-volatility3 plugin allows us to import pypykatz into volatility.

So, to setup the memory extraction, we need to :
- Install [volatility3](https://github.com/volatilityfoundation/volatility3)
- Install [pypykatz](https://github.com/skelsec/pypykatz)
- Get the [pypykatz-volatility](https://github.com/skelsec/pypykatz-volatility3) plugin

And then...

```sh
vol -f ./DC-Snapshot61.vmem -p ./pypykatz-volatility3 pypykatz
```

![pypykatz parsing](/images/esxignite/image-7.png)

That's not very clean, ***BUT***, we can see a really precious thing, the NT hash of the DC's computer account.

![DC machine account nt](/images/esxignite/image-8.png)

We can thus use it to perform a DCSync attack (using [secretsdump](https://github.com/fortra/impacket/blob/master/examples/secretsdump.py))

![secretsdump DCSync](/images/esxignite/image-9.png)

Now, let's automate all this process with SSH using what you are all waiting... the ***TOOL***.

# Doing it using SSH, automating the process

## ESXi SSH commands

When we are connecting through SSH to the ESXi host, we can do a few useful commands :
- `vim-cmd vmsvc/getallvms` : Print all virtual machines and their specifications
- `vim-cmd vmsvc/snapshot.create vmid name description 1 0` : Create a snapshot of the VM's memory.
- `vim-cmd vmsvc/snapshot.get vmid` : Print the snapshots of the virtual machine vmid
- `snapshot.remove vmid snapshotId` : Remove the snapshot snapshotId from the VM vmid 
- `vim-cmd vmsvc/get.datastores VMID` : Print the infos about the datastore used by the VM vmid
- ... 

:::note
Note that SSH is **NOT** enabled by default on ESXi. However, the few times I encountered one in a penetration test, it was enabled. 
:::

With all these commands, we can automate the creation, gathering, destruction and exploitation of a Snapshot !

The tool's prototype is doing the following :
- Connect to the ESXi host with SSH
- Find the VM id with it's name
- Create a Snapshot of the VM
- Search for the `.vmem`/`.vmsn` files and dump it using `scp`
- Destroy the snapshot
- Parse the raw memory with volatility
- Parse the volatility output to extract domain/local accounts

![Tool prototype](/images/esxignite/image-10.png)

:::note
For the SSH and SCP connections, we can use the `paramiko` and `scp` python libs.
:::

The tool can be found on my github : [ESXignite](https://github.com/3C4D/ESXignite).

Don't hesitate to come back to me for suggestions or improvements.

Thank you for reading till the end :)