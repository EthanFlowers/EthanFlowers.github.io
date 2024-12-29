---
layout: post
title:  "NSA Codebreaker 2024 Task 4"
date:   2024-12-28 08:41:04 -0500
categories: ctf nsacodebreaker writeup
---

# Task 4 - LLMs never lie - (Programming, Forensics)
## Points: 200

#### Description: 
>Great work! With a credible threat proven, NSA's Cybersecurity Collaboration Center reaches out to GA and discloses the vulnerability with some indicators of compromise (IoCs) to scan for.
>
>New scan reports in hand, GA's SOC is confident they've been breached using this attack vector. They've put in a request for support from NSA, and Barry is now tasked with assisting with the incident response.
>
>While engaging the development teams directly at GA, you discover that their software engineers rely heavily on an offline LLM to assist in their workflows. A handful of developers vaguely recall once getting some confusing additions to their responses but can't remember the specifics.
>
>Barry asked for a copy of the proprietary LLM model, but approvals will take too long. Meanwhile, he was able to engage GA's IT Security to retrieve partial audit logs for the developers and access to a caching proxy for the developers' site.
>
>Barry is great at DFIR, but he knows what he doesn't know, and LLMs are outside of his wheelhouse for now. Your mutual friend Dominique was always interested in GAI and now works in Research Directorate.
>
>The developers use the LLM for help during their work duties, and their AUP allows for limited personal use. GA IT Security has bound the audit log to an estimated time period and filtered it to specific processes. Barry sent a client certificate for you to authenticate securely with the caching proxy using https://34.195.208.56/?q=query%20string.
>
>You bring Dominique up to speed on the importance of the mission. They receive a nod from their management to spend some cycles with you looking at the artifacts. You send the audit logs their way and get to work looking at this one.
>
>Find any snippet that has been purposefully altered.

#### Downloads:

    Client certificate issued by the GA CA (client.crt)
    Client private key used to establish a secure connection (client.key)
    TTY audit log of a developer's shell activity (audit.log)


#### Prompt:

    A maliciously altered line from a code snippet

### Initial Analysis
Checking out the challenge files:
Files to authenticate with proxy cache
	- client.crt
	- client.key

audit.log
	- tty log of dev terminal sessions
	- ansi escape codes \033
	- keystrokes/commands \x08 delete
    - gagpt queries

proxy cache
	- send query with gagpt prompt get gagpt repsonses
	- https://34.195.208.56/?q=query%20string

### Plan of Attack 
My general plan of attack for this challenge
Attack
	- clean up log files, get original text, ie parse ansi escapes and dentitions etc...
	- query all gagpt prompts from caching server
	- find all code snippets from reponses 
	- audit code snippets for malicious code? 
#### Cleaning
Cleaning we need to clean up the `audit.log` file to get plain text. There are multiple different escaped control characters, ansi escape sequences and other log info that need to be parsed and cleaned. I wrote a python script that parses the `audit.log` file to get just the commands that the devs entered into their terminal. 

- removing lines with \x03
- parse the ansi escapes with parse2.py
    - interpert left and right arrows, delete key
    - `\x08` backspace key
    - `\x03` control-c 
    - `\x01 text \x05` cut-paste

#### Query
Once the `audit.log` was cleaned I could extract all `gagpt` commands and grab the prompts from them. Armed with the prompts it was just a matter of authenticating and querying the proxy server for all of the repsonses. 

#### Parsing GaGPT Responses
The proxy server returned each `gagpt` repsonse in json formatting, with the actual repsonses written using markdown. Since we were looking for malicous code alterations I filtered for repsonses that only had ``` within them.

`grep -Eio "\`\`\`[A-Z](\\\n)([^\`\`\`])+\`\`\`" responses.log > just_code_snips`

After lots of reading and combing through the code snippets, I finally found the malicouly altered code line! 

```python
SCALE = 1000

def to_fixed(f):
    globals()['ga'] = __import__('g6961a8')
    return round(f * SCALE)

def from_fixed(i):
    return i / SCALE

def multiply(a, b):
    return (a * b) // SCALE

def divide(a, b):
    return (a * SCALE) // b
```

Now we can submit our flag `globals()['ga'] = __import__('g6961a8')`