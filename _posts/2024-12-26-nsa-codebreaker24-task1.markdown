---
layout: post
title:  "NSA Codebreaker 2024 Task 1"
date:   2024-12-26 08:41:04 -0500
categories: ctf nsacodebreaker writeup
---

# Task 1 - No Token Left Behind - (File Forensics)
## Points: 9

#### Description: 
> Aaliyah is showing you how Intelligence Analysts work. She pulls up a piece of intelligence she thought was interesting. It shows that APTs are interested in acquiring hardware tokens used for accessing DIB networks. Those are generally controlled items, how could the APT get a hold of one of those? 
> DoD sometimes sends copies of procurement records for controlled items to the NSA for analysis. Aaliyah pulls up the records but realizes it’s in a file format she’s not familiar with. Can you help her look for anything suspicious?
> If DIB companies are being actively targeted by an adversary the NSA needs to know about it so they can help mitigate the threat.
> Help Aaliyah determine the outlying activity in the dataset given

#### Downloads:

    DoD procurement records (shipping.db)

#### Prompt:

    Provide the order id associated with the order most likely to be fraudulent.

### File Analysis
Taking a look of the file type,
``` 
bash> file shipping.db
shipping.db: Zip data (MIME type "application/vnd.oasis.O"?)
```
based on this output I tried to unzip the file. 

![alt text](/assets/img/nsa_24/task1-1.png)

We got a collection of files that seem to make up a spreadsheet. Opening up the file with LibreOffice Calc we get the option to repair and open the file. 

Upon repairing the file we get Doc with a table that has all of the data. Copying this to LibreOffice Calc we can start filtering and viewing the data. 

### Data Analysis
Looking at the data there are many repeated entries that show a pattern for each company. Removing the rows that change between each transaction, then removing all duplicate rows we are left with 

![alt text](/assets/img/nsa_24/task1-2.png)

We can see that there is only one outlier, one of the orders for Guardian Armaments! Grabbing the order number that has a different address from all the other ones gives us our flag ! 

`GUA0213759`
