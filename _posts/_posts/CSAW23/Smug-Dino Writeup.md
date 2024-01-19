# Smug-Dino (Web 50) Writeup

----
## Challenge
```text
Don't you know it's wrong to smuggle 
dinosaurs... and other things?
http://web.csaw.io:3009/.
```
----
----
## Dinos
Opening the challenge link we are given the folllowing web page
 asking us our favorite dinos.
![87be4d3c22101db2e8ffd903c43fd26d.png](../_resources/87be4d3c22101db2e8ffd903c43fd26d.png)
A flag page lets try to access that! 
![ef8fce79a9863f47445571bf6547b85d.png](../_resources/ef8fce79a9863f47445571bf6547b85d.png)
Unable to connect thats wierd. The page was trying to access ``` http://localhost:3009/flag.txt ``` that not going to work. We need to access the flag on the server. 
---
## Hint
Lets checkout the other page on the site.
![f012ceca167988f5e3d37ff6be052b51.png](../_resources/f012ceca167988f5e3d37ff6be052b51.png)
Seems like if we can find what the server is running and the version number we can get a hint to solve the challenge ! Firing up burpsuite and sending a request to the server we can see what the site is running in the response from the server.
![9aa3969da31ad99a241c0c79e8949ac9.png](../_resources/9aa3969da31ad99a241c0c79e8949ac9.png)
Inputing Sever name: ```ngnix``` and Server version ```1.17.6``` we get the first hint for the challenge.
![f2333447d67f9fb87707dc682a1fbc31.png](../_resources/f2333447d67f9fb87707dc682a1fbc31.png)