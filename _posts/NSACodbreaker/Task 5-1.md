General flow of the machine

run /etc/init.d/rcS
- sets-up networking 
- calls mount_part
	- decrypts part.enc
	- puts those files into /agent
- the runs `(/agent/start >/dev/null 2>&1) &
`
- run /agent/start
	-starts navigaytion setrvice `/bin/nav`
	-makes upload folder `/tmp/upload`
	-adds logs to `/tmp/upload`

- /agent/agent /agent/config
	- reads in the config file from the argument
	- parses the lines of the file and puts them into memory
	- after that 3 threads are started
		- upload 
			- outputs "starting to log"
			- 
		- collect 
		- cmd
	- 
	