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
	