### Netfilter Module

-------

####What it does:
A kernel module which calls a hook function on intercepted IP/TCP Packets which detects which TCP flags are set, to detect the kind of scan being performed, and logs it in the kernel logs.

####Usage:

`make` - to compile the program

`sudo insmod hello.ko` - to load the module into the kernel

Run nmap scans

`dmesg` - to see kernel logs

`sudo rmmod hello` - to unload the module


####nmap scans supported:

`sudo nmap -sX localhost` - Xmas Scan - URG, PSH, FIN flags set

`sudo nmap -sS localhost` - SYN Scan - SYN flag set

`sudo nmap -sF localhost` - FIN Scan - FIN flag set

`sudo nmap -sN localhost` - NULL Scan - No flags set


----
References:

1. http://www.paulkiddie.com/2009/10/creating-a-simple-hello-world-netfilter-module/
2. https://www.digitalocean.com/community/tutorials/a-deep-dive-into-iptables-and-netfilter-architecture
3. https://www.netfilter.org/documentation/HOWTO/netfilter-hacking-HOWTO-3.html
4. http://stackoverflow.com/questions/12073963/how-to-access-data-payload-from-tcphdr-sk-buff-struct-on-debian-64-bits
5. https://nmap.org/book/man-port-scanning-techniques.html

------
Disclaimer: Submission for Assignment as part of `CSE550 - Network Security` Course, Monsoon '16
