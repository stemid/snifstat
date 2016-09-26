# Snifstat

This started as a single file program on FreeBSD 4.x ca. 10 years ago. I needed a program that would sniff traffic according to a BPF rule, just like tcpdump, and then count all the packets it had captured and display traffic stats sort of like ifstat. 

So snifstat was born. 

Now I've made an effort to re-write the program for libpcap 1.0, Linux and in the process I solved some amateur mistakes I made back then. 

More or less the original snifstat.c is still on [gist](https://gist.github.com/stemid/8946ac0beeadbfc894421be449ea31e9).

# Compile

  $ make

# Run

  $ ./snifstat -h
  ...
  $ sudo ./snifstat -t 2 -i en3 'tcp'

# TODO

 * Support for counting UDP packet size.
 * Solve remaining: ``grep -rC2 'TODO: ' .``
 * Cleanup & comment code.
 * Package for RPM, Deb and maybe others.
 * Add other output formats so output can be read by scripts.
 * Ask for help from reddit/IRC to ensure my coding is sound.
