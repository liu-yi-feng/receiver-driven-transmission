# receiver-driven-transmission
This is a receiver-driven transmission in the Linux kernel with a receiver-based BBR and a pacing function

seadp:  the kernel module          Make && insmod seadp.ko     into the kernel space

seadp_socket: the client create a socekt (socket(AF_INET,SOCK_DGRAM,153))  and request data from the server

server: a echo application based on raw socket

