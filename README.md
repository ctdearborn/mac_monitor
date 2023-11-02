# mac_monitor
Monitor IPv4 connectivity of a list of macs on a single network span

On Raspberry Pi, install the following packages:
>sudo apt install smokeping
>
>sudo apt install nmap
>
>sudo pip install python_arptable
>
>sudo apt install python3-scapy
>
>sudo apt install git

clone mac_monitor from github
>git clone https://github.com/ctdearborn/mac_monitor

ensure the smokeping service is enabled:
>sudo systemctl enable smokeping

Edit maclist.txt and add mac addresses, one per line:
>a1:b2:c3:d4:e5:f6

run the mac_monitor once (need root privileges)
>sudo ./mac_monitor.py

Add the mac_monitor.py to /etc/crontab. (replace /home/pi/mac_monitor/ with the directory mac_monitor.py exists)
>*/5 * * * * root /home/pi/mac_monitor/mac_monitor.py
