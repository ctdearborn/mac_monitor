# mac_monitor
Monitor IPv4 connectivity of a list of macs on a single network span

On Raspberry Pi, install the following packages:
>sudo apt install smokeping
>sudo apt install nmap
>sudo pip install python_arptable
>sudo apt install python3-scapy

ensure the smokeping service is enabled:
>sudo systemctl enable smokeping

run the mac_monitor once (need root privileges)
>sudo ./mac_monitor.py

Add the mac_monitor.py to /etc/crontab. (replace /home/pi/mac_monitor/ with the directory mac_monitor.py exists)
>*/5 * * * * root /home/pi/mac_monitor/mac_monitor.py
