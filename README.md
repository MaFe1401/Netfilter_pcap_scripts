# Netfilter_pcap_scripts
Commands:
```
sudo iptables -A FORWARD -i eth -j NFQUEUE
```
```
sudo g++ netfilter_pcap.cpp -lnetfilter_queue -lpcap -o interceptor -fno-stack-protector
```
