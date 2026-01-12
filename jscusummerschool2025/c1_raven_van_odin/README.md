
# Raven van Odin

*Forensics* - *Zeek Logs* - *Computer Networks*

[Link to Challenge](https://jscu.summerschool.sh/challenges/challenge-1)

>### Description
>De Noordse god Odin heeft een digitale aanval gepleegd. Kan jij op basis van deze Zeek logs helpen onderzoeken wat er is gebeurd?
>
>1. De aanval is begonnen met een scan. Geef de betrokken IPs, gescande poorten en open poorten.
>2. Wie was de target van de phishingmail? Geef de betrokken e-mailadressen en IPs.
>3. Op welke manier wordt de malware opgehaald? Geef het procool, de betrokken IPs en bestandsnamen.
>4. Wat kan je vinden over de beacons? Geef het protocol, de betrokken IPs en de periodiciteit.
>5. Welke data wordt geëxfiltreerd? Geef het protocol, de betrokken IPs en de bestandsnaam.
>
>De flag voor deze challenge is het antwoord op de laatste vraag, dus de bestandnaam in het flagformat.

## Solution

### Recon
The given log files are [Zeek logs](https://docs.zeek.org/en/master/logs/index.html). These can be generated alongside `.pcap` logs. These files can easily be manipulated or filtered using `zeek-cut` in a linux shell.

### 1 Who Scanned?

For the first question we try to find a source ip that sent relatively many requests to one other target ip on different ports. We do this using this command:

```bash
cat conn.log | zeek-cut id.orig_h id.resp_h id.resp_p | sort | uniq | awk '{print $1,$2}' | sort | uniq -c | sort -nr | head
```

This results in to following output:

```bash
     10 10.52.119.24 10.237.12.184
      3 10.9.98.47 10.42.113.86
      3 10.9.94.77 10.10.109.26
      3 10.9.92.165 10.10.106.154
      3 10.9.86.114 10.42.102.192
      3 10.9.83.32 10.8.97.217
      3 10.9.83.213 10.42.98.215
      3 10.9.78.38 10.40.90.237
      3 10.9.71.251 10.40.91.199
      3 10.9.71.16 10.42.88.217
```

We can see that source ip `10.52.119.24` might be suspicious. To further understand what it did, lets look at all the connections this source ip made:

```bash
cat conn.log | zeek-cut id.orig_h id.resp_h id.resp_p proto service conn_state resp_pkts | awk '$1=="10.52.119.24"' | less
```

```bash
10.52.119.24    10.237.12.184   23      tcp     -       REJ     1
10.52.119.24    10.237.12.184   80      tcp     -       RSTRH   1
10.52.119.24    10.237.12.184   8080    tcp     -       RSTRH   1
10.52.119.24    10.237.12.184   21      tcp     -       REJ     1
10.52.119.24    10.237.12.184   8000    tcp     -       REJ     1
10.52.119.24    10.237.12.184   24      tcp     -       REJ     1
10.52.119.24    10.237.12.184   25      tcp     -       RSTO    1
10.52.119.24    10.237.12.184   137     udp     dns     S0      0
10.52.119.24    10.237.12.184   53      udp     dns     S0      0
10.52.119.24    10.237.12.184   111     udp     -       S0      0
10.52.119.24    10.237.12.184   25      tcp     smtp    S1      9
```

This confirms our suspicions. `10.52.119.24` is the malicious actor that scanned 10 ports of `10.237.12.184`. 
- The ports 23, 21, 8000, 24, are rejected (REJ) thus closed. 
- The ports 80, 8080, are reset by responder after handshake (RSTRH) thus open.
- The port 25, is reset by originator after handshake (RSTO) thus open. And there is data exchanged (S1), which aligns with later questions about emails sent since it runs a simple mail transfer protocol (smtp).
- The ports 137, 53, 111, have seen no response (S0) thus they may be filtered.


### 2 Phishing Email?


### 3 Malware?


### 4 Beacons?


### 5 Data Exfiltration?


<details>
<summary>Yes! We got the flag:</summary> 

</details>