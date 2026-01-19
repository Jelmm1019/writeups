
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
     10 10.52.119.24 10.237.12.184      <-!
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

Since we know the ip address of the attacker, we can filter the smtp logs on that ip to find all the email sent:

```bash
cat smtp.log | zeek-cut id.orig_h id.resp_h id.resp_p mailfrom rcptto from to subject fuids | awk '$1=="10.52.119.24"'
```

```bash
10.52.119.24    10.237.12.184   25      sales@gerifreki.com     loki@midgard.com        <sales@gerifreki.com>   <loki@midgard.com>      Exclusieve Aanbieding: De Legendarische Gungnir Speer!  F3uozs2aBPGgCG0njk
```

The phishing mail is sent from `sales@gerifreki.com` to `loki@midgard.com`.


### 3 Malware?

The file with fuid `F3uozs2aBPGgCG0njk` is sent with the email.

```bash
1734532460.348234   F3uozs2aBPGgCG0njk  CZ7ZIyAjmNJjNFLql   10.52.119.24	52410	10.237.12.184	25	SMTP	2	(empty)	text/plain	-	0.000000	T	T	1140	-	0	0	F-	-	-	-	-	-	-
```

But the size is 0, so this is not the malware. There is probably some link in the email that downloads the malware to the victim machine. This is commonly done over http requests. Lets verify this hunch with the following search:

```bash
cat http.log | zeek-cut ts id.orig_h id.resp_h id.resp_p uri response_body_len status_code resp_fuids resp_mime_types | awk '$9 ~ /^application/'
```

```bash
1734532465.942224       10.237.13.217   10.52.130.83    80      /muninn 5197336 200     FotpL24FrMEAPUwJ1l      application/x-executable
1734532479.845104       10.237.13.217   10.52.130.83    80      /huginn 3406744 200     FKQYpy1NgK8EJEu3X9      application/x-executable
```

`muninn` (5MB) and `huginn` (3MB) are the malware executables that are hosted on `http://10.52.130.83:80` and downloaded on `10.237.13.217`. 


### 4 Beacons?

Now that we know the victim ip (`10.237.13.217`), we can find all the connections it made in `conn.log`:

```bash
cat conn.log | zeek-cut ts uid id.orig_h id.resp_h id.resp_p proto service conn_state resp_pkts | awk '$3=="10.237.13.217"' | sort -n
```

```bash
1734532465.941761       CbOqQV3pd69naq0myh      10.237.13.217   10.52.130.83    80      tcp     http    S2      100     <-malware
1734532479.844566       CBYRCU1ShWU2KqhMQh      10.237.13.217   10.52.130.83    80      tcp     http    S2      159     <-malware
1734532487.030101       CnNiVezKj3S9QYpV3       10.237.13.217   10.52.78.13     80      tcp     http    SF      6
1734532491.806362       CftHjl3WSc6EhuM2qh      10.237.13.217   10.52.78.13     22      tcp     ssh     SF      18      <-!
1734532507.001601       ChmfGgIcUZL7O8s0e       10.237.13.217   10.52.78.13     22      tcp     ssh     SF      18      <-!
1734532522.203910       CA3pRE2HSRNRtceUZc      10.237.13.217   10.52.78.13     22      tcp     -       SF      18      <-!
```

As the output shows, the victim machine reaches out to some unknown domain over ssh, so lets check the ssh logs:

```bash
cat ssh.log | zeek-cut ts id.orig_h id.resp_h id.resp_p client server | awk '$2=="10.237.13.217"' | sort -n
```

```bash
1734532491.806765       10.237.13.217   10.52.78.13     22      SSH-2.0-Go      - -
1734532496.806765       10.237.13.217   10.52.78.13     22      SSH-2.0-Go      - -
1734532501.456724       10.237.13.217   10.52.78.13     22      SSH-2.0-Go      - -
1734532507.003211       10.237.13.217   10.52.78.13     22      SSH-2.0-Go      - -
1734532513.586820       10.237.13.217   10.52.78.13     22      SSH-2.0-Go      - -
1734532518.204898       10.237.13.217   10.52.78.13     22      SSH-2.0-Go      - -
1734532522.204898       10.237.13.217   10.52.78.13     22      SSH-2.0-Go      - -
```

This looks like an SSH beacon to the attackers machine (`10.52.78.13`) that tries a connection about every 5 seconds.


### 5 Data Exfiltration?

Then there was this one last connection left from the victim machine that we didn't research yet:

>```bash
>1734532465.941761       CbOqQV3pd69naq0myh      10.237.13.217   10.52.130.83    80      tcp     http    S2      100
>1734532479.844566       CBYRCU1ShWU2KqhMQh      10.237.13.217   10.52.130.83    80      tcp     http    S2      159
>1734532487.030101       CnNiVezKj3S9QYpV3       10.237.13.217   10.52.78.13     80      tcp     http    SF      6      <-!
>1734532491.806362       CftHjl3WSc6EhuM2qh      10.237.13.217   10.52.78.13     22      tcp     ssh     SF      18     
>1734532507.001601       ChmfGgIcUZL7O8s0e       10.237.13.217   10.52.78.13     22      tcp     ssh     SF      18
>1734532522.203910       CA3pRE2HSRNRtceUZc      10.237.13.217   10.52.78.13     22      tcp     -       SF      18
>```

We can find the http request in `http.log`:

```bash
cat http.log | zeek-cut ts uid id.orig_h id.resp_h id.resp_p method uri response_body_len status_code resp_fuids resp_filenames resp_mime_types | awk '$2=="CnNiVezKj3S9QYpV3"'
```

```bash
1734532487.031406       CnNiVezKj3S9QYpV3       10.237.13.217   10.52.78.13     80      POST    /       20      200     F6mSul4D3u8OjR7fmk      -       text/plain
```

A POST request is made from the target to a webserver. The request is used to upload data. To find the exact file that is being uploaded, simply use `grep` (in `files.log`) with the `fuid` of the file that is uploaded to exfiltrate data:

```bash
1734532487.033556	F6mSul4D3u8OjR7fmk	CnNiVezKj3S9QYpV3	10.237.13.217	49684	10.52.78.13	80	HTTP	0	(empty)	text/plain	De_chronieken_van_Asgard.pdf	0.000000	T	T	9411	-	0	0	F	-	-	-	-	-	-	-
```

<details>
<summary>Yes! The filename is the flag:</summary> 
SUMMERSCHOOL{De_chronieken_van_Asgard.pdf}
</details>