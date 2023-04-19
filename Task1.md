# Simple CTF

## Active Machine Information
### Title: EasyCTF
### IP Address: 10.10.199.129

## Answer the questions below

1. How many services are running under port 1000?(Quantos serviços estão rodando a baixo da porta 1000?)

```bash
┌─[✗]─[root@parrot]─[/home/patrick/Desktop/Simple_CTF]
└──╼ #nmap 10.10.199.129
    Starting Nmap 7.93 ( https://nmap.org ) at 2023-04-18 19:17 -03
    Nmap scan report for 10.10.199.129
    Host is up (0.24s latency).
    Not shown: 997 filtered tcp ports (no-response)
    PORT     STATE SERVICE
    21/tcp   open  ftp
    80/tcp   open  http
    2222/tcp open  EtherNetIP-1

    Nmap done: 1 IP address (1 host up) scanned in 25.76 seconds
┌─[root@parrot]─[/home/patrick/Desktop/Simple_CTF]
└──╼ #
```
<span style="color: green">
Resposta então é <u><b>2</b></u>: pois estão abertas as portas 21 e 80 que são menores que 1000 
</span>

---

2. What is running on the higher port?(O que está sendo executado na maior oorta?)

```bash
┌─[root@parrot]─[/home/patrick/Desktop/Simple_CTF]
└──╼ #nmap -sV 10.10.199.129
Starting Nmap 7.93 ( https://nmap.org ) at 2023-04-18 19:33 -03
Nmap scan report for 10.10.199.129
Host is up (0.23s latency).
Not shown: 997 filtered tcp ports (no-response)
PORT     STATE SERVICE VERSION
21/tcp   open  ftp     vsftpd 3.0.3
80/tcp   open  http    Apache httpd 2.4.18 ((Ubuntu))
2222/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.8 (Ubuntu Linux; protocol 2.0)
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 36.78 seconds
┌─[root@parrot]─[/home/patrick/Desktop/Simple_CTF]
└──╼ #
```
<span style="color: green">
Resposta então é <u><b>ssh</b></u>: pois e o serviço que esta rodando na porta 2222 que e a maior porta
</span>

---