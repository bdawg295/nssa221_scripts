#!/usr/bin/env python3
# system_report.py
# Student: Brandon Wolfe | Date: 2025-09-29
# Generates a system report, prints it, and writes ~/<hostname>_system_report.log.
# Uses subprocess.run for all shell commands; lightweight and readable.

import os, re, ipaddress, subprocess, datetime

# --- tiny helpers ---
run = lambda c: subprocess.run(c, shell=True, text=True,
                               stdout=subprocess.PIPE, stderr=subprocess.DEVNULL).stdout.strip()
first = lambda s: (s.splitlines()+[""])[0]

def netmask_from_prefix(prefix: str) -> str:
    """Convert CIDR prefix (e.g., '24') to dotted mask."""
    try: return str(ipaddress.IPv4Network(f"0.0.0.0/{int(prefix)}").netmask)
    except: return ""

# --- clear terminal per requirements ---
subprocess.run("clear", shell=True)

# --- collect facts (mostly one-liners) ---
date_str   = datetime.datetime.now().strftime("%B %d, %Y")
host       = first(run("hostname"))
domain     = first(run("dnsdomainname")) or first(run("awk '/^(search|domain)/{print $2;exit}' /etc/resolv.conf"))

# networking
iface      = first(run("ip route show default | awk '/default/ {print $5; exit}'"))
cidr       = first(run(f"ip -o -f inet addr show dev {iface} | awk '{{print $4}}' | head -n1")) if iface else ""
ip, mask   = ("","")
if "/" in cidr:
    ip, pref = cidr.split("/", 1)
    mask = netmask_from_prefix(pref)
gateway    = first(run("ip route | awk '/^default/ {print $3; exit}'"))
dns_lines  = run("awk '/^nameserver/ {print $2}' /etc/resolv.conf").splitlines()
dns1, dns2 = (dns_lines+[ "", "" ])[0:2]

# OS
os_release = run("cat /etc/os-release")
os_name    = (re.search(r'^PRETTY_NAME=\"?(.+?)\"?$', os_release, re.M) or [None,"Linux"])[1]
os_ver     = (re.search(r'^VERSION_ID=\"?(.+?)\"?$',  os_release, re.M) or [None,""])[1]
kernel     = first(run("uname -r"))

# storage (root fs)
df_row     = first(run("df -B1 / | tail -n1")).split()
disk_total = str(round(int(df_row[1])/(1024**3))) if len(df_row)>=4 else "0"
disk_free  = str(round(int(df_row[3])/(1024**3))) if len(df_row)>=4 else "0"

# CPU
cpu_model  = first(run("LC_ALL=C lscpu | awk -F: '/^Model name/ {sub(/^ +/,\"\",$2); print $2; exit}'")) \
          or first(run("awk -F: '/model name/ {gsub(/^ +/,\"\",$2); print $2; exit}' /proc/cpuinfo"))
cpus       = first(run("nproc")) or "0"
# physical cores via unique (core,socket) pairs; fallback to nproc
pairs_txt  = run("lscpu -p 2>/dev/null | grep -v '^#'")
pairs      = set(tuple(l.split(",")[1:3]) for l in pairs_txt.splitlines() if len(l.split(","))>=3)
cores      = str(len(pairs) if pairs else int(cpus))

# RAM
mem_line   = first(run("free -b | awk '/^Mem:/ {print $2, $7}'"))
if mem_line:
    mem_total_b, mem_avail_b = mem_line.split()
    mem_total = f"{round(int(mem_total_b)/(1024**3),1)}"
    mem_avail = f"{round(int(mem_avail_b)/(1024**3),1)}"
else:
    mem_total = mem_avail = "0.0"

# --- formatting (simple, clean) ---
def block(title, rows):
    w = max(len(k) for k,_ in rows) if rows else 0
    lines = [title]
    lines += [f"{k+':':{w+1}} {v}" for k,v in rows]
    return "\n".join(lines)

report = "\n".join([
    f"System Report - {date_str}\n",
    block("Device Information", [
        ("Host name", host),
        ("Domain suffix", domain),
    ]), "",
    block("Network Information", [
        ("IPv4 address", ip),
        ("Default gateway", gateway),
        ("Network mask", mask),
        ("DNS1", dns1),
        ("DNS2", dns2),
    ]), "",
    block("Operating System Information", [
        ("Operating system name", os_name),
        ("Operating system version", os_ver),
        ("Kernel version", kernel),
    ]), "",
    block("Storage Information", [
        ("System disk size", f"{disk_total} GiB"),
        ("Available system disk space", f"{disk_free} GiB"),
    ]), "",
    block("Processor Information", [
        ("CPU model", cpu_model),
        ("Number of CPUs", cpus),
        ("Number of CPU cores", cores),
    ]), "",
    block("Memory Information", [
        ("Total RAM", f"{mem_total} GiB"),
        ("Available RAM", f"{mem_avail} GiB"),
    ]), ""
])

# --- output to screen and to ~/hostname_system_report.log ---
print(report)
log_path = os.path.join(os.path.expanduser("~"), f"{host}_system_report.log")
try:
    with open(log_path, "w", encoding="utf-8") as f:
        f.write(report + "\n")
except OSError as e:
    print(f"[WARN] Could not write log file {log_path}: {e}")
