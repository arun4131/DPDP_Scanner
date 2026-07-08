import subprocess, re, time, sys

DB = sys.argv[1] if len(sys.argv) > 1 else "pii_demo_us"
PG_URL = f"postgres://postgres@localhost:5432/{DB}?sslmode=disable"
KDB_CONFIG = "/Users/apple/klouddbshield"
KDB_BIN = "/tmp/ciscollector"

GREEN='\033[92m'; RED='\033[91m'; AMBER='\033[93m'
BLUE='\033[94m';  BOLD='\033[1m'; RESET='\033[0m'

def strip(s): return re.sub(r'\033\[\d+m','',s)
def pad(s,w): return s+' '*max(0,w-len(strip(s)))

print(f"\nScanning {DB} with klouddbshield...")
start=time.time()
kdb_result=subprocess.run(["bash","-c",
    f'echo "" | {KDB_BIN} --config {KDB_CONFIG} --piiscanner datascan --database {DB}'],
    capture_output=True,text=True)
kdb_time=time.time()-start

print(f"Scanning {DB} with pdscan...")
start=time.time()
pds_result=subprocess.run(["/tmp/pdscan/pdscan","--show-all",PG_URL],
    capture_output=True,text=True)
pds_time=time.time()-start

kdb_out=kdb_result.stdout+kdb_result.stderr
pds_out=pds_result.stdout+pds_result.stderr

# ── Parse klouddbshield — track current table across continuation rows ─────────
kdb_findings={}
current_table=None
current_col=None
for line in kdb_out.split('\n'):
    # New table row: | "public"."tablename" | col | label | confidence | detector | matched |
    m=re.search(r'"public"\."(\w+)"\s*\|\s*(\w+)\s*\|\s*(\w+)\s*\|\s*(High|Medium|Low)[^|]*\|\s*\w+\s*\|\s*(\d+)/(\d+)',line)
    if m:
        current_table=m.group(1)
        current_col=m.group(2)
        label=m.group(3); conf=m.group(4)
        matched=int(m.group(5)); total=int(m.group(6))
        kdb_findings[(current_table,current_col)]={'label':label,'confidence':conf,'matched':matched,'total':total}
        continue
    # Continuation row (same table, new column): starts with | + or spaces, has col/label/conf
    m2=re.search(r'^\|\s+\+?\s*\|\s*(\w+)\s*\|\s*(\w+)\s*\|\s*(High|Medium|Low)[^|]*\|\s*\w+\s*\|\s*(\d+)/(\d+)',line)
    if m2 and current_table:
        current_col=m2.group(1); label=m2.group(2); conf=m2.group(3)
        matched=int(m2.group(4)); total=int(m2.group(5))
        kdb_findings[(current_table,current_col)]={'label':label,'confidence':conf,'matched':matched,'total':total}
        continue
    # Meta scan rows
    m3=re.search(r'"public"\."(\w+)"\s*\|\s*(\w+)\s*\|\s*(\w+)\s*\|\s*(High|Medium|Low)',line)
    if m3:
        t=m3.group(1); c=m3.group(2); lbl=m3.group(3); conf=m3.group(4)
        if (t,c) not in kdb_findings:
            kdb_findings[(t,c)]={'label':lbl,'confidence':conf,'matched':0,'total':0}

# ── Parse pdscan ──────────────────────────────────────────────────────────────
pds_findings={}
for line in pds_out.split('\n'):
    m=re.search(r'public\.(\w+)\.(\w+):\s*(.+?)\s*\((\d+)\s*rows',line)
    if m:
        table,col,desc,rows=m.groups()
        label=desc.strip().replace('found ','').replace('possible ','')
        pds_findings[(table,col)]={'label':label,'rows':int(rows)}

# ── Build table ───────────────────────────────────────────────────────────────
all_keys=sorted(set(list(kdb_findings.keys())+list(pds_findings.keys())))
tables={}
for (t,c) in all_keys: tables.setdefault(t,set()).add(c)

print(f"\n{'='*95}")
print(f"{BOLD}DATABASE: {DB}  |  klouddbshield: {kdb_time:.2f}s  |  pdscan: {pds_time:.2f}s{RESET}")
print(f"{'='*95}")

kdb_wins=tie=pds_only=0
issues=[]

for table in sorted(tables.keys()):
    print(f"\n{BOLD}{BLUE}TABLE: {table}{RESET}")
    print(f"{'Column':<25} {'klouddbshield':<40} {'pdscan':<40} Verdict")
    print(f"{'-'*25} {'-'*40} {'-'*40} {'-'*12}")

    for col in sorted(tables[table]):
        kdb=kdb_findings.get((table,col))
        pds=pds_findings.get((table,col))

        if kdb:
            cc=GREEN if kdb['confidence']=='High' else AMBER
            if kdb['total']>0:
                pct=kdb['matched']/kdb['total']*100
                kdb_str=f"{cc}{kdb['label']} {kdb['confidence']} ({pct:.0f}%){RESET}"
            else:
                kdb_str=f"{cc}{kdb['label']} {kdb['confidence']}{RESET}"
        else:
            kdb_str="—"

        if pds:
            # Check if pdscan label is wrong
            is_wrong=False
            if kdb and kdb['label']=='ITIN' and 'SSN' in pds['label']: is_wrong=True
            if is_wrong:
                pds_str=f"{RED}{pds['label']} ({pds['rows']} rows) ✗ WRONG{RESET}"
                issues.append(f"  {table}.{col}: pdscan labeled ITIN as SSN")
            else:
                pds_str=f"{GREEN}{pds['label']} ({pds['rows']} rows){RESET}"
        else:
            pds_str=f"{RED}Not detected{RESET}"

        if kdb and pds and not (kdb and kdb['label']=='ITIN' and pds and 'SSN' in pds['label']):
            verdict=f"{AMBER}Tie{RESET}"; tie+=1
        elif kdb and not pds:
            verdict=f"{GREEN}kdb wins{RESET}"; kdb_wins+=1
        elif kdb and pds and kdb['label']=='ITIN' and 'SSN' in pds['label']:
            verdict=f"{GREEN}kdb wins{RESET}"; kdb_wins+=1
        else:
            verdict="pdscan only"; pds_only+=1

        print(f"{col:<25} {pad(kdb_str,40)} {pad(pds_str,40)} {verdict}")

total=kdb_wins+tie+pds_only
print(f"\n{'='*95}")
print(f"{BOLD}SUMMARY{RESET}")
print(f"{'='*95}")
print(f"{'klouddbshield unique/correct wins:':<45} {GREEN}{kdb_wins}/{total}{RESET}")
print(f"{'Both tools detected (tie):':<45} {AMBER}{tie}/{total}{RESET}")
print(f"{'pdscan only (klouddbshield missed):':<45} {pds_only}/{total}")
print(f"{'Scan time — klouddbshield:':<45} {GREEN}{kdb_time:.2f}s{RESET}")
print(f"{'Scan time — pdscan:':<45} {pds_time:.2f}s")
if issues:
    print(f"\n{RED}pdscan labeling errors:{RESET}")
    for i in issues: print(i)
print(f"{'='*95}\n")
