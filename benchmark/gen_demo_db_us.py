import psycopg2, random, string, sys
from psycopg2.extras import execute_values

random.seed(2124)

def luhn_digit(s):
    d=[int(c) for c in s]; t,p=0,(len(d)+1)%2
    for i,x in enumerate(d):
        if i%2==p: x*=2; x-=9 if x>9 else 0
        t+=x
    return str((10-t%10)%10)

US_AREA_CODES=[201,202,203,206,207,208,209,210,212,213,214,215,216,217,218,219,224,225,228,229,231,234,239,240,248,251,252,253,254,256,260,262,267,269,270,272,276,281,301,302,303,304,305,307,308,309,310,312,313,314,315,316,317,318,319,320,321,323,325,330,331,334,336,337,339,347,351,352,360,361,364,380,385,386,401,402,404,405,406,407,408,409,410,412,413,414,415,417,419,423,424,425,430,432,434,435,440,442,443,447,458,469,470,475,478,479,480,484,501,502,503,504,505,507,508,509,510,512,513,515,516,517,518,520,530,531,534,539,540,541,551,559,561,562,563,567,570,571,573,574,575,580,585,586,601,602,603,605,606,607,608,609,610,612,614,615,616,617,618,619,620,623,626,628,629,630,631,636,641,646,650,651,657,660,661,662,667,669,678,681,682,701,702,703,704,706,707,708,712,713,714,715,716,717,718,719,720,724,725,727,731,732,734,737,740,743,747,754,757,760,762,763,765,769,770,772,773,774,775,779,781,785,786,787,801,802,803,804,805,806,808,810,812,813,814,815,816,817,818,828,830,831,832,843,845,847,848,850,856,857,858,859,860,862,863,864,865,870,872,878,901,903,904,906,907,908,909,910,912,913,914,915,916,917,918,919,920,925,928,929,930,931,936,937,938,940,941,947,949,951,952,954,956,959,970,971,972,973,975,978,979,980,984,985,989]
REAL_ZIPS=['10001','10002','90001','90210','60601','77001','30301','85001','94101','98101','02101','19101','33101','48201','55401','63101','70112','80201','84101','53201','37201','46201','35201','50301','66101','68501','73101','87101','89101','99501','10003','10004','90002','90003','60602','77002','30302']
VISA_IINS=['4']
MC_IINS=['51','52','53','54','55','22','23','24','25','26','27']
AMEX_IINS=['34','37']
US_FIRST=['John','Jane','Mike','Sarah','David','Emily','James','Emma','Robert','Olivia','William','Ava','Richard','Sophia','Thomas','Isabella','Charles','Mia','Daniel','Charlotte']
US_LAST=['Smith','Johnson','Williams','Jones','Brown','Davis','Miller','Wilson','Moore','Taylor','Anderson','Thomas','Jackson','White','Harris','Martin','Thompson','Garcia','Martinez','Robinson']
STATES=['Alabama','Alaska','Arizona','Arkansas','California','Colorado','Connecticut','Delaware','Florida','Georgia','Hawaii','Idaho','Illinois','Indiana','Iowa','Kansas','Kentucky','Louisiana','Maine','Maryland','Massachusetts','Michigan','Minnesota','Mississippi','Missouri','Montana','Nebraska','Nevada','New Hampshire','New Jersey','New Mexico','New York','North Carolina','North Dakota','Ohio','Oklahoma','Oregon','Pennsylvania','Rhode Island','South Carolina','South Dakota','Tennessee','Texas','Utah','Vermont','Virginia','Washington','West Virginia','Wisconsin','Wyoming']

def gen_ssn():
    area=random.choice(list(range(1,666))+list(range(667,900)))
    return f"{area:03d}-{random.randint(1,99):02d}-{random.randint(1,9999):04d}"

def gen_itin():
    area=random.randint(900,999)
    groups=list(range(50,66))+list(range(70,89))+list(range(90,93))+list(range(94,100))
    return f"{area}-{random.choice(groups):02d}-{random.randint(1,9999):04d}"

def gen_phone():
    area=random.choice(US_AREA_CODES)
    exchange=random.randint(200,999)
    number=random.randint(1000,9999)
    fmt=random.randint(0,4)
    if fmt==0: return f"({area}) {exchange}-{number}"
    if fmt==1: return f"{area}-{exchange}-{number}"
    if fmt==2: return f"+1{area}{exchange}{number}"
    if fmt==3: return f"{area}.{exchange}.{number}"
    return f"1-{area}-{exchange}-{number}"

def gen_zip():
    z=random.choice(REAL_ZIPS) if random.random()<0.4 else f"{random.randint(10000,99999)}"
    return f"{z}-{random.randint(1000,9999)}" if random.random()<0.2 else z

def gen_card():
    network=random.choice(['visa','visa','mc','mc','amex'])
    if network=='visa': prefix=random.choice(VISA_IINS); length=16
    elif network=='mc': prefix=random.choice(MC_IINS); length=16
    else: prefix=random.choice(AMEX_IINS); length=15
    body=prefix+''.join(random.choice('0123456789') for _ in range(length-1-len(prefix)))
    n=body+luhn_digit(body)
    fmt=random.randint(0,2)
    if fmt==0: return n
    if fmt==1: return '-'.join(n[i:i+4] for i in range(0,len(n),4))
    return ' '.join(n[i:i+4] for i in range(0,len(n),4))

def gen_email(name):
    domains=['gmail.com','yahoo.com','hotmail.com','outlook.com','icloud.com','company.com','corp.net']
    return f"{name.lower().replace(' ','.')}@{random.choice(domains)}"

def gen_name(): return f"{random.choice(US_FIRST)} {random.choice(US_LAST)}"

def gen_dl_us():
    choice=random.random()
    if choice<0.25:
        mm=f"{random.randint(1,12):02d}"; n3=f"{random.randint(0,999):03d}"
        y=str(random.randint(1,9)); n3b=f"{random.randint(0,999):03d}"
        dd=f"{random.randint(1,28):02d}"; return mm+n3+y+n3b+"41"+dd
    if choice<0.50:
        mm=f"{random.randint(1,12):02d}"
        letters=''.join(random.choice(string.ascii_uppercase) for _ in range(3))
        yy=f"{random.randint(0,99):02d}"; dd=f"{random.randint(1,28):02d}"
        return mm+letters+yy+dd+str(random.randint(0,9))
    if choice<0.75:
        return "WDL"+''.join(random.choice(string.ascii_uppercase+'0123456789') for _ in range(9))
    return random.choice(string.ascii_uppercase)+''.join(random.choice('0123456789') for _ in range(random.choice([6,7])))

def gen_tx_id(i): return f"TXN{random.randint(10000000,99999999)}"
def gen_log_msg(): return random.choice(["Request processed","Database query executed","Cache hit","API call completed","Health check passed","Config loaded","Service started","Batch job finished"])
def gen_service(): return random.choice(["api-gateway","auth-service","payment-service","user-service","notification-service","report-service","scheduler","cache-service"])

def main(n=1000):
    conn=psycopg2.connect(dbname="pii_demo_us", user="postgres", host="localhost")
    cur=conn.cursor()
    print(f"Populating pii_demo_us with {n} rows per table...")
    BATCH=5000

    # Table 1: us_customers (clean naming)
    rows=[]
    for _ in range(n):
        name=gen_name()
        # 70% have SSN, 30% have ITIN (contractors)
        ssn=gen_ssn() if random.random()<0.7 else None
        itin=gen_itin() if ssn is None else None
        rows.append((name, gen_email(name), ssn, itin, gen_phone(), gen_zip(), gen_card(), random.choice(STATES)))
        if len(rows)>=BATCH:
            execute_values(cur,"INSERT INTO us_customers (full_name,email,ssn,itin,phone,zip_code,credit_card,state) VALUES %s",rows); conn.commit(); rows=[]
    if rows: execute_values(cur,"INSERT INTO us_customers (full_name,email,ssn,itin,phone,zip_code,credit_card,state) VALUES %s",rows); conn.commit()
    print("us_customers done")

    # Table 2: records_archive (obscure naming)
    rows=[]
    for _ in range(n):
        rows.append((gen_name(), gen_ssn(), gen_itin(), gen_card(), gen_phone(), gen_zip(), "System archived record"))
        if len(rows)>=BATCH:
            execute_values(cur,"INSERT INTO records_archive (field_a,field_b,field_c,field_d,field_e,field_f,notes) VALUES %s",rows); conn.commit(); rows=[]
    if rows: execute_values(cur,"INSERT INTO records_archive (field_a,field_b,field_c,field_d,field_e,field_f,notes) VALUES %s",rows); conn.commit()
    print("records_archive done")

    # Table 3: financial_records
    rows=[]
    for i in range(n):
        name=gen_name()
        rows.append((gen_tx_id(i), gen_card(), name, gen_zip(), gen_phone(), round(random.uniform(1,5000),2)))
        if len(rows)>=BATCH:
            execute_values(cur,"INSERT INTO financial_records (transaction_id,card_number,card_holder,billing_zip,account_phone,amount,transaction_date) VALUES %s",rows,template="(%s,%s,%s,%s,%s,%s,NOW())"); conn.commit(); rows=[]
    if rows: execute_values(cur,"INSERT INTO financial_records (transaction_id,card_number,card_holder,billing_zip,account_phone,amount,transaction_date) VALUES %s",rows,template="(%s,%s,%s,%s,%s,%s,NOW())"); conn.commit()
    print("financial_records done")

    # Table 4: hr_records (SSN for employees, ITIN for contractors)
    rows=[]
    for _ in range(n):
        name=gen_name()
        is_employee=random.random()<0.6
        tax_id=gen_ssn() if is_employee else gen_itin()
        emp_type="Employee" if is_employee else "Contractor"
        rows.append((name, gen_email(name), tax_id, gen_phone(), gen_zip(), emp_type, random.randint(40000,200000)))
        if len(rows)>=BATCH:
            execute_values(cur,"INSERT INTO hr_records (employee_name,work_email,tax_id,personal_phone,home_zip,employment_type,salary) VALUES %s",rows); conn.commit(); rows=[]
    if rows: execute_values(cur,"INSERT INTO hr_records (employee_name,work_email,tax_id,personal_phone,home_zip,employment_type,salary) VALUES %s",rows); conn.commit()
    print("hr_records done")

    # Table 5: system_logs (NO PII)
    rows=[]
    for i in range(n):
        rows.append((random.choice(["INFO","WARN","ERROR","DEBUG"]), gen_service(), gen_log_msg(),
                     f"req-{random.randint(100000,999999)}", random.randint(1,5000)))
        if len(rows)>=BATCH:
            execute_values(cur,"INSERT INTO system_logs (log_level,service_name,message,request_id,duration_ms,logged_at) VALUES %s",rows,template="(%s,%s,%s,%s,%s,NOW())"); conn.commit(); rows=[]
    if rows: execute_values(cur,"INSERT INTO system_logs (log_level,service_name,message,request_id,duration_ms,logged_at) VALUES %s",rows,template="(%s,%s,%s,%s,%s,NOW())"); conn.commit()
    print("system_logs done")

    cur.close(); conn.close()
    print(f"Done. {n*5:,} total rows across 5 tables.")

if __name__=="__main__":
    n=int(sys.argv[1]) if len(sys.argv)>1 else 1000
    main(n)
