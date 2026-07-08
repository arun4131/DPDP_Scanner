import random, csv, string, os

SEEDS = {'india': 2024, 'us': 2124}
N_PER_ENTITY = 5000

def verhoeff_digit(s):
    D=[[0,1,2,3,4,5,6,7,8,9],[1,2,3,4,0,6,7,8,9,5],[2,3,4,0,1,7,8,9,5,6],[3,4,0,1,2,8,9,5,6,7],[4,0,1,2,3,9,5,6,7,8],[5,9,8,7,6,0,4,3,2,1],[6,5,9,8,7,1,0,4,3,2],[7,6,5,9,8,2,1,0,4,3],[8,7,6,5,9,3,2,1,0,4],[9,8,7,6,5,4,3,2,1,0]]
    P=[[0,1,2,3,4,5,6,7,8,9],[1,5,7,6,2,8,3,0,9,4],[5,8,0,3,7,9,6,1,4,2],[8,9,1,6,0,4,3,5,2,7],[9,4,5,3,1,2,6,8,7,0],[4,2,8,6,5,7,3,9,0,1],[2,7,9,3,8,0,6,4,1,5],[7,0,4,6,9,1,3,2,5,8]]
    for cd in range(10):
        c=0
        for i,ch in enumerate(reversed(s+str(cd))): c=D[c][P[i%8][int(ch)]]
        if c==0: return str(cd)

def luhn_digit(s):
    d=[int(c) for c in s]; t,p=0,(len(d)+1)%2
    for i,x in enumerate(d):
        if i%2==p: x*=2; x-=9 if x>9 else 0
        t+=x
    return str((10-t%10)%10)

def gstin_check(base):
    chars='0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ'
    s=0
    for i,c in enumerate(base):
        val=chars.index(c)
        if i%2==0: s+=val
        else:
            p=val*2; s+=p//36+p%36
    return chars[(36-s%36)%36]

IN_STATES=['AP','AR','AS','BR','CG','CH','DL','GA','GJ','HP','HR','JH','JK','KA','KL','LA','MH','ML','MN','MP','MZ','NL','OD','PB','PY','RJ','SK','TN','TR','TS','UK','UP','WB','AN','DD','DN']
PAN_TYPES='PCHABGJLFT'
PASS_SERIES='ABCDEFGHJKLMNPRSTUVWYZ'
BANKS=['SBIN','HDFC','ICIC','AXIS','KKBK','PUNB','CNRB','UBIN','BARB','INDB','YESB','IDFB','FDRL','KARB','KVBL']
GST_STATES=[f'{i:02d}' for i in range(1,38)]
VISA_IINS=['4']
MC_IINS=['51','52','53','54','55','22','23','24','25','26','27']
AMEX_IINS=['34','37']
UPI_HANDLES = [
    'ybl','ibl','axl','okaxis','okhdfcbank','okicici','oksbi','paytm',
    'ptsbi','pthdfc','ptaxis','ptyes','apl','rapl','yapl','waaxis',
    'waicici','wahdfcbank','wasbi','yesg','yescred','yespop','superyes',
    'ikwik','mvhdfc','fkaxis','indie','federal','fifederal','icici',
    'axisb','hsbc','idbi','indianbank','allbank','kotak','kotak811',
    'barodampay','pnb','unionbank','canara','bob','sbi','hdfcbank',
    'icicibank','axisbank','idfcfirst','idfc','rbl','bandhan','yesbank',
    'indus','indusind','au','aubank','equitas','ujjivan','airtel',
    'freecharge','famapp','slice','cred','groww','jupiter','mobikwik',
    'amazonpay','flipkart','phonepe','gpay','bhim'
]

IN_STATE_CODES = [
    'AN','AP','AR','AS','BR','CH','CG','DD','DL','DN','GA','GJ',
    'HP','HR','JH','JK','KA','KL','LA','LD','MH','ML','MN','MP',
    'MZ','NL','OD','PB','PY','RJ','SK','TN','TR','TS','UK','UP','WB'
]

COMPANY_TYPES = [
    'PTC','PLC','OPC','SGC','FTC','GOI','NPL','ULT','FLC'
]
RUPAY_IINS=['60','65','81','82','508','353']
US_AREA_CODES=[201,202,203,206,207,208,209,210,212,213,214,215,216,217,218,219,224,225,228,229,231,234,239,240,248,251,252,253,254,256,260,262,267,269,270,272,276,281,301,302,303,304,305,307,308,309,310,312,313,314,315,316,317,318,319,320,321,323,325,330,331,334,336,337,339,347,351,352,360,361,364,380,385,386,401,402,404,405,406,407,408,409,410,412,413,414,415,417,419,423,424,425,430,432,434,435,440,442,443,447,458,469,470,475,478,479,480,484,501,502,503,504,505,507,508,509,510,512,513,515,516,517,518,520,530,531,534,539,540,541,551,559,561,562,563,567,570,571,573,574,575,580,585,586,601,602,603,605,606,607,608,609,610,612,614,615,616,617,618,619,620,623,626,628,629,630,631,636,641,646,650,651,657,660,661,662,667,669,678,681,682,701,702,703,704,706,707,708,712,713,714,715,716,717,718,719,720,724,725,727,731,732,734,737,740,743,747,754,757,760,762,763,765,769,770,772,773,774,775,779,781,785,786,787,801,802,803,804,805,806,808,810,812,813,814,815,816,817,818,828,830,831,832,843,845,847,848,850,856,857,858,859,860,862,863,864,865,870,872,878,901,903,904,906,907,908,909,910,912,913,914,915,916,917,918,919,920,925,928,929,930,931,936,937,938,940,941,947,949,951,952,954,956,959,970,971,972,973,975,978,979,980,984,985,989]
REAL_ZIPS=['10001','10002','90001','90210','60601','77001','30301','85001','94101','98101','02101','19101','33101','48201','55401','63101','70112','80201','84101','53201','37201','46201','35201','50301','66101','68501','73101','87101','89101','99501']

def gen_aadhaar():
    while True:
        base = str(random.randint(2,9)) + ''.join(random.choice('0123456789') for _ in range(10))
        n = base + verhoeff_digit(base)

        # Avoid collisions with Indian phone numbers
        if n.startswith("91"):
            continue

        # Avoid collisions with American Express cards
        if n.startswith(("34", "37")):
            continue

        fmt = random.randint(0,4)
        if fmt == 0:
            return n
        if fmt == 1:
            return f"{n[:4]} {n[4:8]} {n[8:]}"
        if fmt == 2:
            return f"{n[:4]}-{n[4:8]}-{n[8:]}"
        if fmt == 3:
            return f"{n[:4]}{n[4:8]}{n[8:]}"
        return f"{n[:4]} {n[4:8]}-{n[8:]}"

def gen_pan():
    return ''.join(random.choice(string.ascii_uppercase) for _ in range(3))+random.choice(PAN_TYPES)+random.choice(string.ascii_uppercase)+''.join(random.choice('0123456789') for _ in range(4))+random.choice(string.ascii_uppercase)

def gen_passport():
    series=random.choice(PASS_SERIES)
    serial=str(random.randint(1,9))+''.join(random.choice('0123456789') for _ in range(6))
    fmt=random.randint(0,2)
    if fmt==0: return series+serial
    if fmt==1: return (series+serial).lower()
    return series+' '+serial

def gen_mobile_in():
    n=random.choice('6789')+''.join(random.choice('0123456789') for _ in range(9))
    fmt=random.randint(0,6)
    if fmt==0: return n
    if fmt==1: return f"+91{n}"
    if fmt==2: return f"+91 {n}"
    if fmt==3: return f"+91-{n}"
    if fmt==4: return f"0{n}"
    if fmt==5: return f"+91 {n[:5]} {n[5:]}"
    return f"+91-{n[:5]}-{n[5:]}"

def gen_dl_in():
    st=random.choice(IN_STATES)
    rto=f"{random.randint(1,49):02d}"
    yr=str(random.randint(1990,2024))
    ser=f"{random.randint(1000000,9999999):07d}"
    sep=random.choice(['','-',' '])
    if sep: return sep.join([st,rto,yr,ser])
    return st+rto+yr+ser

def gen_voter():
    prefix=''.join(random.choice(string.ascii_uppercase) for _ in range(3))
    num=f"{random.randint(1000000,9999999):07d}"
    return random.choice([prefix+num,(prefix+num).lower()])

def gen_bank_in():
    lengths=[9,11,14,15,17,18]
    l=random.choice(lengths)
    prefixes=['00','01','02','10','11','12','20','30','40','50']
    return random.choice(prefixes)+''.join(random.choice('0123456789') for _ in range(l-2))

def gen_cheque():
    return ''.join(random.choice('0123456789') for _ in range(6))

def gen_cif():
    l = random.randint(8, 11)
    return ''.join(random.choice('0123456789') for _ in range(l))

def gen_loan_account():
    l = random.randint(10, 20)
    chars = string.ascii_uppercase + string.digits
    return ''.join(random.choice(chars) for _ in range(l))

def gen_insurance_policy():
    l = random.randint(8, 20)
    chars = string.ascii_uppercase + string.digits
    return ''.join(random.choice(chars) for _ in range(l))

def gen_fastag():
    l = random.randint(10, 24)
    chars = string.ascii_uppercase + string.digits
    return ''.join(random.choice(chars) for _ in range(l))

def gen_upi():
    first = ['rahul','priya','amit','sneha','vikram','anjali','ravi','neha','sanjay','pooja']
    last = ['sharma','patel','kumar','singh','gupta','reddy','nair','mehta','joshi','verma']

    fmt = random.randint(0, 4)

    if fmt == 0:
        username = random.choice(first) + '.' + random.choice(last)
    elif fmt == 1:
        username = random.choice('6789') + ''.join(random.choice('0123456789') for _ in range(9))
    elif fmt == 2:
        username = random.choice(first) + str(random.randint(1, 999))
    elif fmt == 3:
        username = random.choice(first) + '_' + random.choice(last)
    else:
        username = random.choice(first) + random.choice(last)

    return username + '@' + random.choice(UPI_HANDLES)


def gen_cvv():
    if random.random() < 0.2:
        return str(random.randint(1000, 9999))
    return str(random.randint(100, 999))


def gen_tan():
    jurisdiction = ''.join(random.choice(string.ascii_uppercase) for _ in range(3))
    deductor = random.choice(string.ascii_uppercase)
    seq = ''.join(random.choice('0123456789') for _ in range(5))
    last = random.choice(string.ascii_uppercase)
    return jurisdiction + deductor + seq + last


def gen_cin():
    listing = random.choice(['L', 'U'])
    industry = f"{random.randint(10000, 99999)}"
    state = random.choice(IN_STATE_CODES)
    year = str(random.randint(1956, 2024))
    ctype = random.choice(COMPANY_TYPES)
    reg = f"{random.randint(100000, 999999)}"
    return listing + industry + state + year + ctype + reg


def gen_micr():
    city = f"{random.randint(100, 799):03d}"
    bank = f"{random.randint(1, 999):03d}"
    branch = f"{random.randint(1, 999):03d}"
    return city + bank + branch

def gen_card():
    network=random.choice(['visa','visa','visa','mc','mc','amex','rupay','rupay'])
    if network=='visa': prefix=random.choice(VISA_IINS); length=16
    elif network=='mc': prefix=random.choice(MC_IINS); length=16
    elif network=='amex': prefix=random.choice(AMEX_IINS); length=15
    else: prefix=random.choice(RUPAY_IINS); length=16
    body=prefix+''.join(random.choice('0123456789') for _ in range(length-1-len(prefix)))
    n=body+luhn_digit(body)
    fmt=random.randint(0,3)
    if fmt==0: return n
    if fmt==1: return ' '.join(n[i:i+4] for i in range(0,len(n),4))
    if fmt==2: return '-'.join(n[i:i+4] for i in range(0,len(n),4))
    return n

def gen_gstin():
    state=random.choice(GST_STATES)
    pan=gen_pan().upper()[:10]
    if len(pan)!=10: pan=(pan+'AAAA0000A')[:10]
    entity=random.choice('123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ')
    base=state+pan+entity+'Z'
    return base+gstin_check(base)

def gen_ifsc():
    bank=random.choice(BANKS)
    branch=''.join(random.choice('0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ') for _ in range(6))
    ifsc=bank+'0'+branch
    return random.choice([ifsc,ifsc.lower()])

def gen_demat():
    # NSDL BO ID
    return "IN" + ''.join(random.choice('0123456789') for _ in range(14))

def gen_vehicle_in():
    st=random.choice(IN_STATES)
    rto=f"{random.randint(1,99):02d}"
    series=''.join(random.choice(string.ascii_uppercase) for _ in range(random.randint(1,2)))
    num=f"{random.randint(1,9999):04d}"
    sep=random.choice(['','-',' '])
    if sep: return sep.join([st,rto,series,num])
    return st+rto+series+num

def gen_ssn():
    area_ranges=list(range(1,666))+list(range(667,900))
    area=random.choice(area_ranges)
    group=random.randint(1,99)
    serial=random.randint(1,9999)
    if random.random()<0.5: return f"{area:03d}-{group:02d}-{serial:04d}"
    return f"{area:03d} {group:02d} {serial:04d}"

def gen_itin():
    area=random.randint(900,999)
    valid_groups=list(range(50,66))+list(range(70,89))+list(range(90,93))+list(range(94,100))
    group=random.choice(valid_groups)
    serial=random.randint(1,9999)
    if random.random()<0.5: return f"{area}-{group:02d}-{serial:04d}"
    return f"{area} {group:02d} {serial:04d}"

def gen_zip_us():
    z=random.choice(REAL_ZIPS) if random.random()<0.3 else f"{random.randint(10000,99999)}"
    if random.random()<0.3: return f"{z}-{random.randint(1000,9999)}"
    return z

def gen_phone_us():
    area=random.choice(US_AREA_CODES)
    exchange=random.randint(200,999)
    number=random.randint(1000,9999)
    fmt=random.randint(0,5)
    if fmt==0: return f"({area}) {exchange}-{number}"
    if fmt==1: return f"{area}-{exchange}-{number}"
    if fmt==2: return f"+1{area}{exchange}{number}"
    if fmt==3: return f"+1 {area} {exchange} {number}"
    if fmt==4: return f"{area}.{exchange}.{number}"
    return f"1-{area}-{exchange}-{number}"

def gen_email_us():
    domains=['gmail.com','yahoo.com','hotmail.com','outlook.com','icloud.com','aol.com','protonmail.com','company.com']
    first=['john','jane','mike','sarah','david','emily','james','emma','robert','olivia']
    last=['smith','johnson','williams','jones','brown','davis','miller','wilson','moore','taylor']
    sep=random.choice(['.','_',''])
    name=random.choice(first)+sep+random.choice(last)
    if random.random()<0.3: name+=str(random.randint(1,99))
    return f"{name}@{random.choice(domains)}"

MONTHS=['Jan','Feb','Mar','Apr','May','Jun','Jul','Aug','Sep','Oct','Nov','Dec']
ORDER_PREFIXES=['ORD','INV','TXN','REF','SHIP','PKG','CUST','EMP','PRD','SKU']

def gen_dl_montana():
    # MM NNN Y NNN 41 DD  -- month, 3 random, last digit of year, 3 random, literal 41, day
    mm = f"{random.randint(1,12):02d}"
    n3 = f"{random.randint(0,999):03d}"
    y = str(random.randint(1,9))
    n3b = f"{random.randint(0,999):03d}"
    dd = f"{random.randint(1,28):02d}"
    return mm + n3 + y + n3b + "41" + dd

def gen_dl_new_hampshire():
    mm = f"{random.randint(1,12):02d}"
    letters = ''.join(random.choice(string.ascii_uppercase) for _ in range(3))
    yy = f"{random.randint(0,99):02d}"
    dd = f"{random.randint(1,28):02d}"
    last = str(random.randint(0,9))
    return mm + letters + yy + dd + last

def gen_dl_washington_pre2018():
    letters5 = ''.join(random.choice(string.ascii_uppercase) for _ in range(5))
    letters2 = ''.join(random.choice(string.ascii_uppercase) for _ in range(2))
    digits3 = f"{random.randint(0,999):03d}"
    alnum2 = ''.join(random.choice(string.ascii_uppercase + '0123456789') for _ in range(2))
    return letters5 + letters2 + digits3 + alnum2

def gen_dl_washington_post2018():
    return "WDL" + ''.join(random.choice(string.ascii_uppercase + '0123456789') for _ in range(9))

def gen_dl_wv_ca():
    letter = random.choice(string.ascii_uppercase)
    digits = ''.join(random.choice('0123456789') for _ in range(random.choice([6,7])))
    return letter + digits

def gen_dl_us():
    choice = random.random()
    if choice < 0.2: return gen_dl_montana()
    if choice < 0.4: return gen_dl_new_hampshire()
    if choice < 0.6: return gen_dl_washington_pre2018()
    if choice < 0.8: return gen_dl_washington_post2018()
    return gen_dl_wv_ca()

def gen_neg_generic():
    k=random.random()
    if k<0.10: return str(random.randint(10000,9999999))
    if k<0.18: return f"2024{random.randint(1,12):02d}{random.randint(1,28):02d}"
    if k<0.26: return f"{random.randint(1,31):02d}-{random.randint(1,12):02d}-{random.randint(2000,2024)}"
    if k<0.34: return f"{random.choice(ORDER_PREFIXES)}-{random.randint(100000,9999999)}"
    if k<0.42: return f"{random.randint(1,9999)}.{random.randint(0,99):02d}"
    if k<0.50: return f"v{random.randint(1,9)}.{random.randint(0,20)}.{random.randint(0,99)}"
    if k<0.58: return f"{random.choice(string.ascii_uppercase)}{random.randint(10000000,99999999)}"
    if k<0.66: return str(random.randint(10**12,10**13-1))
    if k<0.74: return f"EMP{random.randint(10000,99999)}"
    if k<0.82: return f"{random.randint(1,28):02d} {random.choice(MONTHS)} {random.randint(2000,2024)}"
    if k<0.90: return ''.join(random.choice('0123456789abcdef') for _ in range(random.choice([8,16,32])))
    return f"{''.join(random.choice(string.ascii_uppercase) for _ in range(3))}{random.randint(100,9999)}"

def gen_neg_corrupted_india():
    k=random.random()
    if k<0.20:
        base=str(random.randint(2,9))+''.join(random.choice('0123456789') for _ in range(10))
        n=base+verhoeff_digit(base)
        lst=list(n); lst[random.randint(0,11)]=str((int(lst[random.randint(0,11)])+random.randint(1,9))%10)
        return ''.join(lst)
    if k<0.40:
        p='4'; b=p+''.join(random.choice('0123456789') for _ in range(14))
        n=b+luhn_digit(b); lst=list(n); lst[-1]=str((int(lst[-1])+random.randint(1,9))%10)
        return ''.join(lst)
    if k<0.55: return 'ZZ'+gen_dl_in()[2:]
    if k<0.70: return random.choice('IOQX')+str(random.randint(1,9))+''.join(random.choice('0123456789') for _ in range(6))+'X'
    if k<0.85: return random.choice('012345')+''.join(random.choice('0123456789') for _ in range(9))
    state=random.choice(GST_STATES)
    pan=gen_pan().upper()[:10]
    entity=random.choice('123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ')
    base=state+pan+entity+'Z'
    correct=gstin_check(base)
    wrong=random.choice([c for c in '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ' if c!=correct])
    return base+wrong

def gen_neg_corrupted_us():
    k=random.random()
    if k<0.33:
        # Invalid SSN - no dashes to avoid phone collision
        bad=random.choice([0,666])
        return f"{bad:03d}{random.randint(1,99):02d}{random.randint(1,9999):04d}"
    if k<0.66:
        p='4'; b=p+''.join(random.choice('0123456789') for _ in range(14))
        n=b+luhn_digit(b); lst=list(n); lst[-1]=str((int(lst[-1])+random.randint(1,9))%10)
        return ''.join(lst)
    return str(random.randint(100000000,999999999))

INDIA_GENS={
    'AdharcardNumber': gen_aadhaar,
    'PANNumber': gen_pan,
    'PassportNumber': gen_passport,
    'Phone': gen_mobile_in,
    'DrivingLicenceNumber': gen_dl_in,
    'VoterID': gen_voter,
    'BankAccountNumber': gen_bank_in,
    'CreditCard': gen_card,
    'GSTIN': gen_gstin,
    'VehicleNumber': gen_vehicle_in,
    'IFSC': gen_ifsc,
    'DematAccountNumber': gen_demat,
    'ChequeNumber': gen_cheque,
    'CIFNumber': gen_cif,
    'LoanAccountNumber': gen_loan_account,
    'InsurancePolicyNumber': gen_insurance_policy,
    'FASTagID': gen_fastag,
    'UPIID': gen_upi,
    'CVV': gen_cvv,
    'TAN': gen_tan,
    'CIN': gen_cin,
}

US_GENS={
    'Email': gen_email_us,
    'CreditCard': gen_card,
    'DrivingLicenceNumber': gen_dl_us,
}
def build(gens, filename, seed, corrupt_gen):
    random.seed(seed)
    rows=[]
    for label,gen in gens.items():
        for _ in range(N_PER_ENTITY): rows.append((gen(),label))
    neg_count=len(gens)*N_PER_ENTITY*3
    for _ in range(neg_count//2): rows.append((gen_neg_generic(),'NEG'))
    for _ in range(neg_count//2): rows.append((corrupt_gen(),'NEG'))
    random.shuffle(rows)
    path=os.path.join('benchmark',filename)
    with open(path,'w',newline='') as f:
        w=csv.writer(f); w.writerow(['value','label']); w.writerows(rows)
    pos=len(gens)*N_PER_ENTITY
    print(f"wrote {len(rows):,} samples to {path} ({pos:,} positive, {neg_count:,} negative)")

print(f"Generating with N={N_PER_ENTITY} per entity...")
build(INDIA_GENS,'india_large.csv',2024,gen_neg_corrupted_india)
print("Done.")
