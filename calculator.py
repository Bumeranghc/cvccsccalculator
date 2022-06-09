from Crypto.Cipher import DES, DES3
import re
import argparse

parser = argparse.ArgumentParser(
    prog='python calculator.py',
    description='Small tool to calculate CVV/CSC and CVV2/CSC2 codes using given CVV key, PAN and expiration date.',
    epilog='(c) Pavel Semchenko, 2022'
)

parser.add_argument('--CVVKey', default='00000000000000000000000000000000')
parser.add_argument('--PAN', default='0000000000000000')
parser.add_argument('--EXPIRATION', default='0000')
args = parser.parse_args()

CVVKey=args.CVVKey
PAN=args.PAN
EXPIRATION=args.EXPIRATION

def calculate(SERVICE='101', TYPE='CVV/CSC'):
    Block2=EXPIRATION+SERVICE+'000000000'
    DESCIPHER = DES.new(bytes.fromhex(CVVKey[0:16]), DES.MODE_ECB)
    DESRESULT = DESCIPHER.encrypt(bytes.fromhex(PAN)).hex()
    XOR=hex(int("0x"+Block2, 16) ^ int("0x"+DESRESULT, 16))[2:]
    DESCIPHER3 = DES3.new(bytes.fromhex(CVVKey), DES3.MODE_ECB)
    DESRESULT3 = DESCIPHER3.encrypt(bytes.fromhex(XOR)).hex()
    print(TYPE+": "+''.join(re.findall("\d+", DESRESULT3))[0:3])

calculate()
calculate(SERVICE='000', TYPE='CVV2/CSC2')
