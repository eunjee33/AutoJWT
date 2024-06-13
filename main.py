from flask import Flask, render_template, request, jsonify
import jwt, json, os, hashlib
import autojwt

app = Flask(__name__)

UPLOAD_FOLDER = 'static/images'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

origin_token1 = ''
origin_token2 = ''
mheader = ''
mpayload = ''

# 전역 변수로 공개 키와 kid를 저장-> main? autojwt?
#cached_public_key = None
#cached_kid = None

@app.route('/', methods=['GET'])
def input_token():
    return render_template('input_token.html')

@app.route('/decoded', methods=['POST'])
def decoded():
    token1 = request.form.get('token1')
    token2 = request.form.get('token2')
    
    global origin_token1, origin_token2
    origin_token1 = token1
    origin_token2 = token2
    
    header, payload, signature = autojwt.decode_jwt(token1)
    
    return render_template('decoded_token.html', token=token1, header=header, payload=payload, signature=signature)

@app.route('/jwks.json', methods=['GET'])
def publickey_jwks():
    public_key, kid = autojwt.get_cached_jwk()
    jwk = json.loads(autojwt.pem_to_jwk(public_key, kid))
    jwks = {"keys": [jwk]}
    return jsonify(jwks)

@app.route('/exploit', methods=['POST'])
def exploit():
    global mheader, mpayload
    mheader = request.form.get('header')
    mpayload = request.form.get('payload')
    signature = request.form.get('signature')
    
    mheader = json.loads(mheader.replace('\'', '"').replace("True", "true").replace("False", "false"))
    mpayload = json.loads(mpayload.replace('\'', '"').replace("True", "true").replace("False", "false"))
    tokens = []
    decoded_tokens = []
    
    token1 = autojwt.exploit1(mheader, mpayload)
    tokens.append(token1)
    decoded_tokens.append(autojwt.decode_str(token1))

    token2 = autojwt.exploit2(mheader, mpayload, signature)
    tokens.append(token2)
    decoded_tokens.append(autojwt.decode_str(token2))

    token4_1 = autojwt.exploit4_1(mheader, mpayload)
    tokens.append(token4_1)
    decoded_tokens.append(autojwt.decode_str(token4_1))

    token4_2 = autojwt.exploit4_2(mheader, mpayload)
    tokens.append(token4_2)
    decoded_tokens.append(autojwt.decode_str(token4_2))

    token4_3 = autojwt.exploit4_3(mheader, mpayload)
    tokens.append(token4_3) 
    decoded_tokens.append(autojwt.decode_str(token4_3))
    return render_template('exploit.html', tokens=tokens, decoded_tokens=decoded_tokens)


@app.route('/exploit3', methods=['POST'])
def exploit3():
    global origin_token1, mheader, mpayload
    if mheader['alg']=='RS256':
        return jsonify({"result":0})

    secret = autojwt.fuzz_secret(origin_token1)
    if secret is not None:
        ex3_token = autojwt.exploit3(mheader, mpayload, secret)
        ex3_decoded = autojwt.decode_str(ex3_token)
        return jsonify({"result": 1, "ex3_token": ex3_token, "ex3_decoded": ex3_decoded, "secret": secret})
    else:
        return jsonify({"result": 0})
    


@app.route('/exploit5', methods=['POST'])
def exploit5():
    global origin_token1, origin_token2, mheader, mpayload
    header, payload, signature = autojwt.decode_jwt(origin_token1)

    if not origin_token1 or not origin_token2:
        return jsonify({"result":0, "error":"Input second token!"})
    if not header['alg']=='RS256':
        return jsonify({"result":0, "error":"Working only RS256!"})
    
    json_mpayload = json.dumps(mpayload)
    
    result = autojwt.exploit5(origin_token1, origin_token2, json_mpayload)
    if result:
        ex5_tokens1, ex5_tokens2 = result
        ex5_decoded = []

        for token in ex5_tokens2:
            ex5_decoded.append(autojwt.decode_str(token))
        
        return jsonify({"result": 1, "ex5_tokens1": ex5_tokens1, "ex5_tokens2": ex5_tokens2, "ex5_decoded": ex5_decoded})
    else:
        return jsonify({"result": 0, "error":"Unexpected Server Error"})


@app.route('/viewCode', methods=['GET'])
def viewCode():
    id = request.args.get('id')
    html_file = "code" + id + ".html"
    return render_template(html_file)


if __name__ == '__main__':
    app.run(host="0.0.0.0", debug=True)
