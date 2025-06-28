from flask import Flask, jsonify
import base64, hashlib, binascii, urllib.parse, secrets, os

app = Flask(__name__)

class PKCELoginHelper:
    @staticmethod
    def encodeURIComponent(s):
        return urllib.parse.quote(s, safe='')

    @staticmethod
    def btoa(string):
        if isinstance(string, bytes):
            byte_string = string
        else:
            byte_string = string.encode('utf-8')
        return base64.b64encode(byte_string).decode('utf-8')

    @staticmethod
    def R(Q):
        if isinstance(Q, str):
            Q_bytes = Q.encode()
        else:
            Q_bytes = Q
        return PKCELoginHelper.btoa(Q).replace("+", "-").replace("/", "_").replace("=", "")

    @staticmethod
    def createNonce():
        characters = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~"
        length = 45
        random_string = ''.join(secrets.choice(characters) for _ in range(length))
        return PKCELoginHelper.R(random_string)

    @staticmethod
    def createChallengeVerifierPair():
        verifier = PKCELoginHelper.createNonce()
        hashed = hashlib.sha256(verifier.encode()).digest()
        challenge = PKCELoginHelper.R(hashed)
        return challenge, verifier

    @staticmethod
    def create_login_url():
        state = PKCELoginHelper.encodeURIComponent(PKCELoginHelper.createNonce())
        challenge, verifier = PKCELoginHelper.createChallengeVerifierPair()
        url = (
            "https://egyiam.almaviva-visa.it/realms/oauth2-visaSystem-realm-pkce/protocol/openid-connect/auth"
            f"?response_type=code&client_id=aa-visasys-public"
            f"&state={state}&redirect_uri=https%3A%2F%2Fegy.almaviva-visa.it%2F"
            f"&scope=openid%20profile%20email"
            f"&code_challenge={challenge}&code_challenge_method=S256"
            f"&nonce={state}"
        )
        return url, verifier

@app.route("/get-login-link", methods=["GET"])
def get_login_link():
    try:
        url, verifier = PKCELoginHelper.create_login_url()
        return jsonify({"url": url, "verifier": verifier})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == "__main__":
    app.run(debug=False, host="0.0.0.0", port=5000)
