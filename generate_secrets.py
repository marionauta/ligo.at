import secrets
import time
from authlib.jose import JsonWebKey


if __name__ == "__main__":
    secret_key = secrets.token_hex()

    now = int(time.time())
    key = JsonWebKey.generate_key(
        "EC", "P-256", options={"kid": f"demo-{now}"}, is_private=True
    )
    client_secret_jwk = key.as_json(is_private=True)

    print(f'FLASK_SECRET_KEY="{secret_key}"')
    print(f"FLASK_CLIENT_SECRET_JWK={client_secret_jwk}")
