from cryptography.hazmat.primitives.asymmetric import dsa
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidSignature

private_key = dsa.generate_private_key(key_size=1024)
public_key = private_key.public_key()

def sign_message(private_key, message):
    signature = private_key.sign(
        message.encode('utf-8'),
        hashes.SHA256()
    )
    return signature

def verify_signature(public_key, message, signature):
    try:
        public_key.verify(
            signature,
            message.encode('utf-8'),
            hashes.SHA256()
        )
        return True
    except InvalidSignature:
        return False


message = "This is a test message."

signature = sign_message(private_key, message)

is_valid = verify_signature(public_key, message, signature)

print(f"Message: {message}")
print(f"Signature: {signature.hex()}")
print(f"Verification result: {is_valid}")



