import os
import time 
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, dsa, ec, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

ITERATIONS = 10 
PLAINTEXT_SIZE = 10 * 1024
plaintext = os.urandom(PLAINTEXT_SIZE)

print("=== KEY GENERATION ===")

security_levels = [80, 112, 128, 192, 256]

rsa_sizes = {
    80: 1024,
    112: 2048,
    128: 3072,
    192: 7680,
    256: 15360
}

dsa_sizes = {
    80: 1024,
    112: 2048,
    128: 3072,
    192: None,
    256: None
}

ecc_curves = {
    80: ec.SECP192R1(),
    112: ec.SECP224R1(),
    128: ec.SECP256R1(),
    192: ec.SECP384R1(),
    256: ec.SECP521R1()
}

#KEY GENERATION
for sec in security_levels:
    rsa_times = []
    for i in range(ITERATIONS):
        start = time.perf_counter()
        rsa.generate_private_key(public_exponent=65537, key_size=rsa_sizes[sec])
        end = time.perf_counter()
        rsa_times.append((end - start) * 1000)
    rsa_avg = sum(rsa_times[1:]) / (ITERATIONS - 1)

    #DSA KEYGEN
    if dsa_sizes[sec] is not None:
        dsa_times = []
        for i in range(ITERATIONS):
            start = time.perf_counter()
            dsa.generate_private_key(key_size=dsa_sizes[sec])
            end = time.perf_counter()
            dsa_times.append((end - start) * 1000)
        dsa_avg = sum(dsa_times[1:]) / ( ITERATIONS - 1)
    else:
        dsa_avg = None
    
    #ECC KEYGEN
    ecc_times = []
    for i in range(ITERATIONS):
        start = time.perf_counter()
        ec.generate_private_key(ecc_curves[sec])
        end = time.perf_counter()
        ecc_times.append((end - start) * 1000)
    ecc_avg = sum(ecc_times[1:]) / (ITERATIONS - 1)

    print(f"Security {sec} bits -> RSA: {rsa_avg:.2f} ms, DSA: {dsa_avg}, ECC: {ecc_avg:.2f} ms")

print("\n=== SYMMETRIC ENCRYPTION (µs) ===")

aes_key_sizes = [16,24,32] # AES-128, AES-192, AES-256

#AES ENCRYPTION
for ks in [16, 24, 32]:  # AES 128/192/256
    key = os.urandom(ks)
    cipher = Cipher(algorithms.AES(key), modes.ECB())
    encryptor = cipher.encryptor()
    padded = plaintext + b"\x00" * (16 - (len(plaintext) % 16))

    enc_times = []
    for _ in range(ITERATIONS):
        start = time.perf_counter()
        encryptor.update(padded)
        end = time.perf_counter()
        enc_times.append((end - start) * 1_000_000)

    aes_enc_avg = sum(enc_times[1:]) / 9
    print(f"AES-{ks*8} encrypt: {aes_enc_avg:.2f} µs")

    #AES DECRYPT
    for ks in [16, 24, 32]:
        key = os.urandom(ks)
    cipher = Cipher(algorithms.AES(key), modes.ECB())
    padded = plaintext + b"\x00" * (16 - (len(plaintext) % 16))

    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded)
    decryptor = cipher.decryptor()

    dec_times = []
    for _ in range(ITERATIONS):
        start = time.perf_counter()
        decryptor.update(ciphertext)
        end = time.perf_counter()
        dec_times.append((end - start) * 1_000_000)

    aes_dec_avg = sum(dec_times[1:]) / 9
    print(f"AES-{ks*8} decrypt: {aes_dec_avg:.2f} µs")


#ChaCha20
key = os.urandom(32)
nonce = os.urandom(16)

enc_times = []
for _ in range(ITERATIONS):
    cipher = Cipher(algorithms.ChaCha20(key, nonce), mode=None)
    encryptor = cipher.encryptor()
    start = time.perf_counter()
    encryptor.update(plaintext)
    end = time.perf_counter()
    enc_times.append((end - start) * 1_000_000)

chacha_enc_avg = sum(enc_times[1:]) / 9
print(f"ChaCha20 encrypt: {chacha_enc_avg:.2f} µs")



print("\n=== RSA ENCRYPTION / DECRYPTION ===")

for sec in security_levels:
    keysize = rsa_sizes[sec]

    #Generate RSA key pair
    priv = rsa.generate_private_key(
        public_exponent=65537,
        key_size=keysize
    )
    pub = priv.public_key()

    #RSA can only encrypt small blocks
    small_plain = os.urandom(8)

    #ENCRYPT
    rsa_enc_times = []
    for i in range(ITERATIONS):
        start = time.perf_counter()
        pub.encrypt(
            small_plain,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        end = time.perf_counter()
        rsa_enc_times.append((end - start) * 1000)

    rsa_enc_avg = sum(rsa_enc_times[1:]) / (ITERATIONS - 1)

    #One ciphertext for decrypt timing
    ciphertext = pub.encrypt(
        small_plain,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    #DECRYPT
    rsa_dec_times = []
    for i in range(ITERATIONS):
        start = time.perf_counter()
        priv.decrypt(
            ciphertext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        end = time.perf_counter()
        rsa_dec_times.append((end - start) * 1000)

    rsa_dec_avg = sum(rsa_dec_times[1:]) / (ITERATIONS - 1)

    print(f"RSA Security {sec} -> Enc: {rsa_enc_avg:.2f} ms, Dec: {rsa_dec_avg:.2f} ms")

print("\n === DIGITAL SIGNING (RSA, DSA, ECC) ===")

for sec in security_levels:

    #RSA SIGNING
    priv_rsa = rsa.generate_private_key(
        public_exponent=65537,
        key_size=rsa_sizes[sec]
    )

    rsa_sign_times = []
    for i in range(ITERATIONS):
        start = time.perf_counter()
        priv_rsa.sign(
            plaintext,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        end = time.perf_counter()
        rsa_sign_times.append((end - start) * 1000)
    
    rsa_sign_avg = sum(rsa_sign_times[1:]) / (ITERATIONS -1)

    # DSA SIGNING 
    if dsa_sizes[sec] is not None:
        priv_dsa = dsa.generate_private_key(key_size=dsa_sizes[sec])
        dsa_sign_times = []

        for i in range(ITERATIONS):
            start = time.perf_counter()
            priv_dsa.sign(plaintext, hashes.SHA256())
            end = time.perf_counter()
            dsa_sign_times.append((end - start) * 1000)

        dsa_sign_avg = sum(dsa_sign_times[1:]) / (ITERATIONS - 1)
    else:
        dsa_sign_avg = None

    #ECC SIGNING
    priv_ecc = ec.generate_private_key(ecc_curves[sec])
    ecc_sign_times = []

    for i in range(ITERATIONS):
        start = time.perf_counter()
        priv_ecc.sign(plaintext, ec.ECDSA(hashes.SHA256()))
        end = time.perf_counter()
        ecc_sign_times.append((end - start) * 1000)

    ecc_sign_avg = sum(ecc_sign_times[1:]) / (ITERATIONS - 1)

    print(f"Security {sec} -> RSA sign: {rsa_sign_avg:.2f} ms, DSA Sign: {dsa_sign_avg}, ECC sign: {ecc_sign_avg:.2f} ms")
print("\n=== SIGNATUE VERIFICATION (RSA, DSA, ECC) ===")

for sec in security_levels:

    #RSA VERIFY
    priv_rsa = rsa.generate_private_key(
        public_exponent=65537,
        key_size=rsa_sizes[sec]
    )
    pub_rsa = priv_rsa.public_key()

    sig_rsa = priv_rsa.sign(
        plaintext,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

    rsa_verify_times = []
    for i in range(ITERATIONS):
        start = time.perf_counter()
        pub_rsa.verify(
            sig_rsa,
            plaintext,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        end = time.perf_counter()
        rsa_verify_times.append((end - start) * 1000)
            
    rsa_verify_avg = sum(rsa_verify_times[1:]) / (ITERATIONS - 1)

    #DSA VERIFY
    if dsa_sizes[sec] is not None:
        priv_dsa = dsa.generate_private_key(key_size=dsa_sizes[sec])
        pub_dsa = priv_dsa.public_key()

        sig_dsa = priv_dsa.sign(plaintext, hashes.SHA256())

        dsa_verify_times = []
        for  i in range (ITERATIONS):
            start = time.perf_counter()
            pub_dsa.verify(sig_dsa, plaintext, hashes.SHA256())
            end = time.perf_counter()
            dsa_verify_times.append((end - start) * 1000)

        dsa_verify_avg = sum(dsa_verify_times[1:]) / (ITERATIONS - 1)
    else:
        dsa_verify_avg = None

    # ECC VERIFY 
    priv_ecc = ec.generate_private_key(ecc_curves[sec])
    pub_ecc = priv_ecc.public_key()

    sig_ecc = priv_ecc.sign(plaintext, ec.ECDSA(hashes.SHA256()))

    ecc_verify_times = []
    for i in range(ITERATIONS):
        start = time.perf_counter()
        pub_ecc.verify(sig_ecc, plaintext, ec.ECDSA(hashes.SHA256()))
        end = time.perf_counter()
        ecc_verify_times.append((end - start) * 1000)

    ecc_verify_avg = sum(ecc_verify_times[1:]) / (ITERATIONS - 1)

    print(f"Security {sec} -> RSA verify: {rsa_verify_avg:.2f} ms, DSA verify: {dsa_verify_avg}, ECC verify: {ecc_verify_avg:.2f} ms")

print("\n=== ALL BENCHMARKS COMPLETE ===")