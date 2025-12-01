# Standard libraries for implementation (Step 0.1.1):
import hashlib, hmac, hvac, os, requests, socket, time, uuid, yaml
from pathlib import Path

# Cryptography libraries for the implementation of cryptographic components (Step 0.1.2):
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

# Personal post-quantum cryptographic algorithm libraries (Step 0.1.3):
from dilithium_py.ml_dsa import ML_DSA_44, ML_DSA_65, ML_DSA_87
from kyber_py.ml_kem import ML_KEM_512, ML_KEM_768, ML_KEM_1024

# Scapy libraries for the construction of IKEv2 messages (Step 0.1.4):
from scapy.all import *
from scapy.contrib.ikev2 import *

# Pseudo-random function based on HMAC-SHA256 to derive cryptographic material (Step 0.2):
def prf(key: bytes, data: bytes) -> bytes:
    return hmac.new(key, data, digestmod = hashlib.sha256).digest()

# Pseudo-random function to generate cryptographic material of arbitrary-length (Step 0.3):
def prf_plus(key: bytes, seed: bytes, length: int) -> bytes:
    result, previous, counter = b"", b"", 1 
    while len(result) < length:
        data = previous + seed + bytes([counter])
        previous = prf(key, data)
        result += previous
        counter += 1
    return result[:length]

# Definition of a constant buffer size equal to the UDP MTU (Step 0.4):
BUFFER_SIZE = 1500

# ------------------------------------ Initialization ------------------------------------------------- #

# Reception of input arguments from the server's YAML file  (Step 0.5.1):
with open("server.yaml", "r") as f:
    config = yaml.safe_load(f)

# Input arguments are saved on constants (StJAJep 0.5.2):
HOST, PORT = "0.0.0.0", 4500
VOLUME, VAULT_HOST, VAULT_PORT = config["vault"]["volume"], config["vault"]["host"], config["vault"]["port"]
ML_DSA_LEVEL = config["crypto"]["ml-dsa"]

# Verification of ML-DSA's level of security selected by the client: ML_DSA_65, by default (Step 0.6.1):
ML_DSA_levels = {
    "ML-DSA-44": (ML_DSA_44, "44"),
    "ML-DSA-65": (ML_DSA_65, "65"),
    "ML-DSA-87": (ML_DSA_87, "87")
}

if ML_DSA_LEVEL in ML_DSA_levels:
    ML_DSA, param = ML_DSA_levels[ML_DSA_LEVEL]
    #print(f"Security level selected by server: {ML_DSA_LEVEL}.\n")
else:
    print("ERROR: Security levels for ML-DSA: ML-DSA-44, ML-DSA-65 or ML-DSA-87.")
    exit()

# Preparation for the latter ML-KEM algorithm (Step 0.6.2):
ML_KEM_levels = {
    35: (ML_KEM_512),
    36: (ML_KEM_768),
    37: (ML_KEM_1024)
}

# ------------------------------------ Vault storage -------------------------------------------------- #

# Server creates constants for Vault connection (Step 1.1):
VAULT_ADDR, TOKEN_PATH = f"http://{VAULT_HOST}:{VAULT_PORT}", Path(f"/{VOLUME}/tokens/.vault_root_token")
max_retries, retry_count = 30, 1

# Server creates a function to read the root token from shared volunme (Step 1.2.1):
def read_token(TOKEN_PATH):
    if TOKEN_PATH.exists() and TOKEN_PATH.is_file():
        root_token = TOKEN_PATH.read_text().strip()
        if not root_token:
            print("ERROR: Empty root token.")
            return None
        
        #print(f"[✓] Root Token: {root_token}")
        return root_token
    else:
        return None

# Server creates a function to check Vault connectivity (Step 1.2.2):
def vault_running():
    try:
        r = requests.get(f"{VAULT_ADDR}/v1/sys/health", timeout=1.5)
        return r.status_code in [200, 429, 472, 473, 501, 503]
    except requests.RequestException:
        return False
    

# Server waits for Vault's server to be available (Step 1.3):
def wait_for_vault():
    #print("Waiting for Vault server to be ready...\n")
    for attempt in range(1, max_retries + 1):
        if vault_running():
            #print(f"[✓] Vault session is responding (attempt {attempt})")
            return True
        #print(f"Waiting for Vault... (attempt {attempt}/{max_retries})")
        time.sleep(retry_count)
    print("ERROR: No Vault connection")
    return False

if not wait_for_vault():
        exit(1)

# Server reads the root token from the shared volume (Step 1.4):
root_token = read_token(TOKEN_PATH)
if not root_token:
    print(f"ERROR: Cannot read root token from {TOKEN_PATH}")
    exit(1)

# Server connects to Vault with the captured root token (Step 1.5.1):
try:
    server = hvac.Client(url=VAULT_ADDR, token=root_token)
    
    # Server verifies the Vault authentication (Step 1.5.2):
    if not server.is_authenticated():
        print("ERROR: Authentication with Vault failed")
        exit(1)
    
    #print("[✓] Successfully authenticated with Vault\n")
    
except Exception as e:
    print(f"ERROR connecting to Vault: {e}")
    exit(1)

# Server verifies if it has saved previously its keys in Vault (Step 1.6.1):
try:

    # Server obtains the stored public key in Vault (Step 1.5.2):
    search_public = server.secrets.kv.v2.read_secret_version(
        path = ("server/ML_DSA_"+param+"/public"),
        mount_point = "secret",
        raise_on_deleted_version = True # Silence the warning
    )

    # Server obtains the stored secret key in Vault (Step 1.5.3):
    search_secret = server.secrets.kv.v2.read_secret_version(
        path = ("server/ML_DSA_"+param+"/secret"),
        mount_point = "secret",
        raise_on_deleted_version = True # Silence the warning
    )

    # Server obtains both the public and secret keys from Vault (Step 1.5.4):
    pk_server = bytes.fromhex(list(search_public['data']['data'].values())[-1])
    sk_server = bytes.fromhex(list(search_secret['data']['data'].values())[-1])

    #print("Server's digital signature keys have been found in Vault.\n")

# Server stores its public and secret keys to Vault if it has not been founded (Step 1.6.1):
except hvac.exceptions.InvalidPath:
     
    # Server generates the new pair of digital signature keys (Step 1.6.2)
    try:
        pk_server, sk_server = ML_DSA.keygen()
        pk_VaultFormat, sk_VaultFormat = {"public": pk_server.hex()}, {"secret": sk_server.hex()}

        # Server stores the public keys for digital signature in Vault (Step 1.5.3):
        server.secrets.kv.v2.create_or_update_secret(
            path = ("server/ML_DSA_"+param+"/public"),
            secret = pk_VaultFormat,
            mount_point = "secret"
        )

        # Server stores the secret key for digital signature in Vault (Step 1.5.4):
        server.secrets.kv.v2.create_or_update_secret(
            path = ("server/ML_DSA_"+param+"/secret"),
            secret = sk_VaultFormat,
            mount_point = "secret"
        )

        #print(f"Server's digital signature keys stored in Vault.\n")

    # Server cannot generate the pair of digital signature keys (Step 1.6.1)
    except hvac.exceptions.InvalidPath:
        print(f"Server's digital signature keys could not be stored in Vault.")
        exit() 

# --------------------------------------- SERVER INITIALIZATION --------------------------------------- #

# Server initializes its UDP socket to receive requests (Step 2.1.1):
with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as server_socket:

    # Server prepares to receive requests from clients (Step 2.1.2): 
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind((HOST, PORT))
    #print(f"IKEv2 server waiting in {HOST}:{PORT} (UDP).\n")

    # Server keeps listening to succesive requests from clients (Step 2.1.3):
    while(True):

        # Server receives the request from the client (Step 5.1.1):
        data, addr = server_socket.recvfrom(2 * BUFFER_SIZE)

        # Server parses the received package with Scapy (Step 5.1.2):
        IKE_request = IKEv2(data)

        # Server verifies that the received request is not empty (Step 5.1.3):
        if not IKE_request:
            print("ERROR: Empty response received.")
            exit()

# ------------------------------------- IKE_SA_INIT --------------------------------------------------- #

        # Server receives the IKE_SA_INIT request from the client (Step .):
        if (IKE_request.exch_type == 34):
            IKE_SA_INIT_request = IKE_request

            #print("\n\nIKE_SA_INIT request:")
            #IKE_SA_INIT_request.show()

            # Server verifies the ML-KEM security level used by the client (Step 5.2):
            transform, method_num = IKE_SA_INIT_request[IKEv2_SA].prop.trans, 0
            while transform:
                if transform.transform_type == 6:
                    if 35 <= transform.transform_id <= 37:
                        method_num = transform.transform_id
                        ML_KEM = ML_KEM_levels[method_num]
                        #print(f"ML-KEM Transform ID: {transform.transform_id}\n\n\n")
                transform = transform.payload if isinstance(transform.payload, IKEv2_Transform) else None
                
            if ML_KEM is None:
                raise ValueError("No supported ML-KEM Transform found in SA payload")

            # Server extracts the public keys from the IKE_SA_INIT request (Step 5.3.1):
            payload, pk_dh_client, ek_KEM = IKE_SA_INIT_request, None, None
            while payload:
                if isinstance (payload, IKEv2_KE):
                    if payload.group == 19:

                        # Server extracts the classical public key from the KE1 payload (Step 5.3.2.1):
                        pk_dh_client = payload.ke

                        # Server extracts the "p" and "g" parameters from the Diffie-Hellman public key (Step 5.3.2.2):
                        pk_dh = serialization.load_pem_public_key(pk_dh_client)

                        # Server generates its public and secret key for Diffie-Hellman (Step 5.3.2.3):
                        sk_dh_server = ec.generate_private_key(ec.SECP256R1())
                        pk_dh_server = sk_dh_server.public_key()

                        # Server serialize its public key to send it through the socket (Step 5.3.2.4):
                        pk_dh_serialized = pk_dh_server.public_bytes(
                            encoding=serialization.Encoding.PEM,
                            format=serialization.PublicFormat.SubjectPublicKeyInfo
                        )

                        # Server derives the Diffie-Hellman's shared secret with the client's public and its own secret key (Step 5.3.2.5):
                        shared_secret_DH = sk_dh_server.exchange(ec.ECDH(), pk_dh)

                    elif 35 <= payload.group <= 37:

                        # Server verifies the post-quantum transform ID and KE2 group (Step 5.3.3.1):
                        if (method_num == payload.group):
                            
                            # Server extracts the post-quantum public key from the KE2 payload (Step 5.3.3.2):
                            ek_KEM = payload.ke

                            # Server obtains the shared secret and ciphertext from the ML-KEM (Step 5.3.3.3):
                            shared_secret_KEM, ciphertext_KEM = ML_KEM.encaps(ek_KEM)

                        # Server drops an error if the IKE_SA_INIT request is incorrectly constructed (Step 5.3.3.4):
                        else:
                            raise ValueError("The post-quantum transform ID and KE2 group are different.")
                            
                payload = payload.payload

            # Server generates a 32-byte random Responder's Security Parameter Index (SPI) (Step 5.4):
            SPIr = os.urandom(8)
            
            # Server generates a 32-byte random nonce (Step 5.5):
            Nr = os.urandom(32)

            # Server constructs the header for the IKE_SA_INIT response (Step 6.1):
            ike_hdr = IKEv2(init_SPI=IKE_SA_INIT_request.init_SPI, resp_SPI=SPIr, exch_type=34, flags="Response")

            # Server constructs Security Association payload for the IKE_SA_INIT response (Step 6.2):
            sar1_payload = IKEv2_SA(
                prop = IKEv2_Proposal(
                    proposal = 1,
                    proto = 1,    # Proto ID = IKE(1)
                    trans = [
                        # Transform 1 [ENCR, AES_GCM_16]:
                        IKEv2_Transform(transform_type = 1,  transform_id = 20) /

                        # Transform 2 [PRF, HMAC-SHA2-256]:
                        IKEv2_Transform(transform_type = 2, transform_id = 5) /

                        # Transform 3 [KE, 256-bit-random-ECP]:
                        IKEv2_Transform(transform_type=4, transform_id=19) /

                        # Transform 4 [KE, ML-KEM]:
                        IKEv2_Transform(transform_type=6, transform_id=method_num)
            ]))

            # Server constructs the Key Exchange payloads for the IKE_SA_INIT response (Step 6.3.1):
            ke1_payload = IKEv2_KE(group = 19, ke = pk_dh_serialized)

            # Server constructs the post-quantum Key Exchange payload for the IKE_SA_INIT response (Step 6.3.2)
            ke2_payload = IKEv2_KE(group=method_num, ke=ciphertext_KEM)

            # Server constructs the nonce payload for the IKE_SA_INIT response (Step 6.4):
            nonce_payload = IKEv2_Nonce(nonce = Nr)

            # Server constructs the IKE_SA_INIT response for the ML-KEM-1024 security level (Step 6.5.1):
            IKE_SA_INIT_response = ike_hdr / sar1_payload / ke1_payload / ke2_payload / nonce_payload
    
            # Server prints the resulting IKE_SA_INIT response (Step 6.5.2):
            #print("\n\nIKE_SA_INIT response:")
            #IKE_SA_INIT_response.show()

            # Server sends the IKE_SA_INIT response to the client (Step 6.7):
            server_socket.sendto(bytes(IKE_SA_INIT_response), addr)

# ----------------------------------------- SKEYSEED -------------------------------------------------- #

            # Server uses Diffie-Helman shared secret for the first SKEYSEED (Step 8.1.1):
            shared_secret = shared_secret_DH + shared_secret_KEM

            # Server obtains the nonces "Ni" and "Nr" (8.1.3):
            salt = IKE_SA_INIT_request.nonce + Nr

            # Server prepares the Hash Key Derivation (HKD) function for the SKEYSEED (Step 8.2.1):
            hkdf = HKDF(
                algorithm = hashes.SHA256(),
                length = 32,
                salt = salt,
                info = b'hkdf',
                backend = default_backend()
            )

            # Server obtains the SKEYSEED for future encryption (Step 8.2.2):
            SKEYSEED = hkdf.derive(shared_secret)
            #print(f"SKEYSEED: {SKEYSEED.hex()}\n\n\n")

            # Concatenation of nonces and SPI's for the PRF+ function (Step 8.3):
            seed = salt + IKE_SA_INIT_request.init_SPI + SPIr

            # Cryptographic material extraction from the SKEYSEED (Step 8.4.1):
            crypto_material = prf_plus(SKEYSEED, seed, 7 * 32)

            # Assignment of cryptographic material to seven secrets (Step 8.4.2):
            SK_d = crypto_material[0:32]
            SK_ai, SK_ar = crypto_material[32:64], crypto_material[64:96]
            SK_ei, SK_er = crypto_material[96:128], crypto_material[128:160]
            SK_pi, SK_pr = crypto_material[160:192], crypto_material[192:224]

    # ----------------------------------------- IKE_AUTH -------------------------------------------------- #

            # Server receives the client's IKE_AUTH request (Step 10.1.1):
            data, addr = server_socket.recvfrom(6 * BUFFER_SIZE)
            
            # Server parses the received package with Scapy (Step 10.1.2):
            IKE_AUTH_request = IKEv2(data)

            # Server verifies that the received request is not empty (Step 10.1.3):
            if not IKE_AUTH_request:
                print("ERROR: Empty request received.")
                exit()

            # Server prints the received IKE_AUTH request (Step 10.1.4):
            #print("\n\nIKE_AUTH request:")
            #IKE_AUTH_request.show()
            
            # Server gets the encrypted payload included in the IKE_AUTH request (Step 10.2.1):
            if IKEv2_Encrypted in IKE_AUTH_request:
                encrypted_payload = IKE_AUTH_request[IKEv2_Encrypted].load

            # Server generates the initialization vector for the AES-GCM decryption (Step 10.2.2):
            iv = IKE_AUTH_request[IKEv2].id.to_bytes(4, 'big') + SK_ei[28:]

            # Server tries to decrypt the encrypted payload (Step 10.2.3):
            try:
                decrypted_data = AESGCM(SK_ei).decrypt(iv, encrypted_payload, None)
            except Exception as e:
                print(f"Decryption failed: {e}")

            # Server constructs the decrypted packet from the IKE_AUTH request (Step 10.3.1):
            decrypted_packet = IKEv2_IDi(decrypted_data)

            # Server reconstructed every payload from the decrypted data (Step 10.3.2):
            idi_payload = decrypted_packet[IKEv2_IDi] if IKEv2_IDi in decrypted_packet else None
            cert_payload = decrypted_packet[IKEv2_CERT] if IKEv2_CERT in decrypted_packet else None
            auth_payload = decrypted_packet[IKEv2_AUTH] if IKEv2_AUTH in decrypted_packet else None
            sai2_payload = decrypted_packet[IKEv2_SA] if IKEv2_SA in decrypted_packet else None
            tsi_payload = decrypted_packet[IKEv2_TSi] if IKEv2_TSi in decrypted_packet else None
            tsr_payload = decrypted_packet[IKEv2_TSr] if IKEv2_TSr in decrypted_packet else None

            # Server obtains the public key and the signature from the client (Step 11.2.1):
            pk_client, signature_client = bytes(cert_payload.cert_data), auth_payload.load

            # Server checks the security level for the ML-DSA algorithm used by the client (Step 11.2.2):
            if (len(pk_client) == 1312):
                ML_DSA_client, param_client = ML_DSA_levels["ML-DSA-44"]
            elif (len(pk_client) == 1952):
                ML_DSA_client, param_client = ML_DSA_levels["ML-DSA-65"]
            elif (len(pk_client) == 2592):
                ML_DSA_client, param_client = ML_DSA_levels["ML-DSA-87"]
            else:
                print("Invalid signature.\n")
                server_socket.close()
                exit()
            
            # Server prints the client's security level for the ML-DSA algorithm (Step 11.2.3):
            if ("ML-DSA-"+param_client) not in ML_DSA_levels:
                print("ERROR: Security levels for ML-DSA: ML-DSA-44, ML-DSA-65 or ML-DSA-87.")
                exit()

            # Server searches in Vault for digital signature keys stored for this client (Step 11.2.4.1):
            try:
                search = server.secrets.kv.v2.read_secret_version(
                    path = (addr[0] + "/client/ML_DSA_"+param_client),
                    mount_point = "secret",
                    raise_on_deleted_version = True # Silence the warning
                )

                pk_client_stored = bytes.fromhex(search['data']['data']["public"])
                #print("Client's public key has been found in Vault.")

            # Server stores the server's public key to Vault if it has not been founded (Step 11.2.4.2):
            except hvac.exceptions.InvalidPath:
                
                #print("No client's public key stored in Vault has been found.")
                pk_client_stored = pk_client

                pk_Vault = {"public": pk_client.hex()}
                server.secrets.kv.v2.create_or_update_secret(
                    path = (addr[0] + "/client/ML_DSA_"+param_client),
                    secret = pk_Vault,
                    mount_point = "secret"
                )
                #print(f"Client's public key stored in Vault.")
            
            # Client constructs the IKE_SA_INIT request to be signed (Step 11.3.1.1):
            RealMessage1 = bytes(IKE_SA_INIT_request)

            # Client constructs the responder's nonce to be signed (Step 11.3.1.2):
            NonceRData = Nr

            # Client constructs the MACedIDForI information to be signed (Step 11.3.1.3):
            RestOfInitIDPayload = (idi_payload.IDtype.to_bytes(1, "big") + b"\x00\x00\x00" + socket.inet_aton(idi_payload.ID))
            MACedIDForI = prf(SK_pi, RestOfInitIDPayload)

            # Client constructs the information to be signed for the signature (Step 11.3.1.4):
            initiatorSignedOctets = (RealMessage1 + NonceRData + MACedIDForI)

            # Client computes the hash of the initiatorSignedOctets (Step 11.3.2.1):
            hashedInitiatorSignedOctets = prf(SK_pi, initiatorSignedOctets) 
            
            # Server verifies the client's signature of its public key (Step 11.3.2.2):
            if ML_DSA_client.verify(pk_client_stored, hashedInitiatorSignedOctets, signature_client) == False:
                print("Invalid signature.\n")
                server_socket.close()
                exit()

            # Client constructs the header for the IKE_AUTH response (Step 12.1):
            ike_hdr = IKEv2(init_SPI = IKE_SA_INIT_request.init_SPI, resp_SPI = SPIr, exch_type = 35, flags = "Response")

            # Client constructs the IDi payload (Step 12.2):
            idr_payload = IKEv2_IDi(IDtype = 1, ID = socket.gethostbyname(socket.gethostname()))
            
            # Client constructs the CERT payload (Step 12.3):
            cert_payload = IKEv2_CERT(cert_encoding = 4, cert_data=bytes(pk_server))
            
            # Client constructs the IKE_SA_INIT request to be signed (Step 12.4.1.1):
            RealMessage2 = bytes(IKE_SA_INIT_response)

            # Client constructs the responder's nonce to be signed (Step 12.4.1.2):
            NonceIData = IKE_SA_INIT_request[IKEv2_Nonce].nonce

            # Client constructs the MACedIDForI information to be signed (Step 12.4.1.3):
            RestOfRespIDPayload = (idr_payload.IDtype.to_bytes(1, "big") + b"\x00\x00\x00" + socket.inet_aton(idr_payload.ID))
            MACedIDForR = prf(SK_pr, RestOfRespIDPayload)

            # Client constructs the information to be signed for the signature (Step 12.4.1.4):
            responderSignedOctets = (RealMessage2 + NonceIData + MACedIDForR)

            # Client computes the hash of the initiatorSignedOctets (Step 12.4.2.1):
            hashedResponderSignedOctets = prf(SK_pr, responderSignedOctets) 
            
            # Client signs the hash message with its ML-DSA secret key (Step 12.4.2.2):
            signature = ML_DSA.sign(sk_server, hashedResponderSignedOctets)

            # Client constructs the AUTH component (Step 12.4.3):
            auth_payload = IKEv2_AUTH(auth_type = 14, load = bytes(signature))
            
            # Client constructs the Security Association component for the Child SAs (Step 12.5):
            sar2_payload = IKEv2_SA(
                prop = IKEv2_Proposal(
                    proposal = 1,
                    proto = 1,    # Proto ID = IKE(1)
                    trans = [
                        # Transform 1 [ENCR, AES_GCM_16]:
                        IKEv2_Transform(transform_type = 1,  transform_id = 20) /

                        # Transform 2 [PRF, HMAC-SHA2-256]:
                        IKEv2_Transform(transform_type = 2, transform_id = 5)
            ]))

            # Client constructs the TSi component (Step 12.6.1):
            tsi_payload = IKEv2_TSi(
                traffic_selector = [
                    TrafficSelector(
                        TS_type = 7,                 # TS_IPV4_ADDR_RANGE
                        IP_protocol_ID = 6,
                        start_port = 0,
                        end_port = 65535,
                        starting_address_v4 = socket.gethostbyname(socket.gethostname()),  # Introduce client IP direction.
                        ending_address_v4 = socket.gethostbyname(socket.gethostname())
                    )
                ]
            )

            # Client constructs the TSr component (Step 12.6.2):
            tsr_payload = IKEv2_TSr(
                traffic_selector = [
                    TrafficSelector(
                        TS_type = 7,                           # TS_IPV4_ADDR_RANGE
                        IP_protocol_ID = 6,
                        start_port = 0,
                        end_port = 65535,
                        starting_address_v4 = "0.0.0.0",
                        ending_address_v4 = "255.255.255.255"  # From HOST to anywhere
                    )
                ]
            )
            
            # Server constructs the IKE_AUTH response (Step 12.7):
            data = idr_payload / cert_payload / auth_payload / sar2_payload / tsi_payload / tsr_payload

            # Server generates the initialization vector for the AES-GCM encryption (Step 12.8.1):
            iv = ike_hdr.id.to_bytes(4, 'big') + SK_er[28:]
            
            # Server encrypts the data with AES-GCM (Step 12.8.2):
            encrypted_data = AESGCM(SK_er).encrypt(iv, bytes(data), None)

            # Server constructs the IKEv2 Encrypted and Authenticated (Step 12.8.3):
            encrypted_payload = IKEv2_Encrypted(load = encrypted_data)

            # Server constructs the IKE_AUTH response (Step 12.9.1):
            IKE_AUTH_response = ike_hdr / encrypted_payload

            # Client prints the resulting IKE_AUTH response (Step 12.9.2):
            #print("\n\nIKE_AUTH response:")
            #IKE_AUTH_response.show()

            # Server sends the IKE_AUTH response to the client (Step 12.10):
            server_socket.sendto(bytes(IKE_AUTH_response), addr)

            # Server obtains the nonces "Ni" and "Nr" (12.11):
            seed = IKE_SA_INIT_request.nonce + Nr

            # Server extracts cryptographic material from the shared SK_d key (Step 15.1):
            KEYMAT = prf_plus(SK_d, seed, 32)

            session_elements = {
                "SPIi": IKE_SA_INIT_request.init_SPI,
                "SPIr": SPIr,
                "SK_d": SK_d,
                "SK_ai": SK_ai,
                "SK_ar": SK_ar,
                "SK_ei": SK_ei,
                "SK_er": SK_er,
                "SK_pi": SK_pi,
                "SK_pr": SK_pr
            }

            vault_path = f"{addr[0]}/PQC/server/IKEv2"

            for name, value in session_elements.items():
                try:
                    server.secrets.kv.v2.create_or_update_secret(
                        path = f"{vault_path}/{name}",
                        secret = {name: value.hex()},
                        mount_point = "secret"
                    )

                except hvac.exceptions.Forbidden:
                    print(f"Access denied to {vault_path}/{name}. Check policy or token.")
                    exit()

                except hvac.exceptions.VaultError as e:
                    print(f"Vault error while processing {name}: {e}")
                    exit()

# ----------------------------------- CREATE_CHILD_SA ------------------------------------------------- #
        
        # Server receives the CREATE_CHILD_SA request from the client (Step .):
        elif (IKE_request.exch_type == 36):

            CREATE_CHILD_SA_request = IKE_request

            #print("\n\CREATE_CHILD_SA request:")
            #CREATE_CHILD_SA_request.show()

            try:
                search = server.secrets.kv.v2.list_secrets(
                    path=f"{addr[0]}/PQC/server/IKEv2",
                    mount_point="secret"
                )

            # Client aborts the transmission of information to the server (Step .):
            except Exception as e:
                print(f"Error reading {addr[0]}/PQC/server/IKEv2: {e}")
                server_socket.close()
                exit()

            session_elements = {}

            for name in search["data"]["keys"]:
                try:
                    secret = server.secrets.kv.v2.read_secret_version(
                        path=f"{addr[0]}/PQC/server/IKEv2/{name}",
                        mount_point="secret",
                        raise_on_deleted_version=True
                    )

                    session_elements[name] = secret["data"]["data"].get(name)

                except Exception as e:
                    print(f"Error reading {name}: {e}")
                    server_socket.close()
                    exit()

            SPIi  = bytes.fromhex(session_elements["SPIi"])
            SPIr  = bytes.fromhex(session_elements["SPIr"])
            SK_d  = bytes.fromhex(session_elements["SK_d"])
            SK_ei = bytes.fromhex(session_elements["SK_ei"])
            SK_er = bytes.fromhex(session_elements["SK_er"])

            if SPIi != CREATE_CHILD_SA_request.init_SPI or  SPIr != CREATE_CHILD_SA_request.resp_SPI:
                print("ERROR: Security Parameter Index is incorrect.")
                exit()
            
            # Server gets the encrypted payload included in the IKE_AUTH request (Step 10.2.1):
            if IKEv2_Encrypted in CREATE_CHILD_SA_request:
                encrypted_payload = CREATE_CHILD_SA_request[IKEv2_Encrypted].load

            # Server generates the initialization vector for the AES-GCM decryption (Step 10.2.2):
            iv = CREATE_CHILD_SA_request[IKEv2].id.to_bytes(4, 'big') + SK_ei[28:]

            # Server tries to decrypt the encrypted payload (Step 10.2.3):
            try:
                decrypted_data = AESGCM(SK_ei).decrypt(iv, encrypted_payload, None)
            except Exception as e:
                print(f"Decryption failed: {e}")

            # Server constructs the decrypted packet from the IKE_AUTH request (Step 10.3.1):
            decrypted_packet = IKEv2_SA(decrypted_data)

            # Server reconstructed every payload from the decrypted data (Step 10.3.2):
            sai1_payload = decrypted_packet[IKEv2_SA] if IKEv2_SA in decrypted_packet else None
            kei_payload = decrypted_packet[IKEv2_KE] if IKEv2_KE in decrypted_packet else None
            nonce_payload = decrypted_packet[IKEv2_Nonce] if IKEv2_Nonce in decrypted_packet else None
            tsi_payload = decrypted_packet[IKEv2_TSi] if IKEv2_TSi in decrypted_packet else None
            tsr_payload = decrypted_packet[IKEv2_TSr] if IKEv2_TSr in decrypted_packet else None

            transform, method_num = sai1_payload.prop.trans, 0
            while transform:
                if transform.transform_type == 6:
                    if 35 <= transform.transform_id <= 37:
                        method_num = transform.transform_id
                        ML_KEM = ML_KEM_levels[method_num]
                        #print(f"ML-KEM Transform ID: {transform.transform_id}\n\n\n")
                transform = transform.payload if isinstance(transform.payload, IKEv2_Transform) else None
                
            if ML_KEM is None:
                raise ValueError("No supported ML-KEM Transform found in SA payload")

            # Server extracts the public keys from the IKE_SA_INIT request (Step 5.3.1):
            if 35 <= kei_payload.group <= 37:

                # Server verifies the post-quantum transform ID and KE2 group (Step 5.3.3.1):
                if (method_num == kei_payload.group):
                    
                    # Server extracts the post-quantum public key from the KE2 payload (Step 5.3.3.2):
                    ek_KEM = kei_payload.ke

                    # Server obtains the shared secret and ciphertext from the ML-KEM (Step 5.3.3.3):
                    shared_secret_KEM, ciphertext_KEM = ML_KEM.encaps(ek_KEM)

                # Server drops an error if the IKE_SA_INIT request is incorrectly constructed (Step 5.3.3.4):
                else:
                    raise ValueError("The post-quantum transform ID and KE2 group are different.")
                        
            # Server generates a 32-byte random nonce (Step 5.5):
            Nr = os.urandom(32)

            ike_hdr = IKEv2(
                init_SPI = CREATE_CHILD_SA_request.init_SPI,        
                resp_SPI = CREATE_CHILD_SA_request.resp_SPI,       
                exch_type = 36,         # IKE_SA_INIT
                flags = "Initiator"     # I (Initiator)
            )

            # Client constructs Security Association payload for the IKE_SA_INIT request (Step 4.2):
            sar1_payload = IKEv2_SA(
                prop = IKEv2_Proposal(
                    proposal = 1,
                    proto = 1,    # Proto ID = IKE(1)
                    trans = [
                        # Transform 1 [ENCR, AES_GCM_16]:
                        IKEv2_Transform(transform_type = 1,  transform_id = 20) /

                        # Transform 2 [PRF, HMAC-SHA2-256]:
                        IKEv2_Transform(transform_type = 2, transform_id = 5) /

                        # Transform 4 [KE, ML-KEM]:
                        IKEv2_Transform(transform_type=6, transform_id=method_num)
            ]))

            # Client constructs the classic Key Exchange payload for the IKE_SA_INIT request (Step 4.3.1):
            ker_payload = IKEv2_KE(group=method_num, ke=ciphertext_KEM)
        
            # Client generates a 32-byte random nonce (Step 2.3.2):
            Nr = os.urandom(32)

            # Client constructs the Nonce payload for the IKE_SA_INIT request (Step 4.4):
            nonce_payload = IKEv2_Nonce(nonce = Nr)

            # Client constructs the TSi component (Step 9.6.1):
            tsi_payload = IKEv2_TSi(
                traffic_selector = [
                    TrafficSelector(
                        TS_type = 7,                 # TS_IPV4_ADDR_RANGE
                        IP_protocol_ID = 6,
                        start_port = 0,
                        end_port = 65535,
                        starting_address_v4 = socket.gethostbyname(socket.gethostname()),  # Introduce client IP direction.
                        ending_address_v4 = socket.gethostbyname(socket.gethostname())
                    )
                ]
            )

            # Client constructs the TSr component (Step 9.6.2):
            tsr_payload = IKEv2_TSr(
                traffic_selector = [
                    TrafficSelector(
                        TS_type = 7,                           # TS_IPV4_ADDR_RANGE
                        IP_protocol_ID = 6,
                        start_port = 0,
                        end_port = 65535,
                        starting_address_v4 = "0.0.0.0",
                        ending_address_v4 = "255.255.255.255"  # From HOST to anywhere
                    )
                ]
            )

            # Client sai1_payload the IKE_AUTH request (Step 9.7):
            data = sar1_payload / ker_payload / nonce_payload / tsi_payload / tsr_payload

            # Client generates the initialization vector for the AES-GCM encryption (Step 9.8.1):
            iv = ike_hdr.id.to_bytes(4, 'big') + SK_er[28:]

            # Client encrypts the data with AES-GCM (Step 9.8.2):
            encrypted_data = AESGCM(SK_er).encrypt(iv, bytes(data), None)

            # Client constructs the IKEv2 Encrypted and Authenticated (Step 9.8.3):
            encrypted_payload = IKEv2_Encrypted(load = encrypted_data)

            # Client constructs the IKE_AUTH request (Step 9.9.1):
            CREATE_CHILD_SA_response = ike_hdr / encrypted_payload

            # Client prints the resulting IKE_AUTH request (Step 9.9.2):
            #print("CREATE_CHILD_SA response:")
            #CREATE_CHILD_SA_response.show()

            # Client sends the IKE_AUTH request to the server (Step 9.10):
            server_socket.sendto(bytes(CREATE_CHILD_SA_response), addr)

            # Concatenation of nonces and SPI's for the PRF+ function (Step 8.3):
            seed = shared_secret_KEM + decrypted_packet[IKEv2_Nonce].nonce + Nr

            # Server extracts cryptographic material from the shared SK_d key (Step 15.1):
            KEYMAT = prf_plus(SK_d, seed, 32)

        # Server receives an invalid request's exchange type from the client (Step .):
        else:
            print("Invalid exchange type of the IKEv2 request.\n")
            server_socket.close()
            exit()  
        
        data, addr = server_socket.recvfrom(BUFFER_SIZE)

        id = data.decode()

        print(f"Secret key's identifier: {str(id)}\n")
        #print(f"Shared secret's value: {KEYMAT.hex()}\n")

        try:
            server.secrets.kv.v2.create_or_update_secret(
                path = f"{addr[0]}/PQC/keys/{id}",
                secret = {f"{id}": KEYMAT.hex()},
                mount_point = "secret"
            )

            #print("The shared secret has been stored in Vault.\n")

        except hvac.exceptions.InvalidPath:
            print("The shared secret has not been stored in Vault.\n")
            exit(1)