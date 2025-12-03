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

# Reception of input arguments from the client's YAML file (Step 0.6.1):
with open("client.yaml", "r") as f:
    config = yaml.safe_load(f)

parser = argparse.ArgumentParser(description="Vault client")

parser.add_argument("-ip", required=True, help="Server's IP address")
parser.add_argument("-mlkem", help="ML-KEM's security level")
parser.add_argument("-id", help="Secret key's identifier")

args = parser.parse_args()

VOLUME, VAULT_HOST, VAULT_PORT = config["vault"]["volume"], config["vault"]["host"], config["vault"]["port"]

VAULT_ADDR, TOKEN_PATH = f"http://{VAULT_HOST}:{VAULT_PORT}", Path(f"{Path.home()}/{VOLUME}/tokens/.vault_root_token")
max_retries, retry_count = 30, 1

# Client creates a function to read the root token from shared volunme (Step 1.2.1):
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

# Client creates a function to check Vault connectivity (Step 1.2.2):
def vault_running():
    try:
        r = requests.get(f"{VAULT_ADDR}/v1/sys/health", timeout=1.5)
        return r.status_code in [200, 429, 472, 473, 501, 503]
    except requests.RequestException:
        return False

# Client waits for Vault's server to be available (Step 1.3):
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

# Client reads the root token from the shared volume (Step 1.4):
root_token = read_token(TOKEN_PATH)
if not root_token:
    print(f"ERROR: Cannot read root token from {TOKEN_PATH}")
    exit(1)

# Client connects to Vault with the captured root token (Step 1.5.1):
try:
    client = hvac.Client(url=VAULT_ADDR, token=root_token)
    
    # Client verifies the Vault authentication (Step 1.5.2):
    if not client.is_authenticated():
        print("ERROR: Authentication with Vault failed")
        exit(1)
    
    #print("[✓] Successfully authenticated with Vault\n")
    
except Exception as e:
    print(f"ERROR connecting to Vault: {e}")
    exit(1)

SERVER_HOST, ID = args.ip, args.id

if ID == None:

    PORT = 4500

    # Input arguments are saved on constants (Step 0.6.2):
    ML_KEM_LEVEL, ML_DSA_LEVEL = args.mlkem, config["crypto"]["ml-dsa"]

    # Verification of ML-DSA's level of security selected by the client: ML_DSA_65, by default (Step 0.7.1):
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

    # Verification of ML-KEM's level of security selected by the client (Step 0.7.2):
    ML_KEM_levels = {
        "ML-KEM-512": (ML_KEM_512, 35),
        "ML-KEM-768": (ML_KEM_768, 36),
        "ML-KEM-1024": (ML_KEM_1024, 37)
    }

    if ML_KEM_LEVEL in ML_KEM_levels:
        ML_KEM, method_num = ML_KEM_levels[ML_KEM_LEVEL]
        #print(f"Security level selected by client: {ML_KEM_LEVEL}.\n")
    elif ML_KEM_LEVEL == None:
        ML_KEM, method_num = ML_KEM_levels["ML-KEM-768"]
    else:
        print("ERROR: Security levels for ML-KEM: ML-KEM-512, ML-KEM-768 or ML-KEM-1024.")
        exit()

    # ------------------------------------ Vault storage -------------------------------------------------- #

    # Client creates constants for Vault connection (Step 1.1):

        
    # Client verifies if previously it has saved its keys in Vault (Step 1.6.1):
    try:

        # Server obtains the stored public key in Vault (Step 1.5.2):
        search_public = client.secrets.kv.v2.read_secret_version(
            path = ("client/ML_DSA_"+param+"/public"),
            mount_point = "secret",
            raise_on_deleted_version = True # Silence the warning
        )

        # Server obtains the stored secret key in Vault (Step 1.5.3):
        search_secret = client.secrets.kv.v2.read_secret_version(
            path = ("client/ML_DSA_"+param+"/secret"),
            mount_point = "secret",
            raise_on_deleted_version = True # Silence the warning
        )

        # Server obtains both the public and secret keys from Vault (Step 1.5.4):
        pk_client = bytes.fromhex(list(search_public['data']['data'].values())[-1])
        sk_client = bytes.fromhex(list(search_secret['data']['data'].values())[-1])

        #print("Client's digital signature keys have been found in Vault.\n")

    # Client stores its public and secret keys to Vault if it has not been founded (Step 1.6.1):
    except hvac.exceptions.InvalidPath:

        # Client generates the new pair of digital signature keys (Step 1.6.2)
        try:
            pk_client, sk_client = ML_DSA.keygen()
            pk_VaultFormat, sk_VaultFormat = {"public": pk_client.hex()}, {"secret": sk_client.hex()}

            # Server stores the public keys for digital signature in Vault (Step 1.5.3):
            client.secrets.kv.v2.create_or_update_secret(
                path = ("client/ML_DSA_"+param+"/public"),
                secret = pk_VaultFormat,
                mount_point = "secret"
            )

            # Server stores the secret key for digital signature in Vault (Step 1.5.4):
            client.secrets.kv.v2.create_or_update_secret(
                path = ("client/ML_DSA_"+param+"/secret"),
                secret = sk_VaultFormat,
                mount_point = "secret"
            )

            #print(f"Client's digital signature keys have been stored in Vault.\n")

        # Client cannot generate the pair of digital signature keys (Step 1.6.1):
        except hvac.exceptions.InvalidPath:
            print(f"Client's digital signature keys could not be stored in Vault")
            exit()

    # --------------------------------------- CLIENT INITIALIZATION --------------------------------------- #

    # Client initializes its UDP socket to send requests (Step 2.2.1):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client_socket:

        # Client connects to the server located at HOST and PORT (Step 2.2.2):
        client_socket.connect((SERVER_HOST, PORT))
        #print(f"Connection request accepted at {SERVER_HOST}:{PORT} (UDP).\n")

    # ----------------------------------------- CREATE_SA_CHILD ------------------------------------------- #

        # Client generates the information to start the CREATE_SA_CHILD exchange (Step .):
        try:
            search = client.secrets.kv.v2.list_secrets(
                path=f"{SERVER_HOST}/PQC/client//IKEv2",
                mount_point="secret"
            )

            session_elements = {}

            for name in search["data"]["keys"]:
                try:
                    secret = client.secrets.kv.v2.read_secret_version(
                        path=f"{SERVER_HOST}/PQC/client/IKEv2/{name}",
                        mount_point="secret",
                        raise_on_deleted_version=True
                    )

                    session_elements[name] = secret["data"]["data"].get(name)

                except Exception as e:
                    print(f"Error reading {name}: {e}")
                    client_socket.close()
                    exit()

            SPIi  = bytes.fromhex(session_elements["SPIi"])
            SPIr  = bytes.fromhex(session_elements["SPIr"])
            SK_d  = bytes.fromhex(session_elements["SK_d"])
            SK_ei = bytes.fromhex(session_elements["SK_ei"])
            SK_er = bytes.fromhex(session_elements["SK_er"])

            #print(f"Initializating CREATE_SA_CHILD exchange...")
            
            ike_hdr = IKEv2(
                init_SPI = SPIi,        # Initiator's value to identify a unique IKE Security Association
                resp_SPI = SPIr,        # Responder's value to identify a unique IKE Security Association (0)
                exch_type = 36,         # IKE_SA_INIT
                flags = "Initiator"     # I (Initiator)
            )

            # Client constructs Security Association payload for the IKE_SA_INIT request (Step 4.2):
            sai1_payload = IKEv2_SA(
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

            # Client generates the encapsulation and decapsulation keys for first KEM exchange (Step 2.1):
            ek_KEM, dk_KEM = ML_KEM.keygen()

            # Client constructs the classic Key Exchange payload for the IKE_SA_INIT request (Step 4.3.1):
            kei_payload = IKEv2_KE(group=method_num, ke=ek_KEM)
        
            # Client generates a 32-byte random nonce (Step 2.3.2):
            Ni = os.urandom(32)

            # Client constructs the Nonce payload for the IKE_SA_INIT request (Step 4.4):
            nonce_payload = IKEv2_Nonce(nonce = Ni)

            # Client constructs the TSi component (Step 9.6.1):
            tsi_payload = IKEv2_TSi(
                traffic_selector = [
                    TrafficSelector(
                        TS_type = 7,                 # TS_IPV4_ADDR_RANGE
                        IP_protocol_ID = 17,
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
            data = sai1_payload / kei_payload / nonce_payload / tsi_payload / tsr_payload

            # Client generates the initialization vector for the AES-GCM encryption (Step 9.8.1):
            iv = ike_hdr.id.to_bytes(4, 'big') + SK_ei[28:]

            # Client encrypts the data with AES-GCM (Step 9.8.2):
            encrypted_data = AESGCM(SK_ei).encrypt(iv, bytes(data), None)

            # Client constructs the IKEv2 Encrypted and Authenticated (Step 9.8.3):
            encrypted_payload = IKEv2_Encrypted(load = encrypted_data)

            # Client constructs the IKE_AUTH request (Step 9.9.1):
            CREATE_CHILD_SA_request = ike_hdr / encrypted_payload

            # Client prints the resulting IKE_AUTH request (Step 9.9.2):
            #print("\n\nCREATE_CHILD_SA request:")
            #CREATE_CHILD_SA_request.show()

            # Client sends the IKE_AUTH request to the server (Step 9.10):
            client_socket.sendto(bytes(CREATE_CHILD_SA_request), (SERVER_HOST, PORT))

            # Client receives the IKE_AUTH response from the server (Step 13.1.1):
            data, addr = client_socket.recvfrom(2 * BUFFER_SIZE)

            # Server parses the received package with Scapy (Step 5.1.2):
            CREATE_CHILD_SA_response = IKEv2(data)

            # Server verifies that the received request is not empty (Step 5.1.3):
            if not CREATE_CHILD_SA_response:
                print("ERROR: Empty response received.")
                exit()

            #print("\n\nCREATE_CHILD_SA response:")
            #CREATE_CHILD_SA_response.show()

            # Server gets the encrypted payload included in the IKE_AUTH request (Step 10.2.1):
            if IKEv2_Encrypted in CREATE_CHILD_SA_response:
                encrypted_payload = CREATE_CHILD_SA_response[IKEv2_Encrypted].load

            # Server generates the initialization vector for the AES-GCM decryption (Step 10.2.2):
            iv = CREATE_CHILD_SA_response[IKEv2].id.to_bytes(4, 'big') + SK_er[28:]

            # Server tries to decrypt the encrypted payload (Step 10.2.3):
            try:
                decrypted_data = AESGCM(SK_er).decrypt(iv, encrypted_payload, None)
            except Exception as e:
                print(f"Decryption failed: {e}")

            # Server constructs the decrypted packet from the IKE_AUTH request (Step 10.3.1):
            decrypted_packet = IKEv2_SA(decrypted_data)

            # Server reconstructed every payload from the decrypted data (Step 10.3.2):
            sar1_payload = decrypted_packet[IKEv2_SA] if IKEv2_SA in decrypted_packet else None
            ker_payload = decrypted_packet[IKEv2_KE] if IKEv2_KE in decrypted_packet else None
            nonce_payload = decrypted_packet[IKEv2_Nonce] if IKEv2_Nonce in decrypted_packet else None
            tsi_payload = decrypted_packet[IKEv2_TSi] if IKEv2_TSi in decrypted_packet else None
            tsr_payload = decrypted_packet[IKEv2_TSr] if IKEv2_TSr in decrypted_packet else None

            # Server extracts the public keys from the IKE_SA_INIT request (Step 5.3.1):
            if 35 <= ker_payload.group <= 37:

                # Server verifies the post-quantum transform ID and KE2 group (Step 5.3.3.1):
                if (method_num == ker_payload.group):
                    
                    # Client extracts the post-quantum ciphertext from the KE2 payload (Step 7.2.3.1):
                    ciphertext_KEM = ker_payload.ke

                    # Client obtains the shared secret from the ML-KEM (Step 7.2.3.2):
                    shared_secret_KEM = ML_KEM.decaps(dk_KEM, ciphertext_KEM)

                # Server drops an error if the IKE_SA_INIT request is incorrectly constructed (Step 5.3.3.4):
                else:
                    raise ValueError("The post-quantum transform ID and KE2 group are different.")

            # Concatenation of nonces and SPI's for the PRF+ function (Step 8.3):
            seed = shared_secret_KEM + Ni + nonce_payload.nonce

            # Cryptographic material extraction from the SKEYSEED (Step 8.4.1):
            KEYMAT = prf_plus(SK_d, seed, 32)
            #print(f"Shared secret: {KEYMAT.hex()}\n")

        except hvac.exceptions.InvalidPath:

            # Client generates the information to start the IKE_SA_INIT exchange (Step .):
            try:
                #print(f"Initializating IKE_SA_INIT exchange...")

                # Client generates the encapsulation and decapsulation keys for first KEM exchange (Step 2.1):
                ek_KEM, dk_KEM = ML_KEM.keygen()

                # Client generates the public and secret keys for Diffie-Hellman exchange (Step 2.2.1):
                sk_dh_client = ec.generate_private_key(ec.SECP256R1())
                pk_dh_client = sk_dh_client.public_key()

                # Client serialize the public key (g^i) to send it through the socket (Step 2.2.2):
                pk_dh = pk_dh_client.public_bytes (
                    encoding = serialization.Encoding.PEM,
                    format = serialization.PublicFormat.SubjectPublicKeyInfo
                )

                # Client generates a 8-byte random initiator's SPIi and an empty string for SPIr (Step 2.3.1):
                SPIi, SPIr = os.urandom(8), b"\x00"*8

                # Client generates a 32-byte random nonce (Step 2.3.2):
                Ni = os.urandom(32)

                # Client constructs the header for the IKE_SA_INIT request (RFC 7296, p.73) (Step 4.1):
                ike_hdr = IKEv2(
                    init_SPI = SPIi,        # Initiator's value to identify a unique IKE Security Association
                    resp_SPI = SPIr,        # Responder's value to identify a unique IKE Security Association (0)
                    exch_type = 34,         # IKE_SA_INIT
                    flags = "Initiator"     # I (Initiator)
                )

                # Client constructs Security Association payload for the IKE_SA_INIT request (Step 4.2):
                sai1_payload = IKEv2_SA(
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

                # Client constructs the classic Key Exchange payload for the IKE_SA_INIT request (Step 4.3.1):
                ke1_payload = IKEv2_KE(group=19, ke=pk_dh)
            
                # Client constructs the post-quantum Key Exchange payload for the IKE_SA_INIT request (Step 4.3.2):
                ke2_payload = IKEv2_KE(group=method_num, ke=ek_KEM)

                # Client constructs the Nonce payload for the IKE_SA_INIT request (Step 4.4):
                nonce_payload = IKEv2_Nonce(nonce = Ni)

                # Client constructs the IKE_SA_INIT request (Step 4.5.1):
                IKE_SA_INIT_request = ike_hdr / sai1_payload / ke1_payload / ke2_payload / nonce_payload

                # Client prints the resulting IKE_SA_INIT request (Step 4.5.2):
                #print("IKE_SA_INIT request:")
                #IKE_SA_INIT_request.show()

                # Client sends the IKE_SA_INIT request to the server (Step 4.6):
                client_socket.sendto(bytes(IKE_SA_INIT_request), (SERVER_HOST, PORT))

                # Client receives the IKE_SA_INIT response from the server (Step 7.1.1):
                data, addr = client_socket.recvfrom(2 * BUFFER_SIZE)

                # Client parses the received package with Scapy (Step 7.1.2):
                IKE_SA_INIT_response = IKEv2(data)

                # Client verifies that the received response is not empty (Step 7.1.3):
                if not IKE_SA_INIT_response:
                    print("ERROR: Empty response received.")
                    # TIMER DE RETRANSMISIÓN
                    exit()

                # Client prints the received IKE_SA_INIT response (Step 7.1.4):
                #print("\n\nIKE_SA_INIT response:")
                #IKE_SA_INIT_response.show()

                # Client extracts the public keys from the IKE_SA_INIT response (Step 7.2.1):
                payload, pk_dh_server, ciphertext_KEM = IKE_SA_INIT_response, None, None
                while payload:
                    if isinstance (payload, IKEv2_KE):
                        if payload.group == 19:

                            # Client extracts the classical public key from the KE1 payload (Step 7.2.2.1):
                            pk_dh_server = payload.ke

                            # Client extracts the server's DH public key from the IKE_SA_INIT response (7.2.2.2):
                            pk_dh = serialization.load_pem_public_key(pk_dh_server)

                            # Client obtains the shared secret from the Diffie-Hellman (Step 7.2.2.3):
                            shared_secret_DH = sk_dh_client.exchange(ec.ECDH(), pk_dh)
                
                        elif 35 <= payload.group <= 37:

                            # Server verifies the post-quantum transform ID and KE2 group (Step 7.3.3.1):
                            if (method_num == payload.group):

                                # Client extracts the post-quantum ciphertext from the KE2 payload (Step 7.2.3.1):
                                ciphertext_KEM = payload.ke

                                # Client obtains the shared secret from the ML-KEM (Step 7.2.3.2):
                                shared_secret_KEM = ML_KEM.decaps(dk_KEM, ciphertext_KEM)

                            # Server drops an error if the IKE_SA_INIT request is incorrectly constructed (Step 7.3.3.4):
                            else:
                                raise ValueError("The post-quantum transform ID and KE2 group are different.")

                    payload = payload.payload

    # ----------------------------------------- SKEYSEED -------------------------------------------------- #

                # Client uses Diffie-Helman shared secret for the first SKEYSEED (Step 8.1.1):
                shared_secret = shared_secret_DH + shared_secret_KEM

                # Client obtains the nonces "Ni" and "Nr" (8.1.3):
                salt = Ni + IKE_SA_INIT_response.nonce

                # Client prepares the Hash Key Derivation (HKD) function for the SKEYSEED (Step 8.2.1):
                hkdf = HKDF(
                    algorithm = hashes.SHA256(),
                    length = 32,
                    salt = salt,
                    info = b'hkdf',
                    backend = default_backend()
                )

                # Client obtains the SKEYSEED for future encryption (Step 8.2.2):
                SKEYSEED = hkdf.derive(shared_secret)
                #print(f"SKEYSEED: {SKEYSEED.hex()}\n\n\n")

                # Concatenation of nonces and SPI's for the PRF+ function (Step 8.3):
                seed = salt + SPIi + IKE_SA_INIT_response.resp_SPI

                # Cryptographic material extraction from the SKEYSEED (Step 8.4.1):
                crypto_material = prf_plus(SKEYSEED, seed, 7 * 32)

                # Assignment of cryptographic material to seven secrets (Step 8.4.2):
                SK_d = crypto_material[0:32]
                SK_ai, SK_ar = crypto_material[32:64], crypto_material[64:96]
                SK_ei, SK_er = crypto_material[96:128], crypto_material[128:160]
                SK_pi, SK_pr = crypto_material[160:192], crypto_material[192:224]

    # ----------------------------------------- IKE_AUTH -------------------------------------------------- #

                # Client constructs the header for the IKE_AUTH response (Step 9.1):
                ike_hdr = IKEv2(init_SPI = SPIi, resp_SPI = IKE_SA_INIT_response.resp_SPI, id = 1, exch_type = 35, flags = "Initiator")

                # Client constructs the IDi payload (Step 9.2):
                idi_payload = IKEv2_IDi(IDtype = 1, ID = socket.gethostbyname(socket.gethostname()))

                # Client constructs the CERT payload (Step 9.3):
                cert_payload = IKEv2_CERT(cert_encoding = 4, cert_data=bytes(pk_client))

                # Client constructs the IKE_SA_INIT request to be signed (Step 9.4.1.1):
                RealMessage1 = bytes(IKE_SA_INIT_request)

                # Client constructs the responder's nonce to be signed (Step 9.4.1.2):
                NonceRData = IKE_SA_INIT_response[IKEv2_Nonce].nonce

                # Client constructs the MACedIDForI information to be signed (Step 9.4.1.3):
                RestOfInitIDPayload = (idi_payload.IDtype.to_bytes(1, "big") +  b"\x00\x00\x00" + socket.inet_aton(idi_payload.ID))
                MACedIDForI = prf(SK_pi, RestOfInitIDPayload)

                # Client constructs the information to be signed for the signature (Step 9.4.1.4):
                initiatorSignedOctets = (RealMessage1 + NonceRData + MACedIDForI)

                # Client computes the hash of the initiatorSignedOctets (Step 9.4.2.1):
                hashedInitiatorSignedOctets = prf(SK_pi, initiatorSignedOctets) 
                
                # Client signs the hash message with its ML-DSA secret key (Step 9.4.2.2):
                signature = ML_DSA.sign(sk_client, hashedInitiatorSignedOctets)

                # Client constructs the AUTH component (Step 9.4.3):
                auth_payload = IKEv2_AUTH(auth_type = 14, load = bytes(signature))

                # Client constructs the Security Association component for the Child SAs (Step 9.5):
                sai2_payload = IKEv2_SA(
                    prop = IKEv2_Proposal(
                        proposal = 1,
                        proto = 1,    # Proto ID = IKE(1)
                        trans = [
                            # Transform 1 [ENCR, AES_GCM_16]:
                            IKEv2_Transform(transform_type = 1,  transform_id = 20) /

                            # Transform 2 [PRF, HMAC-SHA2-256]:
                            IKEv2_Transform(transform_type = 2, transform_id = 5)
                ]))

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

                # Client constructs the IKE_AUTH request (Step 9.7):
                data = idi_payload / cert_payload / auth_payload / sai2_payload / tsi_payload / tsr_payload

                # Client generates the initialization vector for the AES-GCM encryption (Step 9.8.1):
                iv = ike_hdr.id.to_bytes(4, 'big') + SK_ei[28:]

                # Client encrypts the data with AES-GCM (Step 9.8.2):
                encrypted_data = AESGCM(SK_ei).encrypt(iv, bytes(data), None)

                # Client constructs the IKEv2 Encrypted and Authenticated (Step 9.8.3):
                encrypted_payload = IKEv2_Encrypted(load = encrypted_data)

                # Client constructs the IKE_AUTH request (Step 9.9.1):
                IKE_AUTH_request = ike_hdr / encrypted_payload
                
                # Client prints the resulting IKE_AUTH request (Step 9.9.2):
                #print("\n\nIKE_AUTH request:")
                #IKE_AUTH_request.show()

                # Client sends the IKE_AUTH request to the server (Step 9.10):
                client_socket.sendto(bytes(IKE_AUTH_request), (SERVER_HOST, PORT))

                # Client receives the IKE_AUTH response from the server (Step 13.1.1):
                data, addr = client_socket.recvfrom(6*BUFFER_SIZE)

                # Client parses the received package with Scapy (Step 13.1.2):
                IKE_AUTH_response = IKEv2(data)

                # Client verifies that the received request is not empty (Step 13.1.3):
                if not IKE_AUTH_response:
                    print("ERROR: Empty request received.")
                    # TIMER DE RETRANSMISION
                    exit()

                # Client prints the received IKE_AUTH response (Step 13.1.4):
                #print("\n\nIKE_AUTH response:")
                #IKE_AUTH_response.show()

                # Client gets the encrypted payload included in the IKE_AUTH response (Step 13.2.1):
                if IKEv2_Encrypted in IKE_AUTH_response:
                    encrypted_payload = IKE_AUTH_response[IKEv2_Encrypted].load

                # Client generates the initialization vector for the AES-GCM decryption (Step 13.2.2):
                iv = IKE_AUTH_response[IKEv2].id.to_bytes(4, 'big') + SK_er[28:]

                # Client tries to decrypt the encrypted payload (Step 13.2.3):
                try:
                    decrypted_data = AESGCM(SK_er).decrypt(iv, encrypted_payload, None)
                except Exception as e:
                    print(f"Decryption failed: {e}")

                # Client constructs the decrypted packet from the IKE_AUTH response (Step 13.3.1):
                decrypted_packet = IKEv2_IDi(decrypted_data)  

                # Client reconstructed every payload from the decrypted data (Step 13.3.2):
                idr_payload = decrypted_packet[IKEv2_IDi] if IKEv2_IDi in decrypted_packet else None
                cert_payload = decrypted_packet[IKEv2_CERT] if IKEv2_CERT in decrypted_packet else None
                auth_payload = decrypted_packet[IKEv2_AUTH] if IKEv2_AUTH in decrypted_packet else None
                sar2_payload = decrypted_packet[IKEv2_SA] if IKEv2_SA in decrypted_packet else None
                tsi_payload = decrypted_packet[IKEv2_TSi] if IKEv2_TSi in decrypted_packet else None
                tsr_payload = decrypted_packet[IKEv2_TSr] if IKEv2_TSr in decrypted_packet else None
                
                # Client obtains the ID from the server (Step 14.1):
                server_name = idr_payload.ID
                
                # Client obtains the public key and the signature from the server (Step 14.2.1):
                pk_server, signature_server = bytes(cert_payload.cert_data), auth_payload.load

                # Client checks the security level for the ML-DSA algorithm used by the server (Step 14.2.2):
                if (len(pk_server) == 1312):
                    ML_DSA_server, param_server = ML_DSA_levels["ML-DSA-44"]
                elif (len(pk_server) == 1952):
                    ML_DSA_server, param_server = ML_DSA_levels["ML-DSA-65"]
                elif (len(pk_server) == 2592):
                    ML_DSA_server, param_server = ML_DSA_levels["ML-DSA-87"]
                else:
                    print("Invalid signature.\n")
                    client_socket.close()
                    exit()

                # Client prints the server's security level for the ML-DSA algorithm (Step 14.2.3):
                if ("ML-DSA-"+param_server) not in ML_DSA_levels:
                    print("ERROR: Security levels for ML-DSA: ML-DSA-44, ML-DSA-65 or ML-DSA-87.")
                    client_socket.close()
                    exit()

                # Client searches in Vault for digital signature keys stored for this server (Step 14.2.4.1):
                try:
                    search = client.secrets.kv.v2.read_secret_version(
                        path = (SERVER_HOST + "/server/ML_DSA_"+param_server),
                        mount_point = "secret",
                        raise_on_deleted_version = True # Silence the warning
                    )

                    pk_server_stored = bytes.fromhex(list(search['data']['data'].values())[-1])
                    #print("Server's public key has been found in Vault.")

                # Client stores the server's public key to Vault if it has not been founded (Step 11.2.4.2):
                except hvac.exceptions.InvalidPath:
                    
                    #print("No server's public key stored in Vault has been found.")
                    pk_server_stored = pk_server

                    pk_Vault = {"pk": bytes(pk_server).hex()}
                    client.secrets.kv.v2.create_or_update_secret(
                        path = (SERVER_HOST + "/server/ML_DSA_"+param_server),
                        secret = pk_Vault,
                        mount_point = "secret"
                    )
                    #print(f"Server's public key stored in Vault.")

                # Client constructs the IKE_SA_INIT response to be signed (Step 14.3.1.1):
                RealMessage2 = bytes(IKE_SA_INIT_response)

                # Client constructs the responder's nonce to be signed (Step 14.3.1.2):
                NonceIData = Ni

                # Client constructs the MACedIDForI information to be signed (Step 14.3.1..3):
                RestOfRespIDPayload = (idr_payload.IDtype.to_bytes(1, "big") + b"\x00\x00\x00" + socket.inet_aton(idr_payload.ID))
                MACedIDForR = prf(SK_pr, RestOfRespIDPayload)

                # Client constructs the information to be signed for the signature (Step 14.3.1.4):
                responderSignedOctets = (RealMessage2 + NonceIData + MACedIDForR)

                # Client computes the hash of the initiatorSignedOctets (Step 14.3.2.1):
                hashedResponderSignedOctets = prf(SK_pr, responderSignedOctets)

                # Server verifies the client's signature of its public key (Step 14.3.2.2):
                if ML_DSA_server.verify(pk_server_stored, hashedResponderSignedOctets, signature_server) == False:
                    print("Invalid signature.\n")
                    client_socket.close()
                    exit()

                # Client extracts cryptographic material from the shared SK_d key (Step 15.1):
                KEYMAT = prf_plus(SK_d, salt, 32)
                #print(f"Shared secret: {KEYMAT.hex()}\n")

                session_elements = {
                    "SPIi": SPIi,
                    "SPIr": IKE_SA_INIT_response.resp_SPI,
                    "SK_d": SK_d,
                    "SK_ai": SK_ai,
                    "SK_ar": SK_ar,
                    "SK_ei": SK_ei,
                    "SK_er": SK_er,
                    "SK_pi": SK_pi,
                    "SK_pr": SK_pr
                }

                vault_path = f"{addr[0]}/PQC/client/IKEv2"

                for name, value in session_elements.items():
                    try:
                        client.secrets.kv.v2.create_or_update_secret(
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

            # Client aborts the transmission of information to the server (Step .):
            except hvac.exceptions.InvalidPath:
                print(f"Internet Key Exchange protocol failed.")
                client_socket.close()
                exit()

        # Client establishes a variable to save correctly the derived shared key (Step 15.2):
        id = str(uuid.uuid4())

        client_socket.sendto(id.encode(), (SERVER_HOST, PORT))
        
        result = {"Secret_key": str(KEYMAT.hex()), "ID": str(id)}
        print(json.dumps(result))
        #print(f"Secret key's identifier: {str(id)}\n")
        #print(f"Shared secret's value: {KEYMAT.hex()}\n")

        try:
            client.secrets.kv.v2.create_or_update_secret(
                path = f"{addr[0]}/PQC/keys/{id}",
                secret = {f"{id}": KEYMAT.hex()},
                mount_point = "secret"
            )

            #print("The shared secret has been stored in Vault.\n")

        except hvac.exceptions.InvalidPath:
            print("The shared secret has not been stored in Vault.\n")
            client_socket.close()
            exit(1)

        client_socket.close()

else:
    try:
        # Construir la ruta del secreto
        path = f"{SERVER_HOST}/PQC/keys/{ID}"

        secret_response = client.secrets.kv.v2.read_secret_version(
            path = path,
            mount_point = "secret",
            raise_on_deleted_version = True
        )
        
        # Extraer los datos del secreto
        secret_data = secret_response['data']['data']
        
        # Obtener el valor hexadecimal y convertirlo a bytes
        keymat_hex = secret_data[ID]
        keymat = bytes.fromhex(keymat_hex)

        if keymat:
            #print(f"Secret key: {keymat.hex()}")
            result = {"Secret_key": str(keymat.hex()), "ID": str({ID})}
            print(json.dumps(result))

    except hvac.exceptions.InvalidPath:
        print(f"Error: Secret has not been found on path {path}")
        exit()

    except Exception as e:
        print(f"ERROR: Secret could not be recovered from Vault {str(e)}")
        exit()