# Standard libraries for implementation (Step 0):
import argparse, os, re, requests, subprocess, time, shutil
from pathlib import Path

# ------------------------------------ Configuration -------------------------------------------------- #

parser = argparse.ArgumentParser(description="Vault server")
parser.add_argument("-v", required=True, help="Volume's name")
parser.add_argument("-p", required=True, help="Vault server's port")
args = parser.parse_args()

# Creation of constants for the initialization of Vault (Step 1.1):
VOLUME, VAULT_HOST, VAULT_PORT = args.v, "0.0.0.0", args.p
VAULT_ADDR = f"http://{VAULT_HOST}:{VAULT_PORT}"

# Definition of the token storage path for the shared volume (Step 1.2):
TOKEN_PATH = Path(f"{Path.home()}/{VOLUME}/tokens/.vault_root_token")

# ------------------------------------ Vault Functions ------------------------------------------------ #

# Function to read the root token from the shared volume (Step 2.1):
def read_token(token_path):
    if token_path.exists() and token_path.is_file():
        return token_path.read_text().strip()
    else:
        return None
    
# Function to save the root token in the volume with secure permissions (Step 2.2):
def save_token(token: str, token_path):
    if not token:
        raise ValueError("ERROR: Root token is None.")
    
    if token_path.exists():
        if token_path.is_dir():
            shutil.rmtree(token_path)
        else:
            token_path.unlink()
    
    token_path.write_text(token)
    token_path.chmod(0o600)
    #print(f"[✓] Root token saved to {token_path} (permissions 600)")
    return token_path

# Function to check if Vault server is responding (Step 2.3):
def vault_running():
    try:
        r = requests.get(f"{VAULT_ADDR}/v1/sys/health", timeout=1.5)
        return r.status_code in [200, 429, 472, 473, 501, 503]
    except requests.RequestException:
        return False

# Function to validate the root token against Vault (Step 2.4):
def token_valid(token: str):
    try:
        r = requests.get(
            f"{VAULT_ADDR}/v1/auth/token/lookup-self",
            headers={"X-Vault-Token": token},
            timeout=1.5
        )
        return r.status_code == 200
    except requests.RequestException:
        return False

# Function to start a Vault server and capture its root token (Step 2.5):
def start_dev_server():
    vault_home_path = Path.home() / ".vault"
    if vault_home_path.exists():
        if vault_home_path.is_dir():
            shutil.rmtree(vault_home_path)
        else:
            vault_home_path.unlink()
    
    #print(f"Starting Vault dev server on {VAULT_HOST}:{VAULT_PORT}...")
    
    cmd = ["vault", "server", "-dev",
        f"-dev-listen-address={VAULT_HOST}:{VAULT_PORT}"]
    
    env = os.environ.copy()
    
    p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        text=True, bufsize=1, env=env)
    
    start, timeout, token, vault_ready = time.time(), 30, None, False
    
    #print("Waiting for Vault to initialize...")
    
    while True:
        line = p.stdout.readline()
        if line:
            print(line.rstrip())
            
            m = re.search(r"Root Token:\s+(\S+)", line)
            if m:
                token = m.group(1)
                print(f"\n[v] Root token captured: {token}")
            
            
            if "core: post-unseal setup complete" in line or "vault is unsealed" in line:
                vault_ready = True
                #print("[✓] Vault is unsealed and ready")
        
        if p.poll() is not None:
            print("ERROR: Vault process terminated unexpectedly")
            break
        
        if vault_ready and token:
            #print("[✓] Vault initialization complete")
            break
        
        if time.time() - start > timeout:
            print("ERROR: Timeout waiting for Vault to start")
            break
    
    time.sleep(1)
    return p, token

# Function to verify if Vault server is responding (Step 2.6):
def verify_vault_connectivity(max_retries=15):
    #print("\nVerifying Vault connectivity...")
    retry_count = 0
    
    while retry_count < max_retries:
        if vault_running():
            #print(f"[✓] Vault is responding (attempt {retry_count + 1})")
            time.sleep(1)
            return True
        #print(f"Waiting for Vault... (attempt {retry_count + 1}/{max_retries})")
        time.sleep(2)
        retry_count += 1
    
    return False

# ------------------------------------ Main Execution ------------------------------------------------- #

# Main function to manage Vault server lifecycle (Step 3):
def main():
    #print("=" * 80)
    #print("Vault Server for IKEv2 Key Storage")
    #print("=" * 80)
    
    # Ensures that the root token's directory exists (Step 3.1):
    TOKEN_PATH.parent.mkdir(parents=True, exist_ok=True)
    #print(f"Token path configured: {TOKEN_PATH}\n")
    
    # Cleans the previous Vault configurations (Step 3.2):
    #print("Cleaning previous Vault configurations...")
    vault_paths = [
        Path.home() / ".vault",
        Path.home() / ".vault-token",
        TOKEN_PATH
    ]
    
    for path in vault_paths:
        if path.exists():
            if path.is_dir():
                shutil.rmtree(path)
                #print(f"Removed directory: {path}")
            else:
                path.unlink()
                #print(f"Removed file: {path}")
    
    # Checks if Vault is already running (Step 3.3):
    if vault_running():
        #print(f"Vault detected running at {VAULT_ADDR}")
        
        root_token = read_token(TOKEN_PATH)
        
        if not root_token and not token_valid(root_token):
            #print("[✓] Existing token is valid")
            #print(f"[✓] Vault is operational at {VAULT_ADDR}")
            #print(f"    Root Token: {root_token}")
        #else:
            #print("[⚠] Existing Vault found but token is invalid")
            #print("    Starting new instance...")
            
            proc, root_token = start_dev_server()
            if not root_token:
                root_token = "root"
            
            save_token(root_token, TOKEN_PATH)
    else:
        #print(f"No Vault server found at {VAULT_ADDR}")
        #print("Initializing new Vault server...\n")
        
        proc, root_token = start_dev_server()
        
        if not root_token:
            root_token = "root"
            #print("⚠ Using default root token: 'root'")
        
        save_token(root_token, TOKEN_PATH)
        
        if not verify_vault_connectivity():
            print("ERROR: Vault failed to start within timeout period")
            return 1
    
    #print("\n" + "=" * 80)
    #print("[✓] Vault is fully operational!")
    #print(f"    Address: {VAULT_ADDR}")
    #print(f"    Token file: {TOKEN_PATH}")
    #print("=" * 80)
    
    # Keep container running and monitoring Vault
    #print("\nMonitoring Vault health (Ctrl+C to stop)...")
    
    try:
        while True:
            time.sleep(30)
            if vault_running():
                print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] Vault health check: OK")
            else:
                print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] Vault health check: FAILED")
                print("Attempting to restart Vault...")
                proc, root_token = start_dev_server()
                if root_token:
                    save_token(root_token, TOKEN_PATH)
                    
    except KeyboardInterrupt:
        print("\nShutting down Vault server...")
        return 0

if __name__ == "__main__":
    exit(main())