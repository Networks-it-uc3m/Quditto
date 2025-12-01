from fastapi import FastAPI
from pydantic import BaseModel
from contextlib import asynccontextmanager
import os
import functions
import sys

if len(sys.argv) == 4:
    node = sys.argv[3]
    node = str(node)

@asynccontextmanager
async def lifespan(app: FastAPI):
    host = os.getenv("HOST", "Not defined")
    port = os.getenv("PORT", "Not defined")
    print(f"Server was launched on {host}:{port}")
    yield
    print("Server shutting down...")

app = FastAPI(lifespan=lifespan)


class Mensaje(BaseModel):
    texto: str

@app.get("/api/v1/keys/QKD/{slave_SAE_ID}/enc_keys")
def get_key_QKD(slave_SAE_ID: str, size: str):

    result = str(functions.get_key_QKD(node,slave_SAE_ID,size))
    
    return {result}

@app.get("/api/v1/keys/PQC/{slave_IP}/enc_keys")
def get_key_PQC(slave_IP: str):

    result = str(functions.get_key_PQC(slave_IP))
    
    return {result}


@app.get("/api/v1/keys/QKD/{master_SAE_ID}/dec_keys")
def get_key_with_ID_QKD(master_SAE_ID: str, key_ID: str):

    result = str(functions.get_key_with_ID_QKD(node,master_SAE_ID,key_ID))
    
    return {result}

@app.get("/api/v1/keys/PQC/{master_IP}/dec_keys")
def get_key_with_ID_PQC(master_IP: str, key_ID: str):

    result = str(functions.get_key_with_ID_PQC(master_IP,key_ID))
    
    return {result}

if __name__ == "__main__":
    import uvicorn
    if len(sys.argv) == 4:
        host = sys.argv[1]
        port = sys.argv[2]
    else:
        sys.exit(1)

    host = str(host)
    port = int(port) 
    os.environ["HOST"] = host
    os.environ["PORT"] = str(port) 
    uvicorn.run(app, host=host, port=port)
