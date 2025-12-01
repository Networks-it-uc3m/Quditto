import asyncio
import aio_pika
import yaml
import sys
import time
import json
import logging

import hvac
from pathlib import Path
import requests

logging.basicConfig(
    filename=f'node_{sys.argv[1]}.log',         
    level=logging.INFO,                
    format='%(asctime)s - %(levelname)s - %(message)s'  
)

def store_key_data(client, node, key_ID, key):
    # Check if the node exists on the container
    #if node not in container:
        #container[node] = {'key_IDs': [], 'keys': [], 'ttls': []}
    
    # Add corresponding key, key_ID and ttl
    #container[node]['key_IDs'].append(key_ID)
    #container[node]['keys'].append(key)
    #container[node]['ttls'].append(time.perf_counter())

    key_material = {"key_ID": key_ID, "key": key}

    path = f"{node}/QKD/keys/{key_ID}"

    try:
        client.secrets.kv.v2.create_or_update_secret(
            path=path,
            secret={"keys": key_material},
            mount_point="secret"
        )

    except hvac.exceptions.InvalidPath:
        print("The key has not been stored in Vault.\n")
        exit()

    
def search_for_key(client, node, key_ID):

    node_path, node_exists = f"{node}/QKD/keys", False
    try:
        search = client.secrets.kv.v2.list_secrets(
            path=node_path,
            mount_point="secret"
        )
        node_exists = True
    except hvac.exceptions.InvalidPath:
        node_exists = False

    if node_exists:
        key_path = f"{node_path}/{key_ID}"
        
        try:
            search = client.secrets.kv.v2.read_secret_version(
                path=key_path,
                mount_point="secret",
                raise_on_deleted_version = True
            )

            key = search["data"]["data"]["keys"]["key"]
            return node_exists, key
        
        except hvac.exceptions.InvalidPath:
            print(f"Key ID '{key_ID}' not found in Vault.")
            return node_exists, None
    else:
        return node_exists, None

#container={}

# Client creates a function to read the root token from shared volunme (Step 1.2.1):
def read_token(TOKEN_PATH):
    if TOKEN_PATH.exists() and TOKEN_PATH.is_file():
        root_token = TOKEN_PATH.read_text().strip()
        if not root_token:
            print("ERROR: Empty root token.")
            return None
        
        print(f"[v] Root Token: {root_token}")
        return root_token
    else:
        return None

# Client creates a function to check Vault connectivity (Step 1.2.2):
def vault_running(vault_addr):
    try:
        r = requests.get(f"{vault_addr}/v1/sys/health", timeout=1.5)
        return r.status_code in [200, 429, 472, 473, 501, 503]
    except requests.RequestException:
        return False

# Client waits for Vault's server to be available (Step 1.3):
def wait_for_vault(max_retries, retry_count, vault_addr):
    print("Waiting for Vault server to be ready...\n")
    for attempt in range(1, max_retries + 1):
        if vault_running(vault_addr):
            print(f"[v] Vault session is responding (attempt {attempt})")
            return True
        print(f"Waiting for Vault... (attempt {attempt}/{max_retries})")
        time.sleep(retry_count)
    print("ERROR: No Vault connection")
    return False

def vault_authenticated (vault_host, VAULT_PORT, VOLUME):
    VAULT_ADDR, TOKEN_PATH = f"http://{vault_host}:{VAULT_PORT}", Path(f"/{VOLUME}/tokens/.vault_root_token")
    max_retries, retry_count = 30, 1

    if not wait_for_vault(max_retries, retry_count, VAULT_ADDR):
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
        
        print("[v] Successfully authenticated with Vault\n")
    except Exception as e:
        print(f"ERROR connecting to Vault: {e}")
        exit(1)

    return client

#async def verify_ttl():
    # Check all key's ttls
#    while True:
#        now = time.perf_counter()
#        for node, data in container.items():
#            if 'ttls' in data:
#                for i in reversed(range(len(data['ttls']))):
#                    if now - data['ttls'][i] >=600:
#                        # If the ttl is exceeded, delete all its data
#                        del data['ttls'][i]
#                        del data['keys'][i]
#                        del data['key_IDs'][i]
#        # Repeat check every 10 sec
#        await asyncio.sleep(10)

async def main():
    
    #asyncio.create_task(verify_ttl())
    # Save controller's IP
    with open("quditto_v2.yaml") as f:
        cfg = yaml.load(f, Loader=yaml.FullLoader)

    VOLUME, VAULT_PORT = sys.argv[2], sys.argv[3]

    node = sys.argv[1]
    if not node:
        sys.stderr.write("Indicate node")
        sys.exit(1)

    ip_controller = cfg['config']['ip_controller']

    for target_node in cfg.get("nodes", []):
        if target_node.get("node_name") == node:
            vault_host = target_node.get("vault_ip")
            break

    client = vault_authenticated(vault_host, VAULT_PORT, VOLUME)
    
    #print(f"IP: {ip_controller}")
    logging.info(f"Creating connection to controler with IP: {ip_controller}")

    # Create connection to the controller's machine
    connection = await aio_pika.connect_robust(f"amqp://node:node@{ip_controller}:5672/")
    async with connection:
        channel = await connection.channel()

        # Create binding with exchanger to receive messages of the corresponding node
        exchange = await channel.declare_exchange('direct_logs', aio_pika.ExchangeType.DIRECT)
        queue = await channel.declare_queue(
            '', 
            exclusive=True, 
            arguments={'x-message-ttl': 60000, 'x-expires': 1800000}
        )
        node = sys.argv[1]
        if not node:
            sys.stderr.write("Indicate node")
            sys.exit(1)
        
        await queue.bind(exchange, routing_key=node)

        #print(' [*] Waiting for logs. To exit press CTRL+C')
        logging.info("Node's setup completed")

        # Callback function to process messages received
        async def on_message(message: aio_pika.IncomingMessage):
            async with message.process():
                message_body = json.loads(message.body)
                #print(f" [x] {message.routing_key}:{message_body}")
                if not (any("node" in key for key in message_body)):
                    logging.info("Redirecting response from the controller to the KME")
                    # If the get_key was made from this node, return key and key_id
                    call_id = message_body["call_id"]
                    message_body.pop("call_id", None)
                    await exchange.publish(
                        aio_pika.Message(body=json.dumps(message_body).encode()),
                        routing_key=call_id,
                    )
                    #print(f"Message redirected to: {node}api")
                else:
                    logging.info("Storing cryptographic material received for future use")
                    # Else, store the key's data in the container
                    node_m = message_body["node"]
                    key_ID = message_body["key_ID"]
                    key = message_body["key"]

                    store_key_data(client, node_m,key_ID,key)

        # Listening to messages from the queue on an asynchronous consumer
        await queue.consume(on_message)

        # Create a new queue for messages with routing key "api+node"
        input_queue = await channel.declare_queue(
            '', 
            exclusive=True
        )
        await input_queue.bind(exchange, routing_key=f"api{node}")

        async def process_input_messages():
            async for message in input_queue:  # Asynchronously consume messages from the input queue
                async with message.process():
                    message_body = json.loads(message.body)
                    
                    if any("key_ID" in key for key in message_body):
                        logging.info("Get key with ID request recieved")
                        # If the message is with ID
                        n = message_body["node"]
                        key_ID = message_body["key_ID"]
                        call_id = message_body["call_id"]

                        node_exists, key = search_for_key(client, n, key_ID)

                        if node_exists == True:
                            if key:
                                message = {"key":str(key)}
                            else:
                                logging.warning("No key with specified key_ID")
                                message={"key":"No key with specified key_ID"}

                            await asyncio.sleep(1)
                            await exchange.publish(
                                aio_pika.Message(json.dumps(message).encode()),
                                routing_key=call_id,
                            )

                        #if n in container:
                            # Get the lists of key_IDs and keys
                            #print(container)
                            #print(key_ID)
                            #key_IDs = container[n]['key_IDs']
                            #keys = container[n]['keys']

                            # Verify if the key_ID is on the list
                            #if key_ID in key_IDs:
                            #    # Get the key_ID's position
                            #    index = key_IDs.index(key_ID)
                                
                                # Extract the corresponding key
                            #    key = keys[index]
                            #    message = {"key":str(key)}
                            #else:
                            #    logging.warning("No key with specified key_ID")
                            #    message={"key":"No key with specified key_ID"}

                            # Send the first line to the exchange
                            #await asyncio.sleep(1)
                            #await exchange.publish(
                            #    aio_pika.Message(json.dumps(message).encode()),
                            #    routing_key=call_id,
                            #)
                            #print(f"Key sent to: {node}api")

                        else:
                            #print("No key was generated with specified node")
                            logging.warning("No key was generated with specified node")
                            message={"key":"No key was generated with specified node"}
                            await asyncio.sleep(1)
                            await exchange.publish(
                                aio_pika.Message(json.dumps(message).encode()),
                                routing_key=call_id,
                            )
                    else:
                        # Redirect the received message
                        await exchange.publish(
                            aio_pika.Message(json.dumps(message_body).encode()),
                            routing_key="c",
                        )
                        logging.info("Get key request recieved")
                        #print(f"Message forwarded: {message_body}")

        # Start processing input messages in a separate coroutine
        await process_input_messages()

# Start main asyncio loop
asyncio.run(main())
