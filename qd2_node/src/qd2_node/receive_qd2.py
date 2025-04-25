import asyncio
import aio_pika
import yaml
import sys
import time
import json
import logging

logging.basicConfig(
    filename=f'node_{sys.argv[1]}.log',         
    level=logging.INFO,                
    format='%(asctime)s - %(levelname)s - %(message)s'  
)


def store_key_data(node, key_ID, key, container):
    # Check if the node exists on the container
    if node not in container:
        container[node] = {'key_IDs': [], 'keys': [], 'ttls': []}
    
    # Add corresponding key, key_ID and ttl
    container[node]['key_IDs'].append(key_ID)
    container[node]['keys'].append(key)
    container[node]['ttls'].append(time.perf_counter())

container={}

async def verify_ttl():
    # Check all key's ttls
    while True:
        now = time.perf_counter()
        for node, data in container.items():
            if 'ttls' in data:
                for i in reversed(range(len(data['ttls']))):
                    if now - data['ttls'][i] >=600:
                        # If the ttl is exceeded, delete all its data
                        del data['ttls'][i]
                        del data['keys'][i]
                        del data['key_IDs'][i]
        # Repeat check every 10 sec
        await asyncio.sleep(10)

async def main():
    
    asyncio.create_task(verify_ttl())
    # Save controller's IP
    with open("quditto_v2.yaml") as f:
        cfg = yaml.load(f, Loader=yaml.FullLoader)

    ip_controller = cfg['config']['ip_controller']
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

                    store_key_data(node_m,key_ID,key,container)

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
                        if n in container:
                            # Get the lists of key_IDs and keys
                            #print(container)
                            #print(key_ID)
                            key_IDs = container[n]['key_IDs']
                            keys = container[n]['keys']

                            # Verify if the key_ID is on the list
                            if key_ID in key_IDs:
                                # Get the key_ID's position
                                index = key_IDs.index(key_ID)
                                
                                # Extract the corresponding key
                                key = keys[index]
                                message = {"key":str(key)}
                            else:
                                logging.warning("No key with specified key_ID")
                                message={"key":"No key with specified key_ID"}

                            # Send the first line to the exchange
                            await asyncio.sleep(1)
                            await exchange.publish(
                                aio_pika.Message(json.dumps(message).encode()),
                                routing_key=call_id,
                            )
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
