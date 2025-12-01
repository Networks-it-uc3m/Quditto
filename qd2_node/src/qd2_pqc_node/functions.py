import yaml
import pika
import json
import secrets
import subprocess


def get_key_QKD(origin=None, node=None, key=None):
        
    call_id = secrets.token_hex(16)
    
    if origin is None or node is None or key is None:
        text = 'Parameters not specified'
        return text
    
    with open("quditto_v2.yaml") as f:
        cfg = yaml.load(f, Loader=yaml.FullLoader)

    ip_controller = cfg['config']['ip_controller']

    # Create connection to the controller's machine
    credentials = pika.PlainCredentials("node", "node")
    parameters = pika.ConnectionParameters(host=ip_controller, port=5672, credentials=credentials)
    connection = pika.BlockingConnection(parameters)
    channel = connection.channel()

    channel.exchange_declare(exchange='direct_logs', exchange_type='direct')

    result = channel.queue_declare(queue='', exclusive=True, arguments={'x-message-ttl': 60000, 'x-expires': 1800000})

    message = {"origin":str(origin), "node": str(node), "key": str(key), "call_id": call_id}
    json_m = json.dumps(message)


    channel.basic_publish(exchange='direct_logs', routing_key="api"+origin, body=json_m)

    queue_name = result.method.queue
    channel.queue_bind(exchange='direct_logs', queue=queue_name, routing_key=call_id)

    # Wait for a message from the queue with key "A"
    def on_message(ch, method, properties, body):
        nonlocal text
        response = json.loads(body)
        text["keys"] = [response]
        ch.basic_ack(delivery_tag=method.delivery_tag)
        connection.close()  # Close connection once message is received

    text = {}
    channel.basic_consume(queue=queue_name, on_message_callback=on_message, auto_ack=False)

    print("Waiting for response...")
    channel.start_consuming()

    return text



def get_key_with_ID_QKD(origin=None, node=None, key_ID=None):

    call_id = secrets.token_hex(16)
    
    if origin is None or node is None or key_ID is None:
        text = 'Parameters not specified'
        return text

    with open("quditto_v2.yaml") as f:
        cfg = yaml.load(f, Loader=yaml.FullLoader)

    ip_controller = cfg['config']['ip_controller']

    # Create connection to the controller's machine
    credentials = pika.PlainCredentials("node", "node")
    parameters = pika.ConnectionParameters(host=ip_controller, port=5672, credentials=credentials)
    connection = pika.BlockingConnection(parameters)
    channel = connection.channel()

    channel.exchange_declare(exchange='direct_logs', exchange_type='direct')

    result = channel.queue_declare(queue='', exclusive=True, arguments={'x-message-ttl': 60000, 'x-expires': 1800000})

    message = {"origin":str(origin), "node": str(node), "key_ID": str(key_ID), "call_id": call_id}
    json_m = json.dumps(message)


    channel.basic_publish(exchange='direct_logs', routing_key="api"+origin, body=json_m)

    queue_name = result.method.queue
    channel.queue_bind(exchange='direct_logs', queue=queue_name, routing_key=call_id)

    def on_message(ch, method, properties, body):
        nonlocal text
        text = json.loads(body)
        ch.basic_ack(delivery_tag=method.delivery_tag)
        connection.close()  # Close connection once message is received

    text = {}
    channel.basic_consume(queue=queue_name, on_message_callback=on_message, auto_ack=False)

    print("Waiting for response...")
    channel.start_consuming()

    return text


def get_key_PQC(node_ip=None):

    # Parameter validation
    if node_ip is None:
        return {"error": "Server's IP not specified"}

    command = ['python3', 'client.py', '-ip', str(node_ip)]

    result = subprocess.run(command, capture_output=True, text=True)

    # Check if there was an error during script execution
    if result.returncode != 0:
        return {"error": "client.py execution failed", "stderr": result.stderr}

    try:
        output = json.loads(result.stdout)

        key = output["Secret_key"]
        key_ID = output["ID"]

        return {
            "keys": [
                {
                    "key_ID": key_ID,
                    "key": key
                }
            ]
        }

    except (json.JSONDecodeError, KeyError) as e:
        return {
            "error": f"Error processing the results: {e}",
            "stdout": result.stdout
        }


def get_key_with_ID_PQC(node_ip, key_ID):

    # Parameter validation
    if node_ip is None:
        return {"error": "Server's IP not specified"}

    command = ['python3', 'client.py', '-ip', str(node_ip), '-id', str(key_ID)]

    # Execute the command
    result = subprocess.run(command, capture_output=True, text=True)

    # Check if there was an error during script execution
    if result.returncode != 0:
        return {
            "error": "client.py execution failed",
            "stderr": result.stderr
        }

    try:
        output = json.loads(result.stdout)

        key = output["Secret_key"]
        key_ID = output["ID"]

        return {
            "keys": [
                {
                    "key_ID": key_ID,
                    "key": key
                }
            ]
        }

    except (json.JSONDecodeError, KeyError) as e:
        return {
            "error": f"Error processing results: {e}",
            "stdout": result.stdout
        }
