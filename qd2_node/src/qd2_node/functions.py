import yaml
import pika
import json
import secrets

def get_key(origin=None, node=None, key=None):
        
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
        text = json.loads(body)
        ch.basic_ack(delivery_tag=method.delivery_tag)
        connection.close()  # Close connection once message is received

    text = {}
    channel.basic_consume(queue=queue_name, on_message_callback=on_message, auto_ack=False)

    print("Waiting for response...")
    channel.start_consuming()

    return text

def get_key_with_ID(origin=None, node=None, key_ID=None):

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



def _raw_request(origin, message):
    with open("quditto_v2.yaml") as f:
        cfg = yaml.load(f, Loader=yaml.FullLoader)
    ip_controller = cfg['config']['ip_controller']

    credentials = pika.PlainCredentials("node", "node")
    parameters = pika.ConnectionParameters(host=ip_controller, port=5672, credentials=credentials)
    connection = pika.BlockingConnection(parameters)
    channel = connection.channel()
    channel.exchange_declare(exchange='direct_logs', exchange_type='direct')

    result = channel.queue_declare(queue='', exclusive=True, arguments={'x-message-ttl': 60000, 'x-expires': 1800000})
    queue_name = result.method.queue
    # Bind the reply queue BEFORE publishing so the answer cannot be missed
    channel.queue_bind(exchange='direct_logs', queue=queue_name, routing_key=message["call_id"])
    channel.basic_publish(exchange='direct_logs', routing_key="api" + origin, body=json.dumps(message))

    response = {}
    def on_message(ch, method, properties, body):
        nonlocal response
        response = json.loads(body)
        ch.basic_ack(delivery_tag=method.delivery_tag)
        ch.stop_consuming()

    channel.basic_consume(queue=queue_name, on_message_callback=on_message, auto_ack=False)
    channel.start_consuming()
    connection.close()
    return response

def get_raw(origin=None, node=None, size=None):
    if origin is None or node is None or size is None:
        return {"error": "Parameters not specified"}
    message = {"service": "raw", "origin": str(origin), "node": str(node),
               "key": str(size), "call_id": secrets.token_hex(16)}
    return _raw_request(str(origin), message)

def get_raw_with_ID(origin=None, node=None, measurement_ID=None):
    if origin is None or node is None or measurement_ID is None:
        return {"error": "Parameters not specified"}
    message = {"service": "raw", "origin": str(origin), "node": str(node),
               "measurement_ID": str(measurement_ID), "call_id": secrets.token_hex(16)}
    return _raw_request(str(origin), message)

    return text