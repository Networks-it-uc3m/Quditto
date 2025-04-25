import threading
import time
import subprocess
import json
import pika
import yaml
import uuid
import base64
import logging

logging.basicConfig(
    filename='controller.log',         
    level=logging.INFO,                
    format='%(asctime)s - %(levelname)s - %(message)s'  
)

with open("quditto_v2.yaml") as f:
    cfg = yaml.load(f, Loader=yaml.FullLoader)

#Indicate the number of network links to initiate the locks

def bits_to_base64(bits_str):
    # Turn the bits string to bytes
    bits_as_bytes = int(bits_str, 2).to_bytes((len(bits_str) + 7) // 8, byteorder='big')
    
    # Code the bytes to base64
    base64_encoded = base64.b64encode(bits_as_bytes)
    
    # Turn the result into a string
    return base64_encoded.decode('utf-8')

def count_all_connections(data):
    connections = []
    
    for node in data.get('nodes', []):
        node_name = node['node_name']
        for neighbour in node.get('neighbour_nodes', []):
            neighbour_name = neighbour['name']
            connection = f"{node_name}{neighbour_name}"
            connections.append(connection)
    return connections

unique_connections = count_all_connections(cfg)

num_groups = len(unique_connections)
groups_locks = {i: threading.Lock() for i in range(num_groups)}

def emul_BB84(group_id, group_lock, key, d, origin, n, call_id, e_d, percentage):
    #print(f"Preparing link {group_id}...")
    logging.info(f"Preparing link {group_id} for simulation")
    #print(f"{e_d},{percentage}")

    #script_name = "BB84_hilo.py"
    script_name = "bb84_with_eve.py"

    #print(f"Running BB84 on link: {group_id} with parameters: {key} {d}")


    #command = ['python3', script_name, str(group_id), key, d]
    command = ['python3', str(script_name), str(key), str(d), str(e_d), str(percentage)]

    #Entering the corresponding link's lock
    with group_lock:
        #print(f"Running protocol on link {group_id}...")
        logging.info(f"Running BB84 on link: {group_id} with parameters: key length={key}, link length={d}")

        #Taking initial time
        start = time.perf_counter()

        #Running the BB84 simulation script with the given parameters
        result = subprocess.run(command, capture_output=True, text=True)
        #print(f"Content of result.stdout: {result.stdout!r}")
        #Retrieving the simulation results
        try:
            output = json.loads(result.stdout)
            Alice_key = output["alice_key"]
            Bob_key = output["bob_key"]
            output_time = output["time"]
            #print(Alice_key == Bob_key)
            logging.info(f"Alice and Bob generated the same key: {Alice_key == Bob_key}")
        except (json.JSONDecodeError, KeyError) as e:
            #print(f"Link {group_id}: Error processing the results: {e}")
            logging.error(f"Link {group_id}: Error processing the results: {e}")
            return
        
        Alice_key = str(Alice_key).replace("[", "").replace("]", "").replace(", ", "")
        Bob_key = str(Bob_key).replace("[", "").replace("]", "").replace(", ", "")

        counter = 1

        while(int(key) > int(len(Alice_key))):
            logging.info("The key returned was too short. Preparing new simulation")
            temp_A = Alice_key
            temp_B = Bob_key
            temp_T = output_time
            counter = counter +1
            key_left = int(key) - int(len(temp_A))
            command = ['python3', script_name, str(group_id), str(key_left), d]
            result = subprocess.run(command, capture_output=True, text=True)
            #print(f"Call number {counter} content: {result.stdout!r}")
            logging.info(f"Simulation try number {counter}")
            try:
                output = json.loads(result.stdout)
                Alice_key = output["alice_key"]
                Bob_key = output["bob_key"]
                output_time = output["time"]
                #print(Alice_key == Bob_key)
                logging.info(f"Alice and Bob generated the same key: {Alice_key == Bob_key}")
            except (json.JSONDecodeError, KeyError) as e:
                #print(f"Link {group_id}: Error processing the results: {e}")
                logging.error(f"Link {group_id}: Error processing the results: {e}")
                return

            Alice_key = str(Alice_key).replace("[", "").replace("]", "").replace(", ", "")
            Bob_key = str(Bob_key).replace("[", "").replace("]", "").replace(", ", "")

            Alice_key = temp_A + Alice_key
            Bob_key = temp_B + Bob_key
            output_time = temp_T + output_time

        #Blocking the sending of results until the specified time has passed
        current_time = time.perf_counter()

        while current_time < start + output_time:
            current_time = time.perf_counter()
        
        real_time = current_time-start

        #print(f"Link {group_id}: Key generated for Alice{Alice_key} \n key generated for Bob{Bob_key}\n delay: {output_time:.4f} sec")
        #print(f"Actual time elapsed until key distribution: {real_time:.4f} sec")

        #Sending results to both linked machines
        connection = pika.BlockingConnection(
        pika.ConnectionParameters(host='localhost'))
        channel = connection.channel()
        channel.exchange_declare(exchange='direct_logs', exchange_type='direct')
        key_id = str(uuid.uuid4())

        Alice_key = str(Alice_key).replace("[", "").replace("]", "").replace(", ", "")
        Alice_key = bits_to_base64(Alice_key)
        message_A = {"key_ID":key_id, "key": Alice_key, "call_id": call_id}
        json_A = json.dumps(message_A)

        Bob_key = str(Bob_key).replace("[", "").replace("]", "").replace(", ", "")
        Bob_key = bits_to_base64(Bob_key)
        message_B = {"node":origin, "key_ID":key_id, "key": Bob_key}
        json_B = json.dumps(message_B)

        channel.basic_publish(
            exchange='direct_logs', routing_key=str(origin), body=json_A)
        channel.basic_publish(
            exchange='direct_logs', routing_key=str(n), body=json_B)
        connection.close()
        logging.info(f"Link {group_id}: Key generated for Alice: {Alice_key}, key generated for Bob: {Bob_key}, delay: {output_time:.4f} sec")
        logging.info(f"Actual time elapsed until key distribution: {real_time:.4f} sec")

# Search index of a specific link
def find_link_position(links, target_name):
    for index, item in enumerate(links):
        if item.get("link_name") == target_name:
            return index  # return link's position if found
    return -1 

#Request receiver funciton
def callback(ch, method, properties, body):
    
    #print(f" [x] {method.routing_key}:{body}")
    logging.info(f"New request: {method.routing_key}:{body}")

    body = json.loads(body)

    origin = body["origin"]
    n = body["node"]
    position = None
    reverse = 0

    for idx, connection in enumerate(unique_connections):
        if connection == origin + n:  # Locate the connection's position on the list
            position = idx
            break
        elif connection == n + origin:
            position = idx
            reverse = 1
            break
        else:
            position = -1


    group_id = position

    key = body["key"]
    call_id = body["call_id"]
    
    if reverse == 1:
        x = origin
        y = n
        origin = y
        n = x

    #If the link requested is valid, begin simulation on a thread
    if 0 <= int(group_id) < num_groups:
        nodes = cfg["nodes"]
        d = None
        for node in nodes:
            if node["node_name"] == origin:
                for neighbour in node["neighbour_nodes"]:
                    if neighbour.get("name") == n and "link_length" in neighbour:
                        d = neighbour["link_length"]
                        if neighbour.get("eavesdropper") == True:
                            e_d = neighbour["eavesdropper_parameters"]["eavesdropper_distance"]
                            percentage = neighbour["eavesdropper_parameters"]["percentage_intercepted_qubits"]
                        else:
                            e_d = 0
                            percentage = 0
                        break

        if reverse == 1:
            x = origin
            y = n
            origin = y
            n = x

        d=str(d)
        hilo = threading.Thread(target=emul_BB84, args=(group_id, groups_locks[group_id], key, d, origin, n, call_id, e_d, percentage))
        hilo.start()

    else:
        #print(f"Select a valid link...")
        logging.warning("Invalid link requested")
        connection = pika.BlockingConnection(
        pika.ConnectionParameters(host='localhost'))
        channel = connection.channel()
        channel.exchange_declare(exchange='direct_logs', exchange_type='direct')
        key_id = str(uuid.uuid4())
        message_A = {"call_id": call_id, "message": "Invalid partner requested.", "details": "The nodes are not neighbours"}
        json_A = json.dumps(message_A)
        channel.basic_publish(
            exchange='direct_logs', routing_key=str(origin), body=json_A)
        connection.close()


    time.sleep(1)
    

def launch_thread():
    #Establish connection with localhost
    connection = pika.BlockingConnection(
        pika.ConnectionParameters(host='localhost'))
    channel = connection.channel()
    #create message exchanger
    channel.exchange_declare(exchange='direct_logs', exchange_type='direct')

    #Create the simulation request queue
    result = channel.queue_declare(queue='', exclusive=True, arguments={'x-message-ttl': 60000,'x-expires': 1800000})
    queue_name = result.method.queue
    channel.queue_bind(exchange='direct_logs', queue=queue_name, routing_key="c")
    #Begin taking requests
    channel.basic_consume(queue=queue_name, on_message_callback=callback, auto_ack=True)
    channel.start_consuming()

if __name__ == "__main__":

    launch_thread()