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

logging.getLogger('pika').setLevel(logging.WARNING)


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

def emul_BB84(group_id, group_lock, key, d, protocol, origin, n, call_id, params):
    #print(f"Preparing link {group_id}...")
    logging.info(f"Preparing link {group_id} for simulation")


    #print(f"Running BB84 on link: {group_id} with parameters: {key} {d}")

    command = ['python3', str(protocol), str(key), str(d), str(params)]

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
            #command = ['python3', script_name, str(group_id), str(key_left), d]
            #command = ['python3', str(script_name), str(key_left), str(d), str(e_d), str(percentage)]
            command = ['python3', str(protocol), str(key_left), str(d), str(params)]
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

        if int(key) < int(len(Alice_key)):
            #Implement buffer here
            Alice_key = Alice_key[:int(key)]
            Bob_key = Bob_key[:int(key)]

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

def _to_bitstring(x):
    if isinstance(x, (list, tuple)):
        return "".join(str(int(b)) for b in x)
    return str(x)

def _publish(messages):
    connection = pika.BlockingConnection(pika.ConnectionParameters(host='localhost'))
    channel = connection.channel()
    channel.exchange_declare(exchange='direct_logs', exchange_type='direct')
    for routing_key, msg in messages:
        channel.basic_publish(exchange='direct_logs', routing_key=str(routing_key), body=json.dumps(msg))
    connection.close()

def emul_raw(group_id, group_lock, size, d, protocol, origin, n, call_id, params):
    logging.info(f"Preparing link {group_id} for raw measurement simulation")
    size = int(size)

    with group_lock:
        start = time.perf_counter()
        a_bits = a_bases = b_bits = b_bases = ""
        total_time = 0.0

        while len(a_bits) < size:
            command = ['python3', str(protocol), str(size - len(a_bits)), str(d), str(params)]
            result = subprocess.run(command, capture_output=True, text=True)
            try:
                out = json.loads(result.stdout)
                new_a_bits = _to_bitstring(out["alice_bits"])
                new_a_bases = _to_bitstring(out["alice_bases"])
                new_b_bits = _to_bitstring(out["bob_bits"])
                new_b_bases = _to_bitstring(out["bob_bases"])
                t = float(out["time"])
            except (json.JSONDecodeError, KeyError, ValueError, TypeError) as e:
                logging.error(f"Link {group_id}: Error processing raw results: {e} | stderr: {result.stderr}")
                _publish([(origin, {"service": "raw", "call_id": call_id,
                                    "error": "Raw measurement simulation failed"})])
                return

            if len(new_a_bits) == 0:
                logging.error(f"Link {group_id}: raw script returned no rounds")
                _publish([(origin, {"service": "raw", "call_id": call_id,
                                    "error": "Raw measurement script returned no rounds"})])
                return

            a_bits += new_a_bits
            a_bases += new_a_bases
            b_bits += new_b_bits
            b_bases += new_b_bases
            total_time += t

        a_bits, a_bases = a_bits[:size], a_bases[:size]
        b_bits, b_bases = b_bits[:size], b_bases[:size]

        # Wait until the simulated time has elapsed
        remaining = (start + total_time) - time.perf_counter()
        if remaining > 0:
            time.sleep(remaining)

        measurement_id = str(uuid.uuid4())

        # Requester (Alice / sender): no "node" field -> receive_qd2 forwards it to call_id
        message_A = {"service": "raw", "measurement_ID": measurement_id, "role": "sender",
                     "peer": n, "bits": a_bits, "bases": a_bases, "call_id": call_id}
        # Peer (Bob / receiver): has "node" field -> receive_qd2 stores it
        message_B = {"service": "raw", "node": origin, "measurement_ID": measurement_id,
                     "data": {"role": "receiver", "peer": origin, "bits": b_bits, "bases": b_bases}}

        _publish([(origin, message_A), (n, message_B)])
        logging.info(f"Link {group_id}: raw measurements delivered, ID {measurement_id}, "
                     f"{size} rounds, simulated time {total_time:.4f} s")
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
    params = f"params_{origin}_{n}.yaml"

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
    service = body.get("service", "key")
    
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
                        protocol = neighbour["protocol"]
                        if service == "raw":
                            protocol = neighbour.get("raw_protocol", "raw_dummy.py")
                        filtered_params = {}
                        ch_params_list = neighbour.get("chanel_parameters", [])
                        if ch_params_list:
                            # ch_params_list must be a list with just one dict
                            ch_params_dict = ch_params_list[0] if isinstance(ch_params_list[0], dict) else {}

                            # Filter params with value other than None
                            filtered_params = {
                                k: v for k, v in ch_params_dict.items() if v is not None
                            }

                        if neighbour["eavesdropper"] == True:
                            filtered_params["eavesdropper_distance"] = neighbour["eavesdropper_parameters"]["eavesdropper_distance"]
                            filtered_params["percentage_intercepted_qubits"] = neighbour["eavesdropper_parameters"]["percentage_intercepted_qubits"]

                        # Save the parameters in the yaml param file
                        with open(params, "w") as file:
                            yaml.dump(filtered_params, file, default_flow_style=False)
                        break

        if reverse == 1:
            x = origin
            y = n
            origin = y
            n = x

        d=str(d)
        target = emul_raw if service == "raw" else emul_BB84
        hilo = threading.Thread(target=target, args=(group_id, groups_locks[group_id], key, d, protocol, origin, n, call_id, params))
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