import yaml
import sys
import ansible_runner
import json
import time
import logging
import time

logger = logging.getLogger(__name__)

install_play = [
{
    "name": "Deployment of QKD network",
    "hosts": "all",
    "tasks":
        [
            {
                "name": "Installing python3-pip",
                "become": "true",
                "apt": "name=python3-pip state=present update_cache=true",
                "retries": "5",
                "delay": "30" 
            },
            {
                "name": "Installing QKD node",
                "become": "false", 
                "shell": "/usr/bin/pip install qdts_node==0.1.8"
            },
            {
                "name": "Creating qkd directory",
                "file":{
                    "path": "~/qkd_workspace/",
                    "state": "directory"
                }
            }
        ]
    
}

]

provisioning_play = [
{
    "name": "Provisioning",
    "hosts": "",
    "tasks":[
        {
            "name": "Copy file",
            "copy":{
                "dest": "~/qkd_workspace/config.json",
                "content": ""
            }
        }
    ]

},
]

start_play = [
    {
    "name": "Execution",
    "hosts": "all",
    "tasks":[
        {
            "name": "Start",
            "shell":{
                "chdir": "~/qkd_workspace/",
                "cmd": "{{py_env}}/python3 ~/.local/bin/qdts_node"
            },
        }
    ]

},    
]


# Auxiliary functions used by install()
def get_provisioning_play(content, host):
    play = provisioning_play
    play[0]["tasks"][0]["copy"]["content"] = content
    play[0]["hosts"] = host
    return play

def generate_qkde_config_file(node_name, nodes):
    node = nodes[node_name]
    config_file_values = {
        "node_name": node["node_name"],
        "node_ip": node["node_ip"],
        "node_id": node["node_id"],
        "neighbour_nodes": []
    }
    for n_node_name in node["neighbour_nodes"]:
        n_node = nodes[n_node_name]
        n_node_config = {
            "node_name": n_node["node_name"],
            "node_ip": n_node["node_ip"],
            "node_id": n_node["node_id"],
        }
        config_file_values["neighbour_nodes"].append(n_node_config)
    return json.dumps(config_file_values)


# Main functions of this library: install and run:
# This functions installs and configures everything in a node to become a QKD node based on simulaqron
def install(config_file, inv_file):
    # Added a small delay to ensure that the virtual node is up
    import time
    print('Sleeping to avoid errors in the Ansible ssh connection....')
    time.sleep(30)
    
    # Added to measure the installation time        
    start_time = time.time()
    
    config = None
    inv = None

    nodes_array = config_file["nodes"]

    nodes = {}

    for i, node in enumerate(nodes_array):
        node_name = node["node_name"]
        nodes[node_name] = node
        nodes[node_name]["node_id"] = i +1

    ansible_runner.run(playbook = install_play, inventory = inv_file)

    
    for node_name in nodes:
        prov = generate_qkde_config_file(node_name, nodes)
        p = get_provisioning_play(prov, node_name)
        ansible_runner.run(playbook = p, inventory=inv_file)
        
    # Added to measure the installation time 
    end_time = time.time()
    total_time = end_time-start_time
    # print('\n Installation time: {}s'.format(total_time))
    logger.info(f'Installation time from qdts_orchestrator: {total_time}')


# This functions starts simulaqron in every node in the inventory file
def run(inv_file):
    start_time = time.time()
    ansible_runner.run(playbook = start_play, inventory=inv_file)
    end_time = time.time()
    total_time = end_time-start_time
    logger.info(f'Time for executing all the qdts_nodes: {total_time}')