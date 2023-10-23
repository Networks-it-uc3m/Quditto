import yaml
import sys
import ansible_runner
import json
import time

install_play = [
{
    "name": "Deployment of QKD network",
    "hosts": "all",
    "tasks":
        [
            {
                "name": "Installing QKD node",
                "shell": "{{py_env}}/bin/pip install qdts_node==0.1.8"
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

def get_provisioning_play(content, host):
    play = provisioning_play
    play[0]["tasks"][0]["copy"]["content"] = content
    play[0]["hosts"] = host
    return play

def install():
    start_time = time.time()
    if len(sys.argv) != 3:
        print("Please provide a config file and a provisioning file")
        exit()
    config_file_path = sys.argv[1]
    inventory_file_path = sys.argv[2]
    config = None
    inv = None
    with open(config_file_path) as config_file:
        config = yaml.safe_load(config_file)
    with open( inventory_file_path) as inv_file:
        inv = yaml.safe_load(inv_file)

    nodes_array = config["nodes"]

    nodes = {}

    for i, node in enumerate(nodes_array):
        node_name = node["node_name"]
        nodes[node_name] = node
        nodes[node_name]["node_id"] = i +1

    ansible_runner.run(playbook = install_play, inventory = inv)

    
    for node_name in nodes:
        prov = generate_qkde_config_file(node_name, nodes)
        p = get_provisioning_play(prov, node_name)
        ansible_runner.run(playbook = p, inventory=inv)
    
    end_time = time.time()
    total_time = end_time-start_time
    print('\n Installation time: {}s'.format(total_time))
    


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

if __name__ == "__main__":
    install()