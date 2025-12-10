import yaml
import sys
import ansible_runner
import json
import time
import copy
from typing import Optional, Tuple, Dict, Any

#Definition of the different ansible plays.

## Installation of the qd2 node package in every qd2_node (qkd or pqc).
install_node_play = [
    {
        "name": "Installation of qd2 node software",
        "hosts": "qd2_nodes",
        "tasks":
        [
            {
                "name": "Install pip",
                "become": True,
                "apt": "name=python3-pip state=present update_cache=true",
                "retries": "5",
                "delay": "10"
            },
            {
                "name": "Installing QKD node",
                "become": "false",
                "shell": (
                    "/usr/bin/pip install "
                    "{% if qd2_node_use_testpypi | default(false) | bool %}"
                    "--index-url https://test.pypi.org/simple "
                    "--extra-index-url https://pypi.org/simple "
                    "{% endif %}"
                    "{{ qd2_node_package_name | default('qd2-node') }}"
                    "{% if qd2_node_version is defined and qd2_node_version %}=={{ qd2_node_version }}{% endif %}"
                )
            }
        ]
    }
]


## Installation of the qd2 controller package just in the controller. The "hosts" variable get filled with the data from the configuration yaml file.
install_controller_play = [
    {
        "name": "Installation of controller software",
        "hosts": "",
        "tasks":
        [
            {
                "name": "Install pip",
                "become": True,
                "apt": "name=python3-pip state=present update_cache=true",
                "retries": "5",
                "delay": "10"
            },
            {
                "name": "Installing Netsquid",
                "become": "false",
                "shell": ""
            },
            {
                "name": "Installing Quditto controller",
                "become": "false",
                "shell": "/usr/bin/pip install qd2_controller"
            },
            {
                "name": "Copy confguration file",
                "copy":{
                    "dest": "{{py_env}}/site-packages/qd2_controller/quditto_v2.yaml",
                    "content": ""
                }
            }
            ]
    }
]

## Provisioning of the configuration file to qd2_nodes installation script to all the nodes.
provisioning_play = [
{
    "name": "Provisioning config file into the qd2_nodes",
    "hosts": "",
    "become": True,
    "tasks":[
        {
            "name": "Copy confguration file",
             "copy":{
                "dest": "",
                "content": ""
            }
        }
    ]

},
]

## Setup of RabbitMQ in the controller
configuring_rmq_play = [
    {
    "name": "RabbitMQ configuration",
    "hosts": "",
    "become": True,
    "tasks":[
        {
            "name": "Install rabbitmq-server",
            "apt": {
                "name": "rabbitmq-server", "state": "present", "update_cache": True,
                }      
        },
        {
            "name": "Start RabbitMQ server if not running",
            "shell": {
                "cmd": (
                    "if ! rabbitmqctl status >/dev/null 2>&1; then "
                    "RABBITMQ_NODENAME='rabbit@$(hostname)' rabbitmq-server -detached; "
                    "fi"
                )
            }
        },
        {
            "name": "Add user",
            "ignore_errors": True,
            "shell":{
                "cmd": "rabbitmqctl add_user node node"
            },
        },
        {
                "name": "Set user tags",
                "shell": {
                    "cmd": "rabbitmqctl set_user_tags node administrator",
                },
            },
        {
            "name": "Set permissions",
            "shell": {
                "cmd": "rabbitmqctl set_permissions -p / node '.*' '.*' '.*'",
            },
        }
    ]

},
]

## Start the receive_q2.py script in all the nodes. Hosts parameter and the command parameter are filled with an ancilliary function because specific parameters are needed.
start_receive_play = [
    {
    "name": "Receiver execution",
    "hosts": "",
    "tasks":[
        {
            "name": "Wait for Vault to be up",
            "wait_for": {
                "host": "localhost",
                "port": 8200,
                "delay": 5,       # seconds before first check
                "timeout": 10     # total time to wait
            }
        },
        {
            "name": "Start receiver",
            "shell":{
                "chdir": "{{py_env}}/site-packages/qd2_node/qkd_node/",
                "cmd": ""
            },
        }
    ]

},
]

## Start the http_receptor.py script in all the nodes. Hosts parameter and the command parameter are filled with an ancilliary function because specific parameters are needed.
start_http_receptor_play = [
    {
    "name": "Receptor execution",
    "hosts": "",
    "tasks":[
        {
            "name": "Start receptor",
            "shell":{
                "chdir": "{{py_env}}/site-packages/qd2_node",
                "cmd": ""
            },
        }
    ]

},
]

## Start the controller.py script
start_controller_play = [
    {
    "name": "Controller file execution",
    "hosts": "",
    "tasks":[
        {
            "name": "Start controller",
            "shell":{
                "chdir": "{{py_env}}/site-packages/qd2_controller",
                "cmd": "nohup python3 controller.py &"
            },
        }
    ]

},
]


## Stop both scripts.
stop_play = [
    {
    "name": "Stop",
    "hosts": "all",
    "become": True,
    "tasks":[
        {
            "name": "Stopping receive script",
            "ignore_errors": True,
            "shell":{
                "chdir": "{{py_env}}/site-packages/qd2_node/qkd_node",
                "cmd": "pkill -f 'receive_qd2.py'"
            },
        },
        {
            "name": "Stopping receptor script",
            "ignore_errors": True,
            "shell":{
                "chdir": "{{py_env}}/site-packages/qd2_node",
                "cmd": "pkill -f 'http_receptor.py'"
            },
        }
    ]

},
]

## Get the name of the simulation scripts in the controller

get_simulation_scripts_play = [
    {
        "name": "Get simulation scripts",
        "hosts": "",  
        "tasks": [
            {
                "name": "Get scripts",
                "shell": {
                    "chdir": "{{py_env}}/site-packages/qd2_controller",
                    "cmd": "ls -p | grep -E '^[^/]+\\.py$' | grep -v '^__init__\\.py$' | grep -v 'controller.py'"
                },
                "register": "sim_scripts"
            }
        ]
    }
]

configuring_vault_play = [
    {
        "name": "Vault installation (HashiCorp official repo)",
        "hosts": "",  
        "become": True,
        "tasks": [
            {
                "name": "Install Vault dependencies",
                "apt": {
                    "name": ["wget", "gpg", "ca-certificates"],
                    "state": "present",
                    "update_cache": True,
                },
            },
            {
                "name": "Add HashiCorp GPG key",
                "shell": (
                    "wget -O- https://apt.releases.hashicorp.com/gpg "
                    "| gpg --dearmor -o /usr/share/keyrings/hashicorp-archive-keyring.gpg"
                ),
                "args": {
                    # Don't redo if the keyring already exists
                    "creates": "/usr/share/keyrings/hashicorp-archive-keyring.gpg",
                },
            },
            {
                "name": "Configure HashiCorp apt repository",
                "copy": {
                    "dest": "/etc/apt/sources.list.d/hashicorp.list",
                    "content": (
                        "deb [signed-by=/usr/share/keyrings/hashicorp-archive-keyring.gpg] "
                        "https://apt.releases.hashicorp.com "
                        "{{ ansible_distribution_release }} main\n"
                    ),
                },
            },
            {
                "name": "Update apt cache after adding HashiCorp repo",
                "apt": {
                    "update_cache": True,
                },
            },
            {
                "name": "Install Vault",
                "apt": {
                    "name": "vault",
                    "state": "present",
                },
            },
            {
                "name": "Remove capabilities from Vault binary",
                "command": "setcap -r /usr/bin/vault",
                "ignore_errors": True,
            },
        ],
    }
]


start_pqc_server_play = [
    {
        "name": "PQC server execution",
        "hosts": "",
        "tasks": [
            {
                "name": "Wait for Vault to be up",
                "wait_for": {
                    "host": "localhost",
                    "port": 8200,
                    "delay": 5,       # seconds before first check
                    "timeout": 10     # total time to wait
                }
            },
            {
                "name": "Start PQC server",
                "shell": {
                    "chdir": "{{py_env}}/site-packages/qd2_node/pqc_node",
                    "cmd": "nohup python3 server.py &",
                },
            }
        ],
    }
]

start_vault_play = [
    {
        "name": "Vault server execution",
        "hosts": "",
        "tasks": [
            {
                "name": "Start vault server",
                "shell": {
                    "chdir": "{{py_env}}/site-packages/qd2_node",
                    "cmd": "",
                },
            }
        ],
    }
]


# Simple SSH connectivity check: try to run a no-op command on all hosts of the inventory.
ssh_health_check_play = [
    {
        "name": "SSH connectivity check",
        "hosts": "all",
        "gather_facts": False,
        "tasks": [
            {
                "name": "Run noop command",
                "ansible.builtin.command": "true",
            }
        ],
    }
]



#Ancilliary functions to fill the plays

def get_controller_play(host, ns_user, ns_pwd, content):
    play = install_controller_play
    play[0]["hosts"] = host
    play[0]["tasks"][1]["shell"] = "/usr/bin/pip install --user --extra-index-url https://"+str(ns_user)+":"+str(ns_pwd)+"@pypi.netsquid.org netsquid"
    play[0]["tasks"][3]["copy"]["content"] = content
    return play

def get_rmq_play(host):
    play = configuring_rmq_play
    play[0]["hosts"] = host
    return play

def get_provisioning_play(hosts: str, dest: str, content: str):
    """
    Build a provisioning play that copies 'content' to 'dest'
    on all hosts in the given 'hosts' group/host pattern.
    """
    play = copy.deepcopy(provisioning_play)
    play[0]["hosts"] = hosts
    play[0]["tasks"][0]["copy"]["dest"] = dest
    play[0]["tasks"][0]["copy"]["content"] = content
    return play

def get_receiver_play(host, vault_volume, vault_port):
    cmd = (
        f"nohup python3 receive_qd2.py "
        f"{host} {vault_volume} {vault_port} &"
    )
    play = start_receive_play
    play[0]["hosts"] = host
    play[0]["tasks"][0]["wait_for"]["port"] = vault_port
    play[0]["tasks"][1]["shell"]["cmd"] = cmd
    return play

def get_receptor_play(host, IP):
    play = start_http_receptor_play
    play[0]["hosts"] = host
    play[0]["tasks"][0]["shell"]["cmd"] = "nohup python3 http_receptor.py "+str(IP)+" 8000 "+str(host)+" &"
    return play

def get_controller_init_play(host):
    play = start_controller_play
    play[0]["hosts"] = host
    return play

def get_pqc_server_play(host):
    play = start_pqc_server_play
    play[0]["hosts"] = host
    return play

def get_vault_play(host, vault_volume, vault_port):
    play = start_vault_play
    play[0]["hosts"] = host

    cmd = (
        f"nohup python3 vault.py "
        f"-v {vault_volume} -p {vault_port} &"
    )

    play[0]["tasks"][0]["shell"]["cmd"] = cmd
    return play


# Check the availability of the nodes 
def wait_for_ssh(inv_file, retries=2, delay=5):
    """
    Wait until Ansible can run a simple command on all hosts via SSH,
    or fail after N retries.

    inv_file: inventory dict loaded from YAML (same type the CLI passes).
    """
    print(f"Checking SSH connectivity to all hosts (up to {retries} attempts)...")
    for attempt in range(1, retries + 1):
        r = ansible_runner.run(
            playbook=ssh_health_check_play,
            inventory=inv_file,
            quiet=True,
        )

        # ansible-runner exposes rc: 0 = success
        if getattr(r, "rc", 0) == 0:
            print(f"SSH connectivity ok on attempt {attempt}.")
            return

        print(f"Attempt {attempt} failed, retrying in {delay} seconds...")
        time.sleep(delay)

    print("ERROR: SSH connectivity to some hosts failed after all retries.")
    sys.exit(1)



# Parse the config file provided by the user to divide qkd and pqc layers
def build_qd2_runtime_configs(initial_config: dict):
    """
    Given the full config yaml,
    return (qkd_config, pqc_nodes).

    - qkd_config: same structure as raw_config, but with PQC nodes removed.
                  If 'config' or 'nodes' are missing, returns None.
    - pqc_nodes: list of nodes with node_type == 'PQC' (case-insensitive).
                 [] if none or if 'nodes' missing.
    """
    nodes = initial_config.get("nodes")
    if not isinstance(nodes, list):
        return (None if "config" not in initial_config else copy.deepcopy(initial_config), [])

    pqc_nodes = []
    qkd_like_nodes = []

    for node in nodes:
        node_type = str(node.get("node_type", "")).upper()
        if node_type == "PQC":
            pqc_nodes.append(node)
        else:
            # QKD, controller, or anything else you want to keep in the QKD view
            qkd_like_nodes.append(node)

    qkd_config = None
    if "config" in initial_config:
        # Only build the QKD config view if the top-level 'config' exists
        qkd_config = copy.deepcopy(initial_config)
        qkd_config["nodes"] = qkd_like_nodes

    return qkd_config, pqc_nodes

# Prepare the required client/server yamls for a pqc qd2 nodes


def build_pqc_node_yamls(node: Dict[str, Any]) -> Tuple[str, Optional[str]]:
    """
    Given a single PQC node dict, build the contents of server.yaml
    and client.yaml for that node.
    """
    vault_ip = node.get("vault_ip")
    vault_port = node.get("vault_port")
    vault_volume = node.get("vault_volume")

    server_security_level = node.get("server_security_level")
    client_security_level = node.get("client_security_level")

    # --- server.yaml dict ---
    server_cfg = {
        "crypto": {
            "ml-dsa": server_security_level,
        },
        "vault": {
            "host": vault_ip,
            "port": vault_port,
            "volume": vault_volume,
        },
    }
    server_yaml = yaml.safe_dump(server_cfg, sort_keys=False)
    

    # --- client.yaml dict (only if client_security_level exists) ---
    client_yaml = None
    if client_security_level is not None:
        client_cfg = {
            "crypto": {
                "ml-dsa": client_security_level,
            },
            "vault": {
                "host": vault_ip,
                "port": vault_port,
                "volume": vault_volume,
            },
        }
        client_yaml = yaml.safe_dump(client_cfg, sort_keys=False)
    else:
        client_cfg = {
            "vault": {
                "host": vault_ip,
                "port": vault_port,
                "volume": vault_volume,
            },
        }
        client_yaml = yaml.safe_dump(client_cfg, sort_keys=False)
        

    return server_yaml, client_yaml


# Install vault software into the specified hosts
def get_vault_install_play(hosts: str):
    """
    Build a play to install HashiCorp Vault on the given hosts/group.
    Typical usage: hosts='qd2_nodes'.
    """
    play = copy.deepcopy(configuring_vault_play)
    play[0]["hosts"] = hosts
    return play





#Complete functions

def install(config_file, inv_file):
    # wait until SSH is actually ready on all hosts
    wait_for_ssh(inv_file)

    qkd_config, pqc_nodes = build_qd2_runtime_configs(config_file)
    has_qkd = qkd_config is not None and qkd_config.get("nodes")
    has_pqc = bool(pqc_nodes)

    # if there is any qd2_node runtime to deploy (QKD or PQC),
    #    install qd2-node on all qd2_nodes from the inventory,
    #    install Vault
    if has_qkd or has_pqc:
        ansible_runner.run(playbook=install_node_play, inventory=inv_file)
        vault_play = get_vault_install_play("qd2_nodes")
        ansible_runner.run(playbook=vault_play, inventory=inv_file)


    # if there is any qkd qd2_node,
    #    install the controller and place configuration in all nodes
    if has_qkd:
        config_array = qkd_config["config"]
        controller = config_array["controller"]
        ns_user = config_array["netsquid_user"]
        ns_pwd = config_array["netsquid_pwd"]

        # Install controller requirements and place config file
        if controller and ns_user and ns_pwd:
            icp = get_controller_play(controller, ns_user, ns_pwd, qkd_config)
            rmqp = get_rmq_play(controller)
            ansible_runner.run(playbook=icp, inventory=inv_file)
            ansible_runner.run(playbook=rmqp, inventory=inv_file)
        
        qkd_prov_config = get_provisioning_play(
            hosts="qkd_nodes",
            dest="{{py_env}}/site-packages/qd2_node/qkd_node/quditto_v2.yaml",
            content=qkd_config,
            )
        
        # Copy config file into the qd2_nodes
        ansible_runner.run(playbook=qkd_prov_config, inventory=inv_file)
    
    if has_pqc:
         # loop per PQC node
        for pqc_node in pqc_nodes:
            node_name = pqc_node.get("node_name")
            if not node_name:
                continue  # skip if unnamed

            server_yaml, client_yaml = build_pqc_node_yamls(pqc_node)

            # provision server.yaml
            server_dest = "{{py_env}}/site-packages/qd2_node/pqc_node/server.yaml"
            server_play = get_provisioning_play(
                hosts=node_name,
                dest=server_dest,
                content=server_yaml,
            )
            ansible_runner.run(playbook=server_play, inventory=inv_file)

            # provision client.yaml if it exists
            if client_yaml is not None:
                client_dest = "{{py_env}}/site-packages/qd2_node/pqc_node/client.yaml"
                client_play = get_provisioning_play(
                    hosts=node_name,
                    dest=client_dest,
                    content=client_yaml,
                )
                ansible_runner.run(playbook=client_play, inventory=inv_file)



def run(config_file, inv_file):
    # Build a mapping node_name -> node_config
    nodes_array = config_file["nodes"]
    nodes_by_name = {}
    for node in nodes_array:
        node_name = node["node_name"]
        nodes_by_name[node_name] = node

    # Loop over (node_name, node_config)
    for node_name, node in nodes_by_name.items():
        node_ip = node.get("node_ip")
        node_type = str(node.get("node_type", "")).upper()
        vault_volume = node.get("vault_volume")
        vault_port = node.get("vault_port")

        # --- All nodes: run http_receptor.py and vault.py  ---
        vp = get_vault_play(node_name, vault_volume, vault_port)
        hp = get_receptor_play(node_name, node_ip)
        ansible_runner.run(playbook=hp, inventory=inv_file)
        ansible_runner.run(playbook=vp, inventory=inv_file)

        # --- QKD: run receive_qd2.py ---
        if node_type == "QKD":
            rp = get_receiver_play(node_name, vault_volume, vault_port)
            print(rp)
            print('----------------------------------------------------------------------')
            ansible_runner.run(playbook=rp, inventory=inv_file)

        # --- PQC: run server.py ---
        elif node_type == "PQC":
            sp = get_pqc_server_play(node_name)
            ansible_runner.run(playbook=sp, inventory=inv_file)

    # Controller init (if present)
    config_array = config_file.get("config", {})
    controller = config_array.get("controller")
    if controller:
        sc = get_controller_init_play(controller)
        ansible_runner.run(playbook=sc, inventory=inv_file)


# def run(config_file, inv_file):
    
#     # Execute the python binaries on the qd2_nodes
#     nodes_array = config_file["nodes"]
#     nodes = {}
#     for node in nodes_array:
#         node_name = node["node_name"]
#         nodes[node_name] = node

#     for node in nodes:

#         node_ip = node.get("node_ip")
#         node_type = str(node.get("node_type", "")).upper()
#         # --- All nodes: run http_receptor.py ---
#         hp = get_receptor_play(node_name, node_ip)
#         ansible_runner.run(playbook=hp, inventory=inv_file)

#         # --- QKD: run receive_qd2.py ---
#         if node_type == "QKD":
#             rp = get_receiver_play(node_name)
#             print(rp)
#             ansible_runner.run(playbook=rp, inventory=inv_file)
#         # --- PQC: run server.py ---
#         elif node_type == "PQC":
#             sp = get_pqc_server_play(node_name)
#             print(sp)
#             ansible_runner.run(playbook=sp, inventory=inv_file)

#         # rp = get_receiver_play(node)
#         # ansible_runner.run(playbook = rp, inventory=inv_file)
#         # hp =get_receptor_play(node, nodes[node]["node_ip"])
#         # ansible_runner.run(playbook = hp, inventory = inv_file)
    
#     # Execute the python binaries on the qd2_controller
#     config_array = config_file["config"]
#     controller = config_array["controller"]
#     sc = get_controller_init_play(controller)
#     ansible_runner.run(playbook=sc, inventory = inv_file)



def stop_nodes(inv_file):
    ansible_runner.run(playbook = stop_play, inventory = inv_file)

def get_scripts(config_file, inv_file):
    config_array = config_file["config"]
    controller = config_array["controller"]
    play = get_simulation_scripts_play
    play[0]["hosts"] = controller
    r = ansible_runner.run(playbook = play, inventory = inv_file, quiet = True)
    # Extract the stdout lines from the registered variable "sim_scripts" in the play results
    script_names = []
    for event in r.events:
        if event.get('event') == 'runner_on_ok':
            if event['event_data']['task'] == 'Get scripts':
                res = event['event_data']['res']
                if 'stdout_lines' in res:
                    script_names = res['stdout_lines']
                    break

    return script_names

