import yaml
import sys
import ansible_runner
import json
import time
import copy

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
                "delay": "30"
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
                "delay": "30"
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
            "name": "Start receiver",
            "shell":{
                "chdir": "{{py_env}}/site-packages/qd2_node",
                "cmd": ""
            },
        }
    ]

},
]

## Start the http_receptor.py script in all the nodes. Hosts parameter and the command parameter are filled with an ancilliary function because specific parameters are needed.
start_http_receptor_play = [
    {
    "name": "Repector execution",
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
                "chdir": "{{py_env}}/site-packages/qd2_node",
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

def get_receiver_play(host):
    play = start_receive_play
    play[0]["hosts"] = host
    play[0]["tasks"][0]["shell"]["cmd"] = "nohup python3 receive_qd2.py "+str(host)+" &"
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

# Check the availability of the nodes 
def wait_for_ssh(inv_file, retries=5, delay=5):
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




#Complete functions

def install(config_file, inv_file):
    # wait until SSH is actually ready on all hosts
    wait_for_ssh(inv_file)

    qkd_config, pqc_nodes = build_qd2_runtime_configs(config_file)
    has_qkd = qkd_config is not None and qkd_config.get("nodes")
    has_pqc = bool(pqc_nodes)

    # # if there is any qd2_node runtime to deploy (QKD or PQC),
    # #    install qd2-node on all qd2_nodes from the inventory
    # if has_qkd or has_pqc:
    #     ansible_runner.run(playbook=install_node_play, inventory=inv_file)

    # # if there is any qkd qd2_node,
    # #    install the controller and place configuration in all nodes
    # if has_qkd:
    #     config_array = qkd_config["config"]
    #     controller = config_array["controller"]
    #     ns_user = config_array["netsquid_user"]
    #     ns_pwd = config_array["netsquid_pwd"]

    #     # Install controller requirements and place config file
    #     if controller and ns_user and ns_pwd:
    #         icp = get_controller_play(controller, ns_user, ns_pwd, qkd_config)
    #         rmqp = get_rmq_play(controller)
    #         ansible_runner.run(playbook=icp, inventory=inv_file)
    #         ansible_runner.run(playbook=rmqp, inventory=inv_file)
        
    #     qkd_prov_config = get_provisioning_play(
    #         hosts="qkd_nodes",
    #         dest="{{py_env}}/site-packages/qd2_node/quditto_v2.yaml",
    #         content=qkd_config,
    #         )
        
    #     # Copy config file into the qd2_nodes
    #     ansible_runner.run(playbook=qkd_prov_config, inventory=inv_file)
    
    if has_pqc:
        print(pqc_nodes)
        pass



def run(config_file, inv_file):


    #with  open(config_file, "r") as config_file_o:
    #    config_data = yaml.safe_load(config_file_o)

    nodes_array = config_file["nodes"]
    nodes = {}
    for node in nodes_array:
        node_name = node["node_name"]
        nodes[node_name] = node

    for node in nodes:
        rp = get_receiver_play(node)
        ansible_runner.run(playbook = rp, inventory=inv_file)
        hp =get_receptor_play(node, nodes[node]["node_ip"])
        ansible_runner.run(playbook = hp, inventory = inv_file)

    config_array = config_file["config"]
    controller = config_array["controller"]
    sc = get_controller_init_play(controller)
    ansible_runner.run(playbook=sc, inventory = inv_file)

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

