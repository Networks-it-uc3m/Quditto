import yaml
import sys
import ansible_runner
import json
import time

#Definition of the different ansible plays.

## Installation of the qd2 node package in every node.
install_node_play = [
    {
        "name": "Installation of QKD node software",
        "hosts": "all",
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
                "shell": "/usr/bin/pip install qd2_node"
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
            },
            {
                "name": "Copy RabbitMQ installation file",
                "ansible.builtin.copy":{
                    "src": "{{py_env}}/site-packages/qd2_orchestrator/rabbit_mq_installation.sh",
                    "dest": "{{py_env}}/site-packages/qd2_controller/rabbit_mq_installation.sh"
                }
            },
            {
                "name": "Make script executable",
                "become": True,
                "shell":{
                    "chdir": "{{py_env}}/site-packages/qd2_controller",
                    "cmd": "chmod +x rabbit_mq_installation.sh"
                }
            }
            ]
    }
]

## Provisioning of the configuration file and the RabbitMQ installation script to all the nodes.
provisioning_play = [
{
    "name": "Provisioning",
    "hosts": "all",
    "become": True,
    "tasks":[
        {
            "name": "Copy confguration file",
             "copy":{
                "dest": "{{py_env}}/site-packages/qd2_node/quditto_v2.yaml",
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
            "name": "Install Rabbit MQ",
            "shell":{
                "chdir": "{{py_env}}/site-packages/qd2_controller",
                "cmd": "bash rabbit_mq_installation.sh"
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




#Ancilliary functions to fill the plays

def get_controller_play(host, ns_user, ns_pwd, content):
    play = install_controller_play
    play[0]["hosts"] = host
    play[0]["tasks"][0]["shell"] = "/usr/bin/pip install --user --extra-index-url https://"+str(ns_user)+":"+str(ns_pwd)+"@pypi.netsquid.org netsquid"
    play[0]["tasks"][2]["copy"]["content"] = content
    return play

def get_rmq_play(host):
    play = configuring_rmq_play
    play[0]["hosts"] = host
    return play

def get_provisioning_play(content):
    play = provisioning_play
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




#Complete functions

def install(config_file, inv_file):
    # Added a small delay to ensure that the virtual node is up
    print('Sleeping to avoid errors in the Ansible ssh connection....')
    time.sleep(30)

    ansible_runner.run(playbook = install_node_play, inventory = inv_file)

#    with  open(config_file, "r") as config_file_o:
#        config_data = yaml.safe_load(config_file_o)
    config_array = config_file["config"]
    controller = config_array["controller"]
    ns_user = config_array["netsquid_user"]
    ns_pwd = config_array["netsquid_pwd"]
    icp = get_controller_play(controller, ns_user, ns_pwd, config_file)
    rmqp = get_rmq_play(controller)
    ansible_runner.run(playbook = icp, inventory = inv_file)
    ansible_runner.run(playbook = rmqp, inventory = inv_file)

    p = get_provisioning_play(config_file)
    ansible_runner.run(playbook = p, inventory=inv_file)


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

