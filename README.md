<picture>
  <source media="(prefers-color-scheme: dark)" srcset="Images/quditto_logo_dark.png">
  <source media="(prefers-color-scheme: light)" srcset="Images/quditto_logo_light.png">
  <img alt="Quditto logo" src="Images/quditto_logo_light.png" height="100">
</picture>

*Quditto* aims at providing researchers and industry stakeholders with an open-source software orchestrator capable of deploying digital twins of Quantum Key Distribution (QKD) networks.

QKD networks enable the secure dissemination of cryptographic keys to remote application entities following Quantum Mechanics principles. Still, quantum devices and equipment remain in a development phase, making their availability low and their price high, hindering the deployment of physical QKD networks and, therefore, the research and experimentation activities related to this field. *Quditto* enables the emulation of QKD network deployments, where experiments and trials can be performed without the quantum physical equipment requirement, nor compromising the integrity of an already built QKD network. 

Our digital twin has three main agents: the orchestrator, based on [Ansible](https://www.ansible.com), automatically configures the virtual machines or containers that will be part of the QKD network; the controller in charge of everything related to the quantum behavior of the network using [NetSquid](https://netsquid.org/); and the nodes, with which the user interacts to request keys. Our QKD node design conforms to the standardized ETSI QKD 014 API, making user-node communication exactly as if they were real physical nodes. By default, an implementation of the BB84 protocol is used to create keys between nodes. There is also the possibility to use another protocol (or another implementation of the same protocol) as explained later [TO DO].

## Installation

The *Quditto* software is divided into three different Python packages that correspond to the three different agents of the digital twins: the *qd2_orchestrator*, the *qd2_controller*, and the *qd2_nodes*. To support the deployment of a QKD network digital twin, the *qd2_orchestrator* needs to be installed. This can be done via pip: 

```
pip install qd2_orchestrator
```
The *qd2_controller* and the *qd2_node* packages will be installed automatically by the orchestrator once the deployment of the digital twin starts.

## Deploying a Digital Twin

We are working to provide the option to use OSM for automatic deployment of virtual machines, as it was in version 1.0. For now, the only deployment mode supported by this version is to use a set of pre-provisioned machines or containers.

To deploy a digital twin of a QKD network on pre-provisioned physical or virtual machines, or virtualization containers, the orchestrator device is required to be able to make *ssh* connections with the machines or containers that will act as QKD nodes. These machines and containers need to count with Python 3.

The *qd2_orchestrator* package has to be installed in the device that will serve as the orchestrator. To start the QKD network digital twin deployment, two YAML files must be specified to the *qd2_orchestrator*: the *config.yaml* file, which describes the configuration of the QKD network; and the *inventory.yaml* file, providing the details that are necessary to access each machine/container and transform it into a functional QKD node in the digital twin. 

More concretely, the *config.yaml* file must contain:

- [Optional] Service version (in the case of this release, the 2.0).
- General configuration parameters:
  - [Optional] API used by the QKD nodes (currently the [ETSI GS QKD 014 V1.1.1](https://www.etsi.org/deliver/etsi_gs/QKD/001_099/014/01.01.01_60/gs_qkd014v010101p.pdf) is supported).
  - QKD protocol is used to form the keys (2.0 version implements by default the BB84 protocol).
  - Name and the IP of the node which will also act as the controller.
  - Credentials to access the NetSquid platform and download the package.
- [Optional] Name of the sites present in the network.
- List of nodes: for each node, the file must contain:
  - Node name.
  - [Optional] Site to which the node belongs.
  - Node IP.
  - List of the neighbour nodes. For each neighbour it must be addressed:
    - Neighbour node.
    - Link length.
    - Protocol used in the link.
    - Presence of an eavesdropper. If this parameter is set to *True*, then the eavesdropper distance to the node and the percentage of intercepted qubits must be added.
   
  For example, a simple valid *config.yaml* file would look like this:

```
---
config:
  qkd_protocol: bb84
  controller: A
  ip_controller: ip_A
  netsquid_user: your_user
  netsquid_pwd: your_pwd

nodes:
  - node_name: A
    node_ip: ip_A
    neighbour_nodes:
      - name: B
        link_length: 20
        protocol: bb84
        eavesdropper: False

  - node_name: B
    node_ip: ip_B
    neighbour_nodes:
      - name: A
        link_length: 20
        protocol: bb84
        eavesdropper: False
```

The *inventory.yaml* file must contain:

- The IP address of each node.
- The SSH credentials for each machine or container.
- The directory where Python is installed.

  Again, a simple *inventory.yaml* file could be:

```
---
all:
  hosts:
    A:
      ansible_host: ip_A
      ansible_connection: ssh
      ansible_user: user
      ansible_ssh_pass: pwd
      py_env: python3/directory
    B:
      ansible_host: ip_B
      ansible_connection: ssh
      ansible_user: user
      ansible_ssh_pass: pwd
      py_env: python3/directory
```

Another sample of these YAML files for a three-noded QKD network can be found in the [Tutorial](https://github.com/Networks-it-uc3m/Quditto/tree/main/Tutorial) folder. 

The *qd2_orchestrator* must be executed providing both files as arguments: 

```
qd2_orchestrator start config.yaml inventory.yaml
```

This command will install the *qd2_node* package on every machine/container, and the *qd2_controller* package on the specified one. Then, it will start all the necessary processes of said packages to start the emulation of the QKD network.

From this point on, the digital twin of the QKD network is operational to run client applications, which may request cryptographic material from the QKD nodes using the 014 ETSI API.

## ACK

This platform has been developed under the MADQuantum-CM project, funded by the Regional Government of Madrid, the Spanish State through the Recovery, Transformation and Resilience Plan, and the European Union through the NextGeneration EU funds, the project 6GINSPIRE PID2022-137329OB-C42, funded by MCIN/AEI/10.13039/501100011033/, and the EU Horizon Europe project Quantum Security Networks Partnership (QSNP), under grant 101114043.
