<picture>
  <source media="(prefers-color-scheme: dark)" srcset="Images/quditto_logo_dark.png">
  <source media="(prefers-color-scheme: light)" srcset="Images/quditto_logo_light.png">
  <img alt="Quditto logo" src="Images/quditto_logo_light.png" height="100">
</picture>

*Quditto* is an open-source platform that enables researchers and industry stakeholders to __deploy fully functional digital twins of Quantum Key Distribution (QKD) networks using classical infrastructure__. Designed to accelerate quantum networking research, *Quditto* emulates distributed QKD exchanges so experiments and analysis can be conducted without quantum hardware.

QKD networks enable the secure dissemination of cryptographic keys to remote application entities following Quantum Mechanics principles. Still, quantum devices and equipment remain in a development phase, making their availability low and their price high, hindering the deployment of physical QKD networks and, therefore, the research and experimentation activities related to this field. With *Quditto*, users can treat their classical equipment as quantum hardware, enabling trials without the quantum physical equipment requirement, nor compromising the integrity of an already built QKD network. 

Our digital twins have three main agents: the __orchestrator__, based on [Ansible](https://www.ansible.com), automatically configures the classical computers, virtual machines, or containers that will be part of the QKD network; the __controller__ in charge of everything related to the quantum behaviour of the network using, by default, [NetSquid](https://netsquid.org/); and the __nodes__, with which the user interacts to request keys. Our QKD node design conforms to the standardized __ETSI QKD 014 API__, making user-node communication exactly as if they were real physical nodes. 

__We offer users two different implementations of the BB84 protocol__, reflected in two simulation scripts: *bb84_with_eve.py*, which is designed so that eavesdroppers can be added to quantum channels, and *bb84_att.py*, a model that includes many more user-configurable variables to reflect much more realistic behavior. A more detailed discussion of both scripts, as well as the files themselves, can be found at the [controller folder](https://github.com/Networks-it-uc3m/Quditto/tree/main/qd2_controller). __However, *Quditto* is designed to accept any other protocol implementation__, instructions can also be found in the [controller folder](https://github.com/Networks-it-uc3m/Quditto/tree/main/qd2_controller).

Below are directions on how to install and use *Quditto* for the first time. In addition, a specific example has been added to the [tutorial folder](https://github.com/Networks-it-uc3m/Quditto/tree/main/Tutorial) to help users become familiar with the platform.

## Installation

The *Quditto* software is divided into three different Python packages that correspond to the three different agents of the digital twins: the *qd2_orchestrator*, the *qd2_controller*, and the *qd2_nodes*. To support the deployment of a QKD network digital twin, __the *qd2_orchestrator* needs to be installed__. This can be done via pip: 

```
pip install qd2_orchestrator
```

__The *qd2_controller* and the *qd2_node* packages will be installed automatically__ by the orchestrator once the deployment of the digital twin starts.

## Deploying a Digital Twin

*Note: We are working to provide the option to use OSM for automatic deployment of virtual machines, as it was in version 1.0. For now, the only deployment mode supported by this version is to use a set of pre-provisioned machines or containers.*

To deploy a digital twin of a QKD network on pre-provisioned physical or virtual machines, or virtualization containers, __the orchestrator device is required to be able to make *ssh* connections with Ansible (usually this means having *sshpass* installed)__ with the machines or containers that will act as QKD nodes. These machines and containers need to count with Python 3.

The *qd2_orchestrator* package has to be installed in the device that will serve as the orchestrator. To start the QKD network digital twin deployment, __two YAML files__ must be specified to the *qd2_orchestrator*: the __*config.yaml*__ file, which describes the configuration of the QKD network; and the __*inventory.yaml*__ file, providing the details that are necessary to access each machine/container and transform it into a functional QKD node in the digital twin.

More concretely, the __*config.yaml*__ file must contain:

- [Optional] Service version (in the case of this release, the 2.0).
- General configuration parameters:
  - [Optional] API used by the QKD nodes (currently the [ETSI GS QKD 014 V1.1.1](https://www.etsi.org/deliver/etsi_gs/QKD/001_099/014/01.01.01_60/gs_qkd014v010101p.pdf) is supported).
  - [Optional] QKD protocol is used to form the keys (2.0 version implements by default the BB84 protocol).
  - __Name and the IP of the node which will also act as the controller.__
  - __Credentials to access the NetSquid platform and download the package.__
- [Optional] Name of the sites present in the network.
- List of nodes: for each node, the file must contain:
  - __Node name.__
  - [Optional] Site to which the node belongs.
  - __Node IP.__
  - List of the neighbour nodes. For each neighbour it must be addressed:
    - __Neighbour node.__
    - __Link length.__
    - __Simulation script__ of protocol used in the link.
    - __Presence of an eavesdropper.__ If this parameter is set to *True*, the eavesdropper distance from the node and the percentage of intercepted qubits must also be included.
    - __Specific parameters required by the simulation script.__

  For example, a simple valid *config.yaml* file would look like this:

```
---
config:
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
        protocol: bb84_att.py
        eavesdropper: False

  - node_name: B
    node_ip: ip_B
    neighbour_nodes:
      - name: A
        link_length: 20
        protocol: bb84_att.py
        eavesdropper: False
```

The __*inventory.yaml*__ file must contain:

- __IP address__ of each node.
- __SSH credentials__ for each machine or container.
- __Directory where Python is installed.__

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

Another complete example of these YAML files for a three-noded QKD network can be found in the [Tutorial](https://github.com/Networks-it-uc3m/Quditto/tree/main/Tutorial) folder. 

The __*qd2_orchestrator*__ must be executed providing both files as arguments: 

```
qd2_orchestrator start config.yaml inventory.yaml
```

This command will install the __*qd2_node*__ package on every machine/container, and the __*qd2_controller*__ package on the specified one. Then, it will start all the necessary processes of said packages to start the emulation of the QKD network.

__From this point on, the digital twin of the QKD network is operational to run client applications, which may request cryptographic material from the QKD nodes using the 014 ETSI API.__


## Related publications and presentations

- [OSM Ecosystem day #16](https://osm.etsi.org/wikipub/index.php/OSM16_Ecosystem_Day): Using OSM to deploy digital twins of Quantum Key Distribution Networks - Presented: 29 November 2023.

- [Service for Deploying Digital Twins of QKD Networks](https://doi.org/10.3390/app14031018) - Published: 25 January 2024. 

- [Unleashing Flexibility and Interoperability in QKD Networks: The Power of Softwarized Architectures](10.1109/QCNC62729.2024.00041) - Published: 22 August 2024.

- [DigiTwin 2024](https://dtiac.com/PreviousConference/info.aspx?itemid=79): Exploring and Building Digital Key Twins for Quantum Distribution Networks - Presented: 16 October 2024

- [An Enhanced Virtualized Control and Key Management Model for QKD Networks](10.1109/MNET.2025.3538752) - Published: 4 February 2025.

- [Monitoring Strategy for Enhanced Adaptability in QKD Networks](10.1109/QCNC64685.2025.00048) - Published: 15 May 2025.

- [A Digital Twin Approach to Quantum Key Distribution Under Eavesdropping](10.1109/QCNC64685.2025.00030) - Published: 15 May 2025.

- [IETF 123](https://datatracker.ietf.org/meeting/123/proceedings/): Quditto: Emulating and Orchestrating Distributed Quantum Network Deployments - Presented: 21 July 2025


## Contact

If you have any doubts or feedback, please feel free to contact us through e-mail. We are more than happy to help and hear ideas for improving the platform :)

- Blanca Lopez: blanca.lopez@networks.imdea.org (IMDEA Networks - Universidad Carlos III de Madrid)
- Ángela Díaz-Bricio: angela.diaz@networks.imdea.org (IMDEA Networks - Universidad Carlos III de Madrid)
- Javier Pérez: javier.perez@networks.imdea.org (IMDEA Networks - Universidad Carlos III de Madrid)
- Iván Vidal: ividal@it.uc3m.es (Universidad Carlos III de Madrid)
- Francisco Valera: fvalera@it.uc3m.es (Universidad Carlos III de Madrid)


## ACK

This platform has been developed under the MADQuantum-CM project, funded by the Regional Government of Madrid, the Spanish State through the Recovery, Transformation and Resilience Plan, and the European Union through the NextGeneration EU funds, the project 6GINSPIRE PID2022-137329OB-C42, funded by MCIN/AEI/10.13039/501100011033/, and the EU Horizon Europe project Quantum Security Networks Partnership (QSNP), under grant 101114043.

### Other projects where Quditto has been used


