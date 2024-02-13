# *Quditto*

Quantum Key Distribution (QKD) networks enable the secure dissemination of cryptographic keys to remote application entities following Quantum Mechanics principles. Still, quantum devices and equipment are still in a development phase, making their availability low and their price high, hindering the deployment of physical QKD networks and, therefore, the research and experimentation activities related to this field.

*Quditto* aims at providing researchers and industry stakeholders with an open-source software orchestrator capable of deploying digital twins of QKD networks. Our digital twins implement each QKD node in software, enabling its execution in a virtual machine or a virtualization container. We use the [SimulaQron](http://www.simulaqron.org) emulator to support quantum links between QKD nodes and qubit operations, such as creating and exchanging Bell pairs. For each QKD node, the user may indicate specific configuration parameters, including the ETSI APIs and the QKD protocol that must be deployed (our current implementation supports the [ETSI QKD 004 interface](https://portal.etsi.org/webapp/workprogram/Report_WorkItem.asp?WKI_ID=54395) and an implementation of the E91 QKD protocol).

The configuration of the virtual QKD nodes is based on [Ansible](https://www.ansible.com), and [ETSI OSM](https://osm.etsi.org) can also be used. QKD nodes may be placed at different locations at the discretion of the user. To this purpose, our solution can leverage ETSI NFV-compliant cloud and edge infrastructures, (e.g., based on OpenStack), if available. Alternatively, it may set up the digital twin of the QKD network using physical or pre-pre-provisioned virtual machines. After the deployment process, user applications can access the different QKD nodes to retrieve cryptographic key material using their respective ETSI standard interface.

For details on the design and implementation of the QKD digital twin orchestration service, please refer to this [article](https://www.mdpi.com/2076-3417/14/3/1018).

## Installation

The *quditto* software is divided into three different components: the *quditto orchestrator*, the *quditto QKD node*, and the *quditto client*. To support the deployment of a digital twin of a QKD network, the *quditto* orchestrator needs to be installed. This can be done by downloading the [qdts_orchestrator](https://github.com/Networks-it-uc3m/QDTS/tree/main/qdts_orchestrator) folder, navigating to its directory, and then simply writing a pip install command:

```
pip install .
````

This will install all the required packages for the *quditto* orchestrator, and the *quditto* orchestrator itself.

To build applications on the QKD network digital twin environment, the *quditto client* package must be installed in the device that will act as a client application (that is, the application that will request cryptographic material from the QKD nodes). This can be done via pip:

```
pip install qdts-client
```

The *quditto QKD node* package will be automatically installed by the *quditto* orchestrator on the virtual machines or virtualization containers that will behave as QKD network nodes

## Deployinq a digital twin of a QKD network

### Using a preprovisionet set of virtual machines or virtualization containers

To deploy a digital twin of a QKD network on a pre-deployed machine pool, the orchestrator device is required to be able to make ssh connections with the machines that will act as QKD nodes. These machines also need to count with Python 3.

The *quditto* orchestrator package has to be installed in the orchestrator device, along with the [OSM client Python package](https://osm.etsi.org/gitlab/osm/osmclient), although in the case of having a pre-deployed machine pool, it will not be used (in future updates this prerequisite will be eliminated). Then, two files have to be written: the config.yaml file, and the inventory.yaml file. An example of these documents can be found in the [functional test](https://github.com/Networks-it-uc3m/QDTS/tree/main/functional_test) folder. 

The config.yaml file must contain:

- The service version (version 0.1.0 is, for now, the only version).
- The API used by the QKD nodes (currently only the [ETSI GS QKD 004 V2.1.1](https://www.etsi.org/deliver/etsi_gs/QKD/001_099/004/02.01.01_60/gs_qkd004v020101p.pdf) is supported).
- The QKD protocol used to form the keys (0.1.0 version implements the E91 protocol).
- The node names along with their IP addresses, and their neighbours.

The inventory.yaml file must contain:

- The IP address of each node.
- The ssh credentials for each machine.
- The directory where Python is installed.

Then, the *quditto* orchestrator must be executed from the device of the network orchestrator, along with these two files. 

```
qdts_orchestrator start config.yaml inventory.yaml
```

This command will install the *quditto* node software in each node, and start the emulation of the different channels, using SimulaQron, to connect the nodes as described in the configuration file. 

From this point on, the network is operational to run client applications.

### Full deployment automation using OSM

The *quditto* orchestrator package has to be installed in the orchestrator device. This method also uses as input a config.yaml file and an inventory.yaml file, to provide the *quditto* orchestrator with the topology of the desired QKD network. However, in this case, it is not necessary to include the IP addresses in either of the documents, as the OSM implementation will provide this information. Therefore, the IP address variable in the documents can remain empty or with any IP, since it will be ignored.

To deploy the QKD network without a pre-deployed machine pool, the OSM client package needs to be installed in the orchestrator device. Then, the *quditto* orchestrator can be executed including "OSM" behind the configuration and inventory file, along with a VIM account, and the ssh credentials so that OSM can connect to the machines.

```
qdts_orchestrator start config.yaml inventory.yaml OSM vim_account ssh_credentials
```

This command will instantiate the virtual machines required to deploy a digital twin of the QKD network described in the configuration file,  install the *quditto* node software in each node, and start the emulation of the different channels, using SimulaQron, to connect the nodes as described in the configuration file.

From this point on, the network is operational to run client applications.

