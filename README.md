# QDTS
The QKD Digital Twin Service (QDTS) is a tool that allows deploying digital twins of QKD networks over classical infrastructure. The service is divided into three different roles of a network: the orchestrator, the nodes and the clients. It is built upon the quantum emulator SimulaQron and incorporates NFV features via OSM.

For details on the design and implementation of the service, please refer to this [article](https://www.mdpi.com/2076-3417/14/3/1018).

## Installation

To deploy the digital twin of a QKD network, the only package that needs to be installed is the QDTS orchestrator. This can be done by downloading the [qdts_orchestrator](https://github.com/Networks-it-uc3m/QDTS/tree/main/qdts_orchestrator) folder, navigating to its directory, and then simply writing a pip install command:

```
pip install .
````

This will install all the required packages for the QDTS orchestrator and the QDTS orchestrator itself.

To build applications on the QKD network digital twin environment, the client package needs to be installed in the device that will act as a network client. This can be done via pip:

```
pip install qdts-client
```

The QDTS node package will be automatically installed on the machines that will be QKD network nodes by the QDTS orchestrator.

## Manual Build

### QKD network over a pre-deployed machine pool

To deploy a digital twin of a QKD network on a pre-deployed machine pool, the orchestrator device is required to be able to make ssh connections with the machines that will act as QKD nodes. These machines have to count with a modern version of Python 3, as well as pip.

The QDTS orchestrator package has to be installed in the orchestrator device. Then, two files have to be written: the config.yaml file, and the inventory.yaml file. An example of these documents can be found in the [functional test](https://github.com/Networks-it-uc3m/QDTS/tree/main/functional_test) folder. 

The config.yaml file must contain:

- The service version (version 0.1.0 is, for now, the only version).
- The API used by the QKD nodes (currently only the [ETSI GS QKD 004 V2.1.1](https://www.etsi.org/deliver/etsi_gs/QKD/001_099/004/02.01.01_60/gs_qkd004v020101p.pdf) is supported).
- The QKD protocol used to form the keys (0.1.0 version implements the E91 protocol).
- The node names along with their IP addresses, and their neighbours.

The inventory.yaml file must contain:

- The IP address of each node.
- The ssh credentials for each machine.
- The directory where Python is installed.

Then, the QDTS orchestrator must be executed from the device of the network orchestrator, along with these two files. 

```
python qdts_orchestrator config.yaml inventory.yaml
```

This command will install the QDTS node software in each node, and start the emulation of the different channels, using SimulaQron, to connect the nodes as described in the configuration file. 

From this point on, the network is operational to run client applications.

### QKD network using OSM

The QDTS orchestrator package has to be installed in the orchestrator device. This method also uses as input a config.yaml file and a inventory.yaml file, to provide the QDTS orchestrator with the topology of the desired QKD network. However, in this case, it is not necessary to include the IP addresses in either of the documents, as the OSM implementation will provide this information. Therefore, the IP address variable in the documents can remain empty or with any IP, since it will be ignored.

To deploy the QKD network without a pre-deployed machine pool, the [OSM client package](https://osm.etsi.org/docs/user-guide/latest/03-installing-osm.html) needs to be installed in the orchestrator device. Then, the QDTS orchestrator can be executed including "OSM" behind the configuration and inventory file, along with a VIM account, and the ssh credentials so that OSM can connect to the machines.

```
python qdts_orchestrator config.yaml inventory.yaml OSM vim_account ssh_credentials
```

This command will instantiate the virtual machines required to deploy a digital twin of the QKD network described in the configuration file,  install the QDTS node software in each node, and start the emulation of the different channels, using SimulaQron, to connect the nodes as described in the configuration file.

From this point on, the network is operational to run client applications.

