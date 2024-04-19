# Functional test

This folder contains a functional test for *Quditto*. 

## Description

The test runs over a digital twin of a three-node QKD network. It opens 4 different key streams, each one with a unique ID (three of them randomly generated and one of them specified by the client). Then, the test retrieves and compares keys exchanged by the QKD node pairs, verifying that they are indeed the same. Lastly, the key streams are closed.

This test checks that the three functions defined in the [ETSI QKD 004 interface](https://portal.etsi.org/webapp/workprogram/Report_WorkItem.asp?WKI_ID=54395), *open_connect*, *get_key*, and *close*, are supported. 

## Execution manual

### Prerequisites

The test has been designed to run over 4 machines. One of the machines corresponds to the orchestrator device and will also function as the tester's workstation (client of the QKD network). The other three will act as the quantum nodes of the QKD network digital twin.

The configuration files assume the three QKD node machines have the following IP addresses:

- 10.4.16.115
- 10.4.16.74
- 10.4.16.132

However, if your machines have different addresses, you can replace them in the following files:

- config.yaml
- functional_test.py
- inventory.yaml

Both the tester's workstation and the QKD node machines must have a modern version of Python 3. The path where Python 3 can be found in the QKD node machines has to be indicated in the *inventory.yaml* file.

Additionally, modify the *inventory.yaml* file if needed with the data from your machines.

The *qd2_orchestrator* and the *qd2_client* packages must be installed in the tester's workstation. Please, refer to the main page [README](https://github.com/Networks-it-uc3m/QDTS/blob/main/README.md) to see instructions on this matter.

### Execution

All the commands must be executed from the tester's workstation and in the directory that contains the [functional_test](https://github.com/Networks-it-uc3m/QDTS/tree/main/functional_test) folder.

1. Execute the following command to deploy the network
   ```
   qd2_orchestrator start config.yaml inventory.yaml
   ```
2. Execute the test with the following command
   ```
   python3 functional_test.py
   ```
3. Verify all the tests run and the message "ALL TESTS OKAY!" is shown
   
