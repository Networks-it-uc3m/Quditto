# Non-ideal-QKDNs
Using NetSquid, we provide a framework for simulating non ideal quantum communications and quantum cryptographic protocols.

## 💻 Environment

This codebase was developed and tested with the following setup:

- **Python version**: 3.8.19
- **Operating System**: macOS Sonoma 14.5

### 📦 Key Dependencies

Standard libraries (no need to install):
- `random`, `copy`, `typing`

Third-party libraries:
- `numpy` – numerical computing (1.24.4)
- `scipy` – scientific computing and optimization (scipy.optimize) (1.9.3)
- `pydynaa` – event-driven simulation (1.0.2)
- `NetSquid` – quantum network simulator ([installation instructions](https://www.netsquid.org/)) (1.1.7)
- [`cryptomyte.trevisan`](https://github.com/CQCL/cryptomite) – randomness extractor (Trevisan)
- [`cascade-python`](https://github.com/brunorijsman/cascade-python) – error correction protocol

To install the Python packages (except NetSquid), run:

```bash
pip install -r requirements.txt
```

## 📁 Project Structure and Module Descriptions

![Project Structure](images/diagram.jpg)

### 📄 `fake_qkd.py`

This module implements a **mock BB84 protocol** used for testing and simulation purposes. It mimics the behavior of a quantum key distribution session without invoking actual BB84 operations implemented in NetSquid. Useful for validating network flow, timing, or component integration in the absence of quantum backends.

**Main features:**
- `fake_QKD` main function: Simulates a fake QKD session between two nodes. Implements the BB84 protocol, but "skips" the quantum communication part. We simulate all sources of noise and randomness with properly implementing them, as we do when using NetSquid.
- Functions to imitate key generation and communication delays: `generate_binary_list`, `calculate_error_rate`, `parameter_estimation`, `apply_loss_and_noise`

---

### 📄 `math_tools.py`

A collection of **mathematical utility functions** used throughout the simulation. This include calculating relevant probabilities to model noise and loses, estimating fundamental parameters to test the behavior of the QKD protocol (KBR, QBER, limit distance) or calculating the minimum photons needed to meet output key length requirements posed by the user. This is the implementation of our theoretical analysis.

**Key functions:**
- `H(p)`: Binary Shannon entropy.
- `P_Loss()`, `P_Depolar()`, `P_DCR()`: Models for loss, depolarization, and dark count rates.
- `expected_qber()`: Estimates QBER under noisy conditions. Specifically, this function calculates the probability of a bit flip occurring between Alice's and Bob's raw keys.
- `expected_KBR`: This function estimates the KBR, given as number of output bits per quantum channel usage, for a given set of parameters. It also estimates the standard deviation of this quantity according to our theoretical analysis.
- `m_solution`: Finds the value for m, the output key length after applying the Trevisan extractor, solving the implicit equation for this variable. For that purpose, `scipy.fsolve` is used.
- `limit_distance`: Calculates the maximum distance for which a non-zero secret key can be obtained after executing the protocol. This is obtained for a given set of parameters.
- `get_minimum_photons`: Estimate the minimum number of photons required to generate a secure key of length M over a quantum link with given physical parameters. This function allows to set the preferred paramater estimation strategy.

---

### 📄 `network.py`

This module defines the **network-level architecture and delay model** for the QKD simulation environment. It sets up the topology, timing behavior, and node interconnections required to simulate realistic quantum communication scenarios.

**Main components:**
- `QKDNetwork` class: Manages the creation and connection of QKD nodes across a simulated network in NetSquid.
- `GaussianDelayModel` class: Introduces realistic communication delays for the quantum channel based on a Gaussian distribution, mimicking latency in optical fiber links.

This module is central to initializing the simulated environment used by the BB84 and fake QKD protocols.

---

### 📁 `nodes/`

This folder contains classes that represent **different types of QKD nodes** (distinguishing between sender and receiver) and supporting logic for communication and protocol coordination. These nodes form the building blocks of the network simulation and are instantiated by the `network.py` module.

#### 📄 `qkd_node.py`
Defines a generic **QKD-capable node** that can send quantum states. Acts as a base class for specialized receiver implementations.

- `create_qprocessor` Function: This function creates a quantum processor for QKD tasks. It has a single memory unit and noise models for the quantum gates and quantum memory.
- `QKDNode` class: Represents a node in a quantum key distribution network, extending the NetSquid Node class.

#### 📄 `receiver_node.py`
ReceiverNode class inherits from QKDNode and represents a node in a Quantum Key Distribution (QKD) network specifically designed for receiving qubits. This class adds functionalities for incorporating a quantum detector and a property for the Dark Count Rate (DCR).

- `ReceiverNode` class: Inherits from `QKDNode` and configures the node to receive quantum and classical messages, and suffer from dark count rates.

#### 📄 `qkd_link_informer.py`

- `QKDLinkInformer` class: When a QKD connection is stablished, each one of the participating nodes gathers and stores knowledge about the link status, and also information about the other node. This can be modelized using this new class, to which both nodes will have access. Each node in the quantum network owns a dictionary of Link Informers, each one coresponding to a node which it is connected to. A Link Informer saves relevant information about the connection: includes the key memory for previusly shared keys between both parties, along with important parameters about the link, such as distance, std, attenuation rate, characteristic speed and depolar rate.

---

### 📁 `bb84/`

This folder contains the full implementation of the **BB84 quantum key distribution protocol**, split into modular components to separately handle protocol stages for the sender (Alice), receiver (Bob), and core logic. These modules work together to simulate a full BB84 session over a quantum network, driven by node behavior and network conditions.

#### 📄 `basic_protocol.py`
Defines common base functionality shared between the sender and receiver protocols.

- `BasicProtocol` class:  A base class for defining protocols with additional functionalities on top of NodeProtocol (NetSquid). These functionalities are shared between the sender and the receiver in a DV-QKD protocol.

  
#### 📄 `sender_protocol.py`
Implements the sender side (Alice) of the BB84 protocol.

- `SenderProtocol` class: Handles the generation of quantum bits, basis selection, and the transmission of quantum and classical messages to the receiver.

#### 📄 `receiver_protocol.py`
Implements the receiver side (Bob) of the BB84 protocol.

- `ReceiverProtocol` class: Handles quantum bit reception, basis measurement, sifting, and preparation for key reconciliation.

#### 📄 `bb84_protocol.py`
Combines the sender and receiver protocol logic into a unified BB84 setup.

**Main components:**
- `BB84Protocol` class: Manages full protocol orchestration between sender and receiver nodes. Instantiates `SenderProtocol` and `ReceiverProtocol`, handles timing, and initiates the key exchange process. Inherits LocalProtocol from NetSquid.
- `setup_datacontroller` function: Sets up a data collector for the BB84 protocol to gather key statistics, such as QBER and key rate. This function ensures that Alice and Bob nodes are correctly identified in the network, calculates the Quantum Bit Error Rate (QBER) and the expected key generation rate (KBR_exp), and collects relevant metrics during the protocol execution.
- `BB84_Experiment` function:     Executes only the quantum phase of hte BB84 quantum key distribution (QKD) experiment simulation using NetSquid. It is used to benchmark this part of the protocol, where NetSquid is involved.
- `FULL_BB84` function: Runs a full BB84 QKD experiment simulation using NetSquid, cascade-python and Cryptomite.trevisan. This function sets up a QKD network with two nodes (Alice and Bob), applies a specified strategy for parameter estimation, simulates quantum transmission, and performs post-processing (error correction and privacy amplification) to generate a final secret key.

