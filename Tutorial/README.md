# Quditto Tutorial: Your First QKD Digital Twin Network

This tutorial is designed to help you create and test your first Quantum Key Distribution (QKD) digital twin network using Quditto.

A simple three-node topology is used: **B–A–C**, with an **eavesdropper placed between A and C**. The tutorial walks you through several key exchange scenarios to explore both normal operation and compromised links.

<img alt="Quditto network" src="Images/quditto_tutorial_network.png" height="100">



##  Tutorial Setup Steps

1. **Select Devices**  
   Choose at least **three Python-capable devices** accessible via SSH and with pip to act as the distributed nodes.  
   >  *Note: The Quditto orchestrator and controller can run on any of the nodes—no dedicated machine is required.*

   In the provided YAML example, the controller runs on **node A**.

2. **Edit the Configuration YAML**  
   - Update the **IP addresses** to match your device setup.  
   - Add your **NetSquid credentials** (username and password).

3. **Edit the Inventory YAML**  
   - Update the **IP addresses** again.  
   - Add the **SSH credentials** and the path to the Python interpreter on each device.

4. **Deploy the Orchestrator**  
   - Choose a device connected to the network to act as the orchestrator (it can be one of the nodes).  
   - Clone or copy the Quditto repository to that device.  
   - Navigate to the Quditto folder and run:  
     ```bash
     pip install qd2_orchestrator
     ```
   - From a terminal, go to the folder containing the tutorial YAML files and start the orchestrator:
     ```bash
     qd2_orchestrator start config.yaml inventory.yaml
     ```

5. **Run the Test Client**  
   - On any terminal with access to the nodes' network (acting as the client), run the test script:
     ```bash
     ./client.sh
     ```


##  What Happens During the Tutorial

### 1.  Key Exchange: Node A ↔ Node B

- A key request is initiated to **node A** for a key with **node B**.
- You retrieve the key and the **key ID** from A.
- Using the key ID, you retrieve the same key from **node B**. If both keys match, the exchange was successful and **no eavesdropping** occurred.
- Then, you try retrieving a key from **B using a fake key ID**. This should fail, confirming the system validates key identifiers.


### 2.  Eavesdropped Exchange: Node A ↔ Node C

- A key request is initiated to **node C** for a key with **node A**.
- You retrieve the key and key ID from C.
- Using the key ID, you retrieve the key from **A**. The two keys **do not match**, indicating the presence of an **eavesdropper** on the A–C link.



### 3.  Non-Neighbor Exchange: Node B ↔ Node C

- You try to initiate key requests between **nodes B and C** (both directions). The system replies that **no such neighbor exists**.
>  *Note: This limitation can be addressed by implementing a Key Management Entity (KME) script that performs quantum key relaying via node A as a trusted node, but this is not directly supported by Quditto.*




