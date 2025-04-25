import random
import netsquid as ns
import numpy as np
import sys
import json
import netsquid.components.instructions as instr
from netsquid.nodes import Node, Network, DirectConnection
from netsquid.components import QuantumChannel, QuantumProgram, ClassicalChannel, FibreDelayModel
from netsquid.protocols import NodeProtocol, Signals
from netsquid.components.models.qerrormodels import DepolarNoiseModel, DephaseNoiseModel, FibreLossModel
from netsquid.components.qprocessor import QuantumProcessor, PhysicalInstruction
import logging

logging.basicConfig(
    filename='bb84_eve_percentage.log',         
    level=logging.INFO,                
    format='%(asctime)s - %(levelname)s - %(message)s'  
)




class Encode(QuantumProgram):
    """
    Program to encode a bit according to a secret key and a basis.
    """

    default_num_qubits = 1

    def __init__(self, base, bit):
        super().__init__()
        self.base = base
        self.bit = bit

    def program(self):
        q1, = self.get_qubit_indices(1)
        self.apply(instr.INSTR_INIT, q1) # by default en estado |0>
        if self.bit == 1:
            self.apply(instr.INSTR_X, q1) # si el bit es 1 lo convertimos en |1>
        if self.base == 1:
            self.apply(instr.INSTR_H, q1) # si la base es 1 lo convertimos en |+>,|->
        yield self.run()



class KeyReceiverProtocol(NodeProtocol):
    """
    Protocol for the receiver of the key.
    """

    def __init__(self, node, key_size=10, port_names=("qubitIO_b", "classicIO")):
        super().__init__(node)
        self.node = node
        self.q_port = port_names[0]
        self.c_port = port_names[1]
        self.key_size = key_size
        self.key = None

    def run(self):
        # Select random bases to measure in
        bases = np.random.randint(2, size=self.key_size)
        results = []
        for i in range(self.key_size):
            # Await a qubit from Eve
            yield self.await_port_input(self.node.ports[self.q_port])
            
            # Measure in random basis
            if bases[i] == 0:
                res = self.node.qmemory.execute_instruction(instr.INSTR_MEASURE, output_key="M")
            else:
                res = self.node.qmemory.execute_instruction(instr.INSTR_MEASURE_X, output_key="M")
            yield self.await_program(self.node.qmemory)
            results.append(res[0]['M'][0])
            self.node.qmemory.reset()

            # Send ACK to Alice to trigger next qubit send (except in last transmit)
            if i < self.key_size - 1:
                self.node.ports[self.c_port].tx_output('ACK')

        # All qubits arrived, send bases
        self.node.ports[self.c_port].tx_output(bases)

        # Await matched indices from Alice and process key
        yield self.await_port_input(self.node.ports[self.c_port])
        matched_indices = self.node.ports[self.c_port].rx_input().items
        final_key = []
        for i in matched_indices:
            final_key.append(results[i])
        self.key = final_key
        self.send_signal(signal_label=Signals.SUCCESS, result=final_key)

        



class EavesdropperProtocol(NodeProtocol):
    """
    Protocol for the eavesdropper
    """

    def __init__(self, node, key_size=10, port_names=("qubitIO_e1", "qubitIO_e2"),percentage=50):
        super().__init__(node)
        self.node = node
        self.q_port_a = port_names[0]
        self.q_port_b = port_names[1]
        self.key_size = key_size                                                                                                                                                                                                                                                                                                                                                                                                                               
        self.percentage = percentage
        self.spied_bits_size = int(key_size*percentage/100)
        self.key = None


    def run(self):
        # Select randomly the bits to spy
        spied_bits = np.random.choice(np.arange(self.key_size), size=self.spied_bits_size, replace=False)

        # Select random bases to measure in
        bases_measure = np.random.randint(2, size=self.spied_bits_size)

        #Select random bits to send to Bob and bases to encode them
        bits = np.random.randint(2, size=self.spied_bits_size)
        bases_encode = list(np.random.randint(2, size=self.spied_bits_size))

        counter = 0 # to count the bits you spy

        for i in range(self.key_size):
            
            # Await a qubit from Alice
            yield self.await_port_input(self.node.ports[self.q_port_a])
            
            # Check if Eve has to spy this bit
            if i in spied_bits:
                # Measure in random basis
                if bases_measure[counter] == 0:
                    res = self.node.qmemory.execute_instruction(instr.INSTR_MEASURE, output_key="M")
                else:
                    res = self.node.qmemory.execute_instruction(instr.INSTR_MEASURE_X, output_key="M")
                yield self.await_program(self.node.qmemory)
                self.node.qmemory.reset()

                self.node.qmemory.execute_program(Encode(bases_encode[counter], bits[counter]))
                yield self.await_program(self.node.qmemory) # tells the protocol to pause
                                                        # its execution until the specified
                                                        #  quantum program has finished running on the memory
                qubit = self.node.qmemory.pop(0) # we get from the memory the qubit to send it to bob
                self.node.ports[self.q_port_b].tx_output(qubit)

                counter += 1

            
            else:
                qubit = self.node.qmemory.pop(0)  # Retrieve the qubit from memory
                self.node.ports[self.q_port_b].tx_output(qubit)
                self.node.qmemory.reset()

            


class KeySenderProtocol(NodeProtocol):
    """
    Protocol for the sender of the key.
    """

    def __init__(self, node, key_size=10, port_names=("qubitIO_a", "classicIO")):
        super().__init__(node)
        self.node = node
        self.q_port = port_names[0]
        self.c_port = port_names[1]
        self.key_size = key_size
        self.key = None

    def run(self):
        secret_key = np.random.randint(2, size=self.key_size)
        bases = list(np.random.randint(2, size=self.key_size))

        # Transmit encoded qubits to Bob
        for i, bit in enumerate(secret_key):
            self.node.qmemory.execute_program(Encode(bases[i], bit))
            yield self.await_program(self.node.qmemory) # tells the protocol to pause
                                                        # its execution until the specified
                                                        #  quantum program has finished running on the memory

            q = self.node.qmemory.pop(0) # we get from the memory the qubit to send it to bob
            self.node.ports[self.q_port].tx_output(q)
            if i < self.key_size - 1:
                yield self.await_port_input(self.node.ports[self.c_port]) # espera el ACK de bob
                

        # Await response from Bob (about the bases)
        yield self.await_port_input(self.node.ports[self.c_port])
        bob_bases = self.node.ports[self.c_port].rx_input().items[0]
        matched_indices = []
        for i in range(self.key_size):
            if bob_bases[i] == bases[i]:
                matched_indices.append(i)

        self.node.ports[self.c_port].tx_output(matched_indices)
        final_key = []
        for i in matched_indices:
            final_key.append(secret_key[i])
        self.key = final_key
        self.send_signal(signal_label=Signals.SUCCESS, result=final_key) # use this signal to end protocol





# Ruido memoria? Ruido medir?
def create_processor():
    """Factory to create a quantum processor for each end node.

    Has one memory positions and the physical instructions necessary
    for teleportation.
    """
    physical_instructions = [
        PhysicalInstruction(instr.INSTR_INIT, duration=3, parallel=True),
        PhysicalInstruction(instr.INSTR_H, duration=68, parallel=True),
        PhysicalInstruction(instr.INSTR_X, duration=68, parallel=True),
        PhysicalInstruction(instr.INSTR_Z, duration=68, parallel=True),
        PhysicalInstruction(instr.INSTR_MEASURE, duration=1000, parallel=False),
        PhysicalInstruction(instr.INSTR_MEASURE_X, duration=1068, parallel=False)
    ]
    processor = QuantumProcessor("quantum_processor",
                                 memory_noise_models=DepolarNoiseModel(depolar_rate=1e7),
                                 phys_instructions=physical_instructions)
    return processor



def generate_network(length, eve_distance, attenuation=0):
    """
    Generate the network. For BB84, with an eavesdropper we need 2 quantum
    channels (one between Alice and Eve and another one between Eve and Bob)
    and classical channel between Alice and Bob.

    The network is generated in a way that it doesn't matter if Alice is the
    sender and Bob the receiver or viceversa.
    """
    eve_distance_bob = length-eve_distance

    network = Network("BB84 Network")
    alice = Node("alice", qmemory=create_processor())
    bob = Node("bob", qmemory=create_processor())
    eve = Node("eve",qmemory=create_processor())

    network.add_nodes([alice, bob, eve])

    loss_model = FibreLossModel(p_loss_init=0, p_loss_length=attenuation)

    # Quantum channel Alice-Eve
    p_ae, p_ea = network.add_connection(alice,
                                        eve,
                                        label="q_chan_AE",
                                        channel_to=QuantumChannel("AqE", length=eve_distance, models={"delay_model": FibreDelayModel(), "quantum_loss_model": loss_model}),
                                        channel_from=QuantumChannel("EqA", length=eve_distance, models={"delay_model": FibreDelayModel(), "quantum_loss_model": loss_model}),
                                        port_name_node1="qubitIO_a",
                                        port_name_node2="qubitIO_e1")
    
    # Quantum channel Eve-Bob
    p_eb, p_be = network.add_connection(eve,
                                    bob,
                                    label="q_chan_EB",
                                    channel_to=QuantumChannel("EqB", length=eve_distance_bob, models={"delay_model": FibreDelayModel(), "quantum_loss_model": loss_model}),
                                    channel_from=QuantumChannel("BqE", length=eve_distance_bob, models={"delay_model": FibreDelayModel(), "quantum_loss_model": loss_model}),
                                    port_name_node1="qubitIO_e2",
                                    port_name_node2="qubitIO_b")
    
    # Map the qubit input ports
    alice.ports[p_ae].forward_input(alice.qmemory.ports["qin0"]) # bob sender
    eve.ports[p_ea].forward_input(eve.qmemory.ports["qin0"]) # alice sender

    eve.ports[p_eb].forward_input(eve.qmemory.ports["qin0"]) # bob sender
    bob.ports[p_be].forward_input(bob.qmemory.ports["qin0"]) # alice sender


    # Classical channel Alice-Bob
    network.add_connection(alice,
                           bob,
                           label="c_chan",
                           channel_to=ClassicalChannel('AcB', length=length, models={"delay_model": FibreDelayModel()}),
                           channel_from=ClassicalChannel('BcA', length=length, models={"delay_model": FibreDelayModel()}),
                           port_name_node1="classicIO",
                           port_name_node2="classicIO")
    return network


def calculate_qber(bits1, bits2):
    n = len(bits1)
    error = 0
    for i in range(n):
        if bits1[i] != bits2[i]:
            error += 1
    return error/n



def sample_bits(bits, selection):
    sample = []
    original = []
    for i in range(len(bits)):
        # use np.mod to make sure the
        # bit we sample is always in 
        # the list range
        i = np.mod(i, len(bits))

        if i in selection:
            sample.append(bits[i])
        
        else:
            original.append(bits[i])


    return sample, original


def bb84_key_perc(desired_key_length, link_length, distance_to_alice, percentage, attenuation=0, redundancy_rate=2):
    key_length = 2*desired_key_length # half is sacrified for calculating QBER
    alice_key = []
    bob_key = []
    simulated_time = 0
    repetitions = 0

    
    # Repeat the protocol until we get enough bits
    while len(alice_key) < key_length or len(bob_key) < key_length:
        repetitions += 1

        # LOG INFO: Iniciar repetición del protocolo
        logging.info(f"Starting protocol repetition {repetitions}")

        # Calculate how many qubits to generate based on the redundancy rate
        n_qubits = int(key_length * redundancy_rate)

        # LOG DEBUG: Número de qubits que se usarán
        logging.debug(f"Generating {n_qubits} qubits for redundancy")

        # Generate the network and protocols
        n = generate_network(length=link_length, eve_distance=distance_to_alice, attenuation=attenuation) 
        node_a = n.get_node("alice")
        node_b = n.get_node("bob")
        node_e = n.get_node("eve")

        p1 = KeySenderProtocol(node_a, key_size=n_qubits)
        p2 = KeyReceiverProtocol(node_b, key_size=n_qubits)
        p3 = EavesdropperProtocol(node_e, key_size=n_qubits, percentage=percentage)

        # Start protocols
        p1.start()
        p2.start()
        p3.start()

        # Run simulation and collect stats
        stats = ns.sim_run()

        # Append the new part of the key generated
        if p1.key and p2.key:
            alice_key.extend(p1.key)
            bob_key.extend(p2.key)

            # LOG INFO: Show accumulated key lengths
            logging.info(f"Accumulated key lengths -> Alice: {len(alice_key)}, Bob: {len(bob_key)}")
        
        simulated_time += float(stats.timeline_status().split()[2])
        
        # Reset the simulation for the next run if needed
        ns.sim_reset()

    alice_key= alice_key[:key_length]
    bob_key= bob_key[:key_length]


    # Calculate QBER once we have the full key (half for QBER half for key)

    bit_selection = random.sample(range(key_length), desired_key_length) 

    alice_for_qber, alice_final_key = sample_bits(alice_key, bit_selection)
    bob_for_qber, bob_final_key = sample_bits(bob_key, bit_selection)

    qber = calculate_qber(alice_for_qber, bob_for_qber)

    # LOG INFO: Show QBER and final metrics
    logging.info(f"QBER: {qber:.4f}, Total simulated time: {simulated_time:.2f} ns, Repetitions: {repetitions}")
    

    return alice_final_key, bob_final_key, qber, simulated_time, repetitions



def main():
    if len(sys.argv) == 5:
        desired_key_length = int(sys.argv[1])
        link_length = float(sys.argv[2])
        distance_to_alice = float(sys.argv[3])
        percentage = float(sys.argv[4])
    
    alice_final_key, bob_final_key, qber, simulated_time, repetitions = bb84_key_perc(desired_key_length, link_length, distance_to_alice, percentage)

    simulated_time=simulated_time/10**9
    alice_final_key = [int(x) for x in alice_final_key]
    bob_final_key = [int(x) for x in bob_final_key]

    result = {"alice_key": alice_final_key, "bob_key": bob_final_key, "time": simulated_time}

    print(json.dumps(result))


if __name__ == "__main__":
    main()