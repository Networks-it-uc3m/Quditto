import sys

import netsquid as ns
import numpy as np
from bb84.basic_protocol import BasicProtocol
from nodes.qkd_node import QKDNode
from netsquid.protocols import Signals
from numpy.random import randint
from netsquid.qubits import qubitapi as qapi
import netsquid.components.instructions as instr
#We distinguish between Sender and Receiver

class SenderProtocol(BasicProtocol):
    def __init__(self, n, s, strategy = 1/3, *args, **kwargs):
        # Call the constructor of the base class
        super().__init__(*args, **kwargs)
        # Validate the type of the node
        #if not isinstance(self.node, QKDNode):
            #raise TypeError(f"Expected a QKDNode instance, but got {type(self.node).__name__}")
        self.n = n #initial photons sent
        self.estimated_qber = None
        self.s = s #send rate
        self.intermediate_key_length_1 = None
        self.intermediate_key_length_2 = None
        self.raw_key = None
        self.strategy = strategy #Parameter estimation strategy
        """
        strategy = 1/3 is the average situation
        strategy = f serves for other fractions for the sample size. MAX IS O.5
        strategy =[1, A] or [0.5, A/sqrt(n_lim)] for more complex sample strategies
        """

    def run(self):
        n = self.n
        s=self.s
        c_port = self.node.ports["c_channel"]
        GD_A = self.node.properties["gate_duration"]
        
        #1. Generate initial key and basis
        alice_key = randint(2, size=n)
        alice_bases = randint(2, size=n)

        #2. Greetings and inform about send rate, Alice's name, Alice's gate duration and emission efficiency
        c_port.tx_output(["Hello Bob!", s, self.node.name, GD_A, self.node.properties["emission_efficiency"]])
        yield self.await_port_input(c_port)
        complete_message = c_port.rx_input().items
        all_good =  complete_message[1] #Bob informs if the sending rate is fine.
        receiver_name = complete_message[2]

        #3. Quantum phase
        if not all_good:
            print(f"\n2. {self.node.name} at {ns.sim_time():.2f}. Rate too high, windows overlapping, abort protocol!!")
        else:
            wait_time = ns.sim_time()/2
            for i in range(0,n):
                qubit = qapi.create_qubits(1)
                self.node.qmemory.put(qubit, positions = [0])
                if alice_key[i] == 1:
                    self.node.qmemory.execute_instruction(instr.INSTR_X, [0])
                    yield self.await_program(self.node.qmemory)
                else:
                    yield self.await_timer(GD_A)
                if alice_bases[i] == 1:
                    self.node.qmemory.execute_instruction(instr.INSTR_H, [0])
                    yield self.await_program(self.node.qmemory)
                else:
                    yield self.await_timer(GD_A)
                
                self.node.qmemory.pop([0], positional_qout = False)
                yield self.await_timer(s-2*GD_A)

            yield self.await_timer(wait_time)
            c_port.tx_output("I finished sending qubits")
        
            #4. Wait for Bob to announce registered qubits
            yield self.await_port_input(c_port) #Bob will send the time slots a qubit was registered
            bob_received = c_port.rx_input().items[0]

            #5. Eliminate positions for which Bob did not record photon
            alice_key = list(self.pop_elements(alice_key, bob_received))
            alice_bases = self.pop_elements(alice_bases, bob_received)
        
            #6. Send bases to Bob
            c_port.tx_output(alice_bases)
            alice_bases = list(alice_bases)
        
            #7. Wait for Bob bases
            yield self.await_port_input(c_port)
            bob_bases = c_port.rx_input().items[0]
            bob_bases = list(bob_bases)
    
            #8. Remove garbage from bases
            alice_key2 = self.sift(alice_bases, bob_bases, alice_key)
            c_port.tx_output("Alice key ready")
            yield self.await_port_input(c_port)
            #print("Key length: ", len(alice_key2))
            self.intermediate_key_length_1 = len(alice_key)
            self.intermediate_key_length_2 = len(alice_key2)

            #9 Calculate error rate
            if isinstance(self.strategy, (int, float)):
                error_estimation_size = int(len(alice_key2)*self.strategy)
            elif isinstance(self.strategy, list) and self.strategy[0] == 0.5:
                error_estimation_size = int(self.strategy[1]*np.sqrt(len(alice_key2))) #In this situations, extra constraits exist
            elif isinstance(self.strategy, list) and self.strategy[0] == 1.0:
                error_estimation_size = int(self.strategy[1]) #In this situation, we choose a fixed number of bits. Extra constraits exist

            bit_selection = randint(n, size=error_estimation_size)
            c_port.tx_output(bit_selection)
            alice_sample = self.sample_bits(alice_key2, bit_selection)

            yield self.await_port_input(c_port)
            bob_sample = c_port.rx_input().items
            err = self.error_rate(alice_sample, bob_sample)
            #KBR_t = self.H2(err)*(1 - P0)* (10**(-R/10*wait_time*1e-9*0.5*300000))/(3*s)*1e9 #key bits/second
            #KBR_e = self.H2(err)*len(alice_key2)/(ns.sim_time())*1e9
            c_port.tx_output("Error rate is estimated")
            self.node.connections[receiver_name].key_memory

            #self.save_key(alice_key2, receiver_name)
            self.raw_key = alice_key2

            self.estimated_qber = err
            #print("Alice final key: ", self.node.connections[receiver_name].get_key(0))
            self.send_signal(Signals.SUCCESS, err)
            