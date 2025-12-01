import sys
import netsquid as ns
import numpy as np
from netsquid.protocols import Signals
from bb84.basic_protocol import BasicProtocol
from nodes.receiver_node import ReceiverNode
from numpy.random import randint
import netsquid.components.instructions as instr

class ReceiverProtocol(BasicProtocol):
    def __init__(self, n, P_extra, covery_factor, *args, **kwargs):
        # Call the constructor of the base class
        super().__init__(*args, **kwargs)
        #if not isinstance(self.node, ReceiverNode):
            #raise TypeError(f"Expected a ReceiverNode instance, but got {type(self.node).__name__}")
        self.n = n
        self.p_extra = P_extra
        self.covery_factor = covery_factor
        self.raw_key = None
        
    def run(self):
        detector = self.node.subcomponents["QDetector"]
        n = self.n
        C = self.covery_factor
        DCR = self.node.properties["DCR"]*1e-9 #transformamos a counts/ns
        DT = self.node.properties["dead_time"]
        DD = self.node.properties["detector_delay"]
        GD_B = self.node.properties["gate_duration"]
        c_port = self.node.ports["c_channel"]
        
        #1. Generate initial key (empty) and basis
        bob_key = []
        bob_received =  np.ones(n) #Time slots Bob actually measured something
        bob_bases = randint(2, size=n)

        #2. Greetings
        yield self.await_port_input(c_port)
        complete_message = c_port.rx_input().items
        s = complete_message[1] #ns. Rate at which Alice sends photons. It is bounded by Bob's dead time
        sender_name = complete_message[2]
        GD_A = complete_message[3]
        emission_efficiency = complete_message[4]

        P0 = 1 - emission_efficiency * self.node.properties["detection_efficiency"]
        std = self.node.connections[sender_name].std 
        f = self.node.connections[sender_name].speed_fraction
        R = self.node.connections[sender_name].p_loss_length
        d = self.node.connections[sender_name].distance 
        vf = f*300000
        wait_time = d/vf * 1e9 #Time distance separating Alice and Bob (ns)
        qubits_received = 0
        s_lim = max(2*GD_A, 2*C*std*wait_time + DT + DD + GD_B)
        if s < s_lim:
            c_port.tx_output(["Hello Alice!",False, self.node.name])
        else:
            c_port.tx_output(["Hello Alice!",True,self.node.name])
            yield self.await_timer(duration = 2*GD_A + wait_time*(2-C*std))
            P = 1 - np.exp(-DCR*2*C*std*wait_time)  #DCR is already in counts/ns (1-np.exp(-DCR*2*C*std*d/vf))
            #print(f"2. {self.node.name} at {ns.sim_time():.2f}. Probability of getting a dark count: {P:.2e}")
            #print(f"2. {self.node.name} at {ns.sim_time():.2f}. Probability of survival the channel: {P2:.2e}")
            Bob_waits_less = 0
            self.node.ports['q_channel'].disconnect() #WE INITIALLY DISCONNECT. WE ONLY CONNECT PORTS DURING TIME WINDOW IN ORDER TO AVOID INFERENCE OF LATE ARRIVING PHOTONS
            for i in range(0,n):
                t = np.random.uniform(ns.sim_time(), ns.sim_time() + wait_time*(2*C*std)) #time for which we receive the supposed dark count
                self.node.supercomponent.subcomponents['conn|Alice<->Bob|quantum'].port_B.connect(self.node.ports['q_channel'])#WE CONNECT
                yield self.await_port_input(self.node.ports['q_channel'])  | self.await_timer(wait_time*(2*C*std) - Bob_waits_less)
                self.node.ports['q_channel'].disconnect() #WE DISCONNECT
                a = np.random.binomial(n=1, p=P) #Do we get a dark count at time t?
                if a == 1 and t<ns.sim_time():
                    # Dark count detected first
                    b = np.random.choice([0, 1])
                    bob_key.append(b)
                    #print("DCR")
                else:
                    if self.node.qmemory.mem_positions[0].is_empty:
                        #print(f"BOB at {ns.sim_time():.2f}: Qubit {i} PERDIDO.\n")
                        bob_received[i] = 0
                        self.await_timer(GD_B+DD)                        
                    else:
                        #print(f"BOB at {ns.sim_time():.2f}: Qubit {i} recibido.")
                        if bob_bases[i] == 1:
                            self.node.qmemory.execute_instruction(instr.INSTR_H, [0])
                            yield self.await_program(self.node.qmemory)
                        else:
                            yield self.await_timer(GD_B)
                        self.node.qmemory.pop([0])
                        #print(f"BOB at {ns.sim_time():.2f}: Qubit {i} operado.")
                        yield self.await_port_output(detector.ports['cout0'])
                        k = detector.ports['cout0'].rx_output().items[0]
                        bob_key.append(k)
                        #print(f"BOB at {ns.sim_time():.2f}: Qubit {i} medido: {k}.\n")
                        qubits_received+=1
                        
                    if not self.node.qmemory.mem_positions[0].is_empty: #El qubit puede haber llegado una vez ya habíamos cerrado la ventana
                        self.node.qmemory.discard([0], check_positions = False)
                delta_i = 2*GD_B + 3*wait_time + i*s - ns.sim_time() #Así, Bob se recupera a cada paso de la desviación entre el tiempo de detección real y el esperado
                rec_time = max(0,s + delta_i - C*std*wait_time)
                if rec_time > 0:
                    yield self.await_timer(duration = rec_time) #Esperamos a que se abra la ventana de llegada, contando la std
                    Bob_waits_less = 0
                else:
                    Bob_waits_less = ns.sim_time() - (3*wait_time + (i+1)*s - C*std*wait_time)
                    #print("OJO: ",Bob_waits_less)

            yield self.await_port_input(c_port) #Wait until alice finishes sending qubits
            c_port.tx_output(bob_received)  # send message to Alice
            bob_bases = self.pop_elements(bob_bases, bob_received)
            if len(bob_bases) == 0:
                raise ValueError("Bob did not measure any quantum signal...")
            #3. Wait for Alice bases
            yield self.await_port_input(c_port)
            alice_bases = c_port.rx_input().items[0]

            #4. Send used bases to Alice
            c_port.tx_output(bob_bases)
            bob_bases = list(bob_bases)
    
            #5. Remove garbage from bases
            yield self.await_port_input(c_port)
            bob_key2 = self.sift(alice_bases, bob_bases, bob_key)

            #6. Add extra noise
            flip_mask = np.random.rand(len(bob_key)) < self.p_extra
            # Apply flip: XOR each bit with the mask
            bob_key2 = [bit ^ flip for bit, flip in zip(bob_key2, flip_mask)]

            #7. Parameter estimation
            c_port.tx_output("Bob key ready")
            yield self.await_port_input(c_port)
            bit_selection = c_port.rx_input().items[0]
            bob_sample = self.sample_bits(bob_key2, bit_selection)
            c_port.tx_output(bob_sample)
            yield self.await_port_input(c_port)

            #self.save_key(bob_key2, sender_name)
            self.raw_key = bob_key2

            #print("Bob final key:   ", self.node.connections[sender_name].key_memory[0])
            self.send_signal(Signals.SUCCESS)