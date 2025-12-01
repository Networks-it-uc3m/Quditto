import sys

from nodes.qkd_node import QKDNode
from nodes.qkd_link_informer import QKDLinkInformer
from nodes.receiver_node import ReceiverNode
from netsquid.nodes import Network
from netsquid.components.models import DelayModel
from netsquid.components.models import FibreDelayModel, DepolarNoiseModel, FibreLossModel
from netsquid.components.qchannel import QuantumChannel
from netsquid.nodes import DirectConnection
from netsquid.components import ClassicalChannel
from copy import deepcopy

class GaussianDelayModel(DelayModel):
    """
    A delay model that simulates delays based on a Gaussian distribution 
    for speed, relative to the speed of light. 

    This class inherits from the `DelayModel` base class and overrides its
    `generate_delay` method to compute delays for a given length of transmission.

    Attributes:
    -----------
    properties : dict
        A dictionary containing model properties:
        - "speed": The average speed as a fraction of the speed of light (in km/s).
        - "std": The standard deviation for the Gaussian distribution of speed, relative to the average speed.

    required_properties : list
        A list of properties that need to be provided when the model is called.
        In this case, it requires:
        - "length" (in kilometers): The distance over which the signal propagates.

    Methods:
    --------
    __init__(speed_of_light_fraction, standard_deviation):
        Initializes the Gaussian delay model with the given speed fraction and 
        standard deviation, calculating the average speed in km/s.

    generate_delay(**kwargs):
        Overrides the base method to compute delay based on the Gaussian speed
        and the given length. The result is returned in nanoseconds.
    """
    def __init__(self, speed_of_light_fraction: float, standard_deviation: float):
        super().__init__()
        # (the speed of light is about 300,000 km/s)
        self.properties["speed"] = speed_of_light_fraction * 3e5 #km/s
        self.properties["std"] = standard_deviation
        self.required_properties = ['length']  # in km
        #required_properties are parameters that need to be passed to the model when the model is called.

    def generate_delay(self, **kwargs): #Overriden method
        avg_speed = self.properties["speed"]
        std = self.properties["std"]
        speed = self.properties["rng"].normal(avg_speed, avg_speed * std)
        delay = 1e9 * kwargs['length'] / speed  # in nanoseconds
        return delay
class QKDNetwork(Network):
    """
    A new class that aims to simulate the topology of QKD networks,
    stablishing quantum links between nodes.
    """
    def __init__(self, name, nodes=None):
          super().__init__(name, nodes)

    def inform_about_connection(self, Alice: QKDNode, Bob: QKDNode, link_info: QKDLinkInformer):
        """
        Both nodes are informed about the link status.
        """
        Alice.add_connection(Bob.name, deepcopy(link_info))
        Bob.add_connection(Alice.name, deepcopy(link_info))

    def set_simple_link(self, nodeA: QKDNode, nodeB: ReceiverNode, 
                distance: float, depolar_rate: float,
                distance_factor: float, classical_std: float,
                p_loss_length: float, std: float, speed_fraction: float):
        
        """
        For a QKD Network object, configures a quantum and classical link between two QKD nodes.

        This function establishes a quantum channel and a classical channel
        between `nodeA` (sender) and `nodeB` (receiver). The quantum channel is modeled using delay, noise, and loss models, 
        while the classical channel uses a fiber fixed delay model. The links are bound to the respective 
        ports of the nodes and their components.

        The sender can create qubits, while the receiver owns a quantum detector.

        Parameters:
        -----------
        nodeA : QKDNode
            The SENDER, the first quantum key distribution (QKD) node.
        nodeB : QKDNode
            The RECEIVER, the second quantum key distribution (QKD) node.
        distance : float
            The physical distance between the two nodes (in kilometers).
        p_loss_init : float
            Initial probability of losing a qubit at the start of the transmission.
            Set to account for transmission and detection inefficiencies. (e.g. 0.2)
        depolar_rate : float
            Exponential depolarizing rate per unit time (in Hz). (e.g., 5e7 Hz).
        distance_factor : float
            Ratio between the classical link length and the quantum link length. Default to 1.
        classical_std : float
            If 0 (default), classical link has a fixed delay model. Otherwise, we have a Gaussian delay model with its value as std.
            Used to simulate natural delays of classical Internet connection between both nodes.
        p_loss_length : float, optional
            Rate at which detection probability decreases with channel length (in dB/km). Default is 0.2.
        std : float, optional
            Relative standard deviation for the flight duration in the quantum channel. Default is 0.05.
        speed_fraction : float, optional
            Fraction of the speed of light for fiber-optic communication. Default is 2/3 (200,000 km/s).

        Typical Values (Example):
        ---------------
        1. Channel properties:
            - std = 0.02
            - classical_std = 0
            - distance_factor = 1
            - speed_fraction = 0.67
            - depolar_rate = 100 Hz
            - emission_efficiency = 0.2
            - detection_efficiency = 0.6
            - p_loss_length = 0.2 dB/km
        2. Other parameters:
            - covery_factor = 3
        3. Detector parameters:
            - DCR = 25 counts/s
            - detector_delay = 0.5 ns
            - dead_time = 100 ns
        4. Quantum processor parameters:
            - gate_duration = 1 ns
            - gate_noise_rate = 0 Hz

        Notes:
        ------
        -THIS FUNCTION ASSUMES FOR NOW AN EMPTY NETWORK
        - The quantum channel uses a Gaussian delay model for signal propagation delay and a depolarizing 
        noise model for qubit fidelity degradation.
        - Classical communication is modeled using a fiber delay model.
        - Classical link and quantum link have different lenngths according to distance_factor.
        - All properties are bound to the respective QKD nodes and are used during simulation.
        """

        vf = speed_fraction * 300000 #km/s

        #MODELS
        delay_model = GaussianDelayModel(speed_of_light_fraction=speed_fraction, standard_deviation=std)  #Gaussian delay for quantum light transmissions
        noise_model = DepolarNoiseModel(depolar_rate) #Noise model affecting qubits
        p_loss_init = 1 - nodeA.properties["emission_efficiency"] * nodeB.properties["detection_efficiency"]
        loss_model = FibreLossModel(p_loss_init = p_loss_init, p_loss_length = p_loss_length) #Qubit loss model in fiber
        
        #NODES
        self.add_nodes([nodeA, nodeB])

        #We inform both nodes about the network status
        link_info = QKDLinkInformer(distance = distance, 
                    std = std, p_loss_length = p_loss_length, speed_fraction = speed_fraction, 
                    depolar_rate = depolar_rate)
        self.inform_about_connection(nodeA, nodeB, link_info)

        #BIDIRECTIONAL QUANTUM CONNECTION (Even though we are only using one direction)
        qchannel_1 = QuantumChannel(name="qchannel[A to B]",
                                    length=distance,
                                    models={"delay_model": delay_model, "quantum_noise_model": noise_model, 'quantum_loss_model': loss_model})
        qchannel_2 = QuantumChannel(name="qchannel[B to A]",
                                    length=distance,
                                    models={"delay_model": delay_model, "quantum_noise_model": noise_model, 'quantum_loss_model': loss_model})
        q_conn = DirectConnection(name="qconn[A|B]",
                                    channel_AtoB=qchannel_1,
                                    channel_BtoA=qchannel_2)
        
        #BIDIRECTIONAL CLASSICAL CONNECTION
        if classical_std <= 0:
            classical_delay_model = FibreDelayModel(c=vf)
        else:
            classical_delay_model = GaussianDelayModel(speed_of_light_fraction=speed_fraction, standard_deviation=classical_std)

        cchannel_1 = ClassicalChannel("Channel_A2B",length = distance_factor * distance, models={"delay_model": classical_delay_model})
        cchannel_2 = ClassicalChannel("Channel_B2A",length = distance_factor * distance, models={"delay_model": classical_delay_model})
        c_conn = DirectConnection(name="cconn[A|B]",
                                    channel_AtoB=cchannel_1,
                                    channel_BtoA=cchannel_2)
        #BINDING PORTS
        port_name, port_r_name = self.add_connection(nodeA, nodeB, connection=c_conn, label="classical", port_name_node1="c_channel", port_name_node2="c_channel")
        port_name, port_r_name = self.add_connection(nodeA, nodeB, connection=q_conn, label="quantum", port_name_node1="q_channel", port_name_node2="q_channel")
        
        #BINDING PORTS TO QUANTUM PROCESSORS AND DETECTOR
        nodeA.qmemory.ports["qout"].forward_output(nodeA.ports['q_channel'])  # R input
        nodeB.ports['q_channel'].forward_input(nodeB.qmemory.ports["qin"])  # L input
        nodeB.qmemory.ports['qout'].connect(nodeB.subcomponents["QDetector"].ports['qin0'])
        
