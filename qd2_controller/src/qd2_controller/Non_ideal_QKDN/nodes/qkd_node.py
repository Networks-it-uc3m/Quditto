from typing import Dict
import os
import sys
current_dir = os.path.dirname(os.path.abspath(__file__))
sys.path.append(current_dir)
from qkd_link_informer import QKDLinkInformer
from netsquid.nodes import Node
from netsquid.components.instructions import INSTR_X, INSTR_Z, INSTR_H, INSTR_MEASURE
from netsquid.components.qprocessor import QuantumProcessor
from netsquid.components.qprocessor import PhysicalInstruction
from netsquid.components.models import DepolarNoiseModel, DephaseNoiseModel

def create_qprocessor(name: str, gate_duration: float, gate_noise_rate: float):
    """
   This function creates a quantum processor for QKD tasks. 
   It has a single memory unit and noise models for the quantum gates and quantum memory.

    Parameters:
    -----------
    name : String
        The name of the quantum processor.
    gate_duration : Float
        Duration (ns) of the quantum gates, the same value for H, Z, X and Measure.
    gate_noise_rate : Float
        Noise rate (Hz) parameter for noise models.

    Returns:
    --------
    QuantumProcessor
        Returns the QuantumProcessor object
    Notes:
    ------
    All gates share the same noise duration. All noise models share the same noise parameter. 
    """

    gate_noise_model = DephaseNoiseModel(gate_noise_rate)
    mem_noise_model = DepolarNoiseModel(gate_noise_rate)
    physical_instructions = [
        PhysicalInstruction(INSTR_X, duration=gate_duration,
                            quantum_noise_model=gate_noise_model),
        PhysicalInstruction(INSTR_Z, duration=gate_duration,
                            quantum_noise_model=gate_noise_model),
        PhysicalInstruction(INSTR_H, duration=gate_duration,
                            quantum_noise_model=gate_noise_model),
        PhysicalInstruction(INSTR_MEASURE, duration=gate_duration),
    ]
    qproc = QuantumProcessor(name, num_positions=1, fallback_to_nonphysical=False,
                             mem_noise_models=[mem_noise_model],
                             phys_instructions=physical_instructions)
    return qproc

class QKDNode(Node):
    """
    Represents a node in a quantum key distribution network, extending the NetSquid Node class.

    Parameters:
    -----------
    name : str
        Name or identifier of the node.
    qmemory: QuantumProcessor
        The quantum processor to store and manipulate single qubits.
    connections : Dict['QKDNode', QKD_link_informer]
        A dictionary of all QKD connections of this node, along with their corresponding QKD_link_informer objects.
        It is initialized empty
    gate_duration : Float
        Duration (ns) of the quantum gates for the quantum processor.
    gate_noise_rate : Float
        Noise rate (Hz) parameter for noise models in the quantum processor.
    emission_efficiency : Float
        Probability of emitting the generated photon.
    """
    def __init__(self, name: str, gate_duration: float, gate_noise_rate: float, emission_efficiency: float, **kwargs):
        """
        Initializes a QKDNode instance.

        Parameters:
        -----------
        name : String
            The name of the quantum node.
        gate_duration : Float
            Duration (ns) of the quantum gates for the quantum processor.
        gate_noise_rate : Float
            Noise rate (Hz) parameter for noise models in the quantum processor.
        emission_efficiency : Float
            Probability of emitting the generated photon.
        kwargs: 
            Additional keyword arguments passed to the base Node class.
        Returns:
        --------
        QKDNode
            A new QKDNode instance

        Typical Values (Example):
        ---------------
        - gate_duration = 1 ns
        - gate_noise_rate = 200 Hz
        - emission_efficiency = 0.9

        Notes:
        ------
        We save gate_duration and gate_noise_rate as specific properties of the node, to get accessed later on.
        """
        # Call the constructor of the base Node class
        qprocessor = create_qprocessor(f"qp{name}", gate_duration = gate_duration, gate_noise_rate = gate_noise_rate)
        super().__init__(name, qmemory = qprocessor, **kwargs)
        self.connections: Dict[str, QKDLinkInformer] = {}  # Dictionary of connections to other nodes
        self.add_property(name ="gate_duration", value = gate_duration)
        self.add_property(name ="gate_noise_rate", value = gate_noise_rate)
        self.add_property(name = "emission_efficiency", value = emission_efficiency)

    def add_connection(self, other_node_name: str, link_info: QKDLinkInformer):
        """
        Adds a connection to another node with the specified link.

        Parameters:
        -----------
        other_node : QKDNode
            The node to connect to.
        link_info : QKD_link
            The link object containing connection parameters.
        """
        self.connections[other_node_name] = link_info

    def __repr__(self):
        return f"QKDNode(name={self.name}, connections={list(self.connections.keys())})"


    
#continue
