from qkd_node import QKDNode
from netsquid.components.qdetector import QuantumDetector

class ReceiverNode(QKDNode):
    """
    ReceiverNode class inherits from QKDNode and represents a node in a Quantum Key Distribution (QKD) network 
    specifically designed for receiving qubits. This class adds functionalities for incorporating a quantum 
    detector and a property for the Dark Count Rate (DCR).

    New attributes:
        quantum_detector (QuantumDetector): A quantum detector object responsible for measuring qubits.
        DCR : float
            The Dark Count Rate (DCR) of the receiver node, representing the rate of false detections 
            due to thermal noise or other unwanted sources.
        detector_delay : float
            Delay of the detector in making a measurement (in nanoseconds). (e.g., 1 ns).
        dead_time : float
            Dead time for the detector, i.e., time needed for recovery (in nanoseconds). (e.g., 10 ns).
        receiver_efficiency: float
            Probability of actually detecting an incoming photon.
    """
    def __init__(self, name: str, DCR: float, detector_delay: float, dead_time: float, detection_efficiency: float,
                 **kwargs):
        """
        Initializes a QKDNode instance.

        Parameters:
        -----------
        name : String
            The name of the quantum node.
        DCR : Float
            Dark count rate in counts/s.
        detector_delay : float
            Delay of the detector in making a measurement (in nanoseconds). (e.g., 1 ns).
        dead_time : float
            Dead time for the detector, i.e., time needed for recovery (in nanoseconds). (e.g., 10 ns).
        receiver_efficiency: float
            Probability of actually detecting an incoming photon.

        Returns:
        --------
        ReceiverNode
            A new ReceiverNode instance

        Typical Values (Example):
        ---------------
        - DCR = 100 counts/s
        - detector_delay = 1 ns
        - dead_time = 10 ns
        - detection_efficiency = 0.9
    

        Notes:
        ------
        We save DCR, detector_delay, dead_time and detection_efficiency as specific properties of the node, to get accessed later on.
        """
        # Call the constructor of the base QKDNode class
        super().__init__(name, emission_efficiency = 1, **kwargs)
        detector = QuantumDetector("QDetector",system_delay = detector_delay, dead_time = dead_time) #ns creo, measures Z
        self.add_subcomponent(detector, name = "QDetector")
        self.add_property(name ="DCR", value = DCR)
        self.add_property(name ="detector_delay", value = detector_delay)
        self.add_property(name ="dead_time", value = dead_time)
        self.add_property(name = "detection_efficiency", value = detection_efficiency)


