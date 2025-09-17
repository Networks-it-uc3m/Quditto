import sys
import os
import time

current_dir = os.path.dirname(os.path.abspath(__file__))
nonideal_dir = os.path.abspath(os.path.join(current_dir, '..'))
sys.path.append(nonideal_dir)

#TREVISAN
from cryptomite.trevisan import Trevisan

#BRUNO RIKJSMAN CASCADE
current_dir = os.path.dirname(os.path.abspath(__file__))
parent_dir = os.path.abspath(os.path.join(current_dir, '..', 'cascade_python'))
sys.path.append(parent_dir)

from cascade_python.cascade.reconciliation import *
from cascade_python.cascade.tests.test_reconciliation import *

from netsquid.protocols.nodeprotocols import LocalProtocol
from netsquid.protocols import Signals
from netsquid.util import DataCollector
import pydynaa
import numpy as np
import netsquid as ns
from bb84.sender_protocol import SenderProtocol
from bb84.receiver_protocol import ReceiverProtocol
from math_tools import *
from nodes.qkd_node import QKDNode
from nodes.receiver_node import ReceiverNode
from network import QKDNetwork

PARAMETER_UNITS = {
    "n": "photons",
    "distance": "km",
    "depolar_rate": "Hz",
    "gate_duration_A": "ns",
    "gate_duration_B" : "ns",
    "gate_noise_rate_A" : "Hz",
    "gate_noise_rate_B" : "Hz",
    "dead_time" : "ns",
    "detector_delay" : "ns",
    "DCR" : "counts/s",
    "emission_efficiency" : "",
    "detection_efficiency" : "",
    "distance_factor" : "",
    "classical_std" : "",
    "covery_factor" : "",
    "p_loss_length" : "dB/km",
    "std" : "",
    "speed_fraction" : "",
    
    "sending_rate" : "ns",
    "sim_duration" : "ns",
    "Final_key_size": "", 
    "Intermediate_key_size_1": "", 
    "Intermediate_key_size_2" : ""
    
}

PARAMETER_VALUES_0 = {
    #CHANNEL
    "distance": 20, #link distance, km
    "depolar_rate": 100, #noise rate, Hz
    "emission_efficiency" : 0.2, #Emission success probability
    "detection_efficiency" : 0.6, #Detection success probability
    "p_loss_length" : 0.2, #Loss rate in the channel, dB/km
    "std" : 0.02, #Timing jitter fraction in the quantum channel
    "speed_fraction" : 2/3, #Parameter defining channel speed, as a fraction of c
    "distance_factor" : 1, #Ratio between classical link length and quantum link length
    "classical_std" : 0, #Timing jitter fraction in the classical channel

    #ALICE
    "gate_duration_A": 1, #ns
    "gate_noise_rate_A" : 0, #Hz

    #BOB
    "gate_duration_B": 1, #ns
    "gate_noise_rate_B" : 0, #Hz
    "dead_time" : 100, #ns
    "detector_delay" : 0.5, #ns
    "DCR" : 25, # Dark count rate per unit time, counts/s
    
    #PROTOCOL AND OUTPUT REQUIREMENTS
    "num_photons": None, #Initial number of photons, INTEGER, if set to None, the protocol will calculate it according to key requirements
    "covery_factor" : 3,
    "strategy": 1/3, #Fraction of bits taken for parameter estimations. Requires a value between 0 and 1/2. If given a value 1, uses a fisex number of bits.
    "max_eps": 0.01, #Security parameter for Trevisan
    "required_length": 100, #Output length requirements fixed by the user, INTEGER
    "eps": 0.1, #Parameter to define QBER estimation accuracy
    "alpha": 3, #Parameter to define QBER estimation accuracy
    "beta": 20, #Parameter to define QBER estimation accuracy
    "C_F": 3, #Covery factor for output requirements guarantee
}


class BB84_Protocol(LocalProtocol):
    """
    Implements the BB84 quantum key distribution protocol as a local protocol in a quantum network.

    This class manages the setup and execution of the BB84 protocol between two nodes (Alice (sender) and Bob (receiver)). 
    It computes the optimal photon sending rate according to the quantum link 
    characteristics to maximize the key generation rate while preventing 
    protocol errors due to timing issues.

    Parameters:
    -----------
    n : int
        The number of initial photons/pulses sent to be generated during the protocol.
    network : Network
        The quantum network containing the participating nodes.
    ID_A : str
        The name of the sender node (e.g., "Alice").
    ID_B : str
        The name of the receiver node (e.g., "Bob").
    covery_factor : int
        The detection window width relative to the standard deviation of photon flight times. Usually fixed to 3.
    *args : tuple
        Additional arguments to be passed to the parent class.
    **kwargs : dict
        Additional keyword arguments to be passed to the parent class.

    Attributes:
    -----------
    subprotocol_A : SenderProtocol
        The protocol responsible for photon transmission from the sender node.
    subprotocol_B : ReceiverProtocol
        The protocol responsible for photon reception and key processing at the receiver node.

    Key Computations:
    -----------------
    - `GD_A` and `GD_B`:
        Gate durations for Alice and Bob's quantum processors.
    - `std`:
        Standard deviation of photon flight duration in the quantum channel.
    - `d`:
        Distance of the quantum channel between Alice and Bob.
    - `f`:
        Fraction of the speed of light in the quantum channel.
    - `wait_time`:
        Time required for a photon to travel the channel length, calculated as `d / (f * 300,000) * 1e9` (in nanoseconds).
    - `DT` and `DD`:
        Dead time and detector delay for Bob's quantum detector.
    - `s`:
        Optimal photon sending rate for Alice, calculated to minimize timing errors and maximize key generation.

    Notes:
    ------
    This class relies on two subprotocols, `SenderProtocol` and `ReceiverProtocol`, which are dynamically 
    added and executed during the protocol. 
    """
    def __init__(self, n: int, P_extra: float, network, ID_A: str, ID_B: str, covery_factor: int, strategy, *args, **kwargs):
        super().__init__(nodes = network.nodes, *args, **kwargs)
        nodes = network.nodes
        #We select the optimal value of photon sending rate, maximizing KBR while avoiding code errors
        GD_A = nodes[ID_A].properties["gate_duration"]
        GD_B = nodes[ID_B].properties["gate_duration"]
        std = nodes[ID_A].connections[ID_B].std 
        d = nodes[ID_A].connections[ID_B].distance
        f = nodes[ID_A].connections[ID_B].speed_fraction
        wait_time = d/f/300000*1e9
        DT = nodes[ID_B].properties["dead_time"]
        DD = nodes[ID_B].properties["detector_delay"]
        C = covery_factor

        sending_rate =  max(3*GD_A, 3*C*std*wait_time + DT + DD + GD_B)
        subprotocol_A = SenderProtocol(node=nodes[ID_A], n=n, s=sending_rate, strategy = strategy, name=f"BB84 Sender")
        self.add_subprotocol(subprotocol_A, name = "subprotocol_A")
        subprotocol_B = ReceiverProtocol(node=nodes[ID_B], n=n, P_extra = P_extra, covery_factor = C, name=f"BB84 Receiver")
        self.add_subprotocol(subprotocol_B, name = "subprotocol_B")
        

def setup_datacollector(protocol):
    """
    Sets up a data collector for the BB84 protocol to gather key statistics, such as QBER and key rate.

    This function ensures that Alice and Bob nodes are correctly identified in the network, calculates 
    the Quantum Bit Error Rate (QBER) and the expected key generation rate (KBR_exp), and collects relevant 
    metrics during the protocol execution.

    Parameters:
    -----------
    protocol : LocalProtocol
        The BB84 protocol instance managing the key distribution process.

    Returns:
    --------
    dc : DataCollector
        A data collector object configured to calculate and record QBER, key size, and KBR metrics.

    Nested Functions:
    -----------------
    H2(x):
        Calculates the Shannon binary entropy, used to determine the security rate of BB84.
    error_rate(a, b):
        Computes the error rate between two bit sequences `a` and `b`.
    calc_QBER(evexpr):
        Core function used by the data collector to calculate QBER, key size, and expected key rate:
        - Retrieves the final keys from Alice and Bob.
        - Calculates QBER using the `error_rate` function.
        - Estimates the key generation rate (KBR_exp) based on QBER and simulation time.
        - Returns a dictionary of metrics.

    DataCollector Configuration:
    ----------------------------
    The data collector is triggered on the `SUCCESS` signal emitted by Bob's subprotocol, 
    which indicates that a key distribution round has been successfully completed.

    """

    # Ensure nodes are ordered in the chain:
    alice = protocol.subprotocols["subprotocol_A"].node
    bob = protocol.subprotocols["subprotocol_B"].node

    def H2(x):
        #Shannon binary entropy for security rate of BB84
        if x>0 and x<1:
            res = 1-2*(x*np.log2(1/x)+(1-x)*np.log2(1/(1-x)))
            return (res + np.abs(res))/2
        elif x==0:
            return 1
        else:
            return 0
            
    def error_rate(a, b):
        res=0
        if len(a) != len(b):
            print("Error gordo")
        else:
            for i in range(0, len(a)):
                if a[i] != b[i]:
                    res+=1
            return res/len(a)
            
    def calc_QBER(evexpr):
        #key_a = alice.connections[bob.name].get_last_key()
        #key_b = bob.connections[alice.name].get_last_key()

        key_a = protocol.subprotocols["subprotocol_A"].raw_key
        key_b = protocol.subprotocols["subprotocol_B"].raw_key

        qber = error_rate(key_a, key_b)
        n = protocol.subprotocols['subprotocol_A'].n
        int_key_size_1 = protocol.subprotocols['subprotocol_A'].intermediate_key_length_1
        int_key_size_2 = protocol.subprotocols['subprotocol_A'].intermediate_key_length_2

        estimated_qber = protocol.subprotocols['subprotocol_A'].estimated_qber
        #kr_exp = (1 - H2(qber))*(len(key_b))/(ns.sim_time())*1e9 #counts/s
        wait_time = alice.connections[bob.name].distance/(alice.connections[bob.name].speed_fraction*300000)*1e9
        #s = max(2*alice.properties["gate_duration"], 3*protocol.subprotocols['subprotocol_B'].covery_factor*alice.connections[bob.name].std*wait_time + bob.properties["dead_time"] + bob.properties["detector_delay"] + bob.properties["gate_duration"])
        #KBR_t = self.H2(err)*(1 - P0)* (10**(-R/10*wait_time*1e-9*0.5*300000))/(3*s)*1e9
        key_size = len(key_b)
        return {"Alice raw key": key_a, "Bob raw key": key_b, "n (photons sent)": n, "Intermediate_key_size_3 (after PEst)": key_size, "Intermediate_key_size_1 (after transmission)": int_key_size_1, "Intermediate_key_size_2 (after sifting)": int_key_size_2, "Estimated QBER": estimated_qber, "Actual QBER": qber} #we use here the correct ns.sim_time()

    dc = DataCollector(calc_QBER, include_entity_name=False)
    dc.collect_on([pydynaa.EventExpression(source=protocol.subprotocols["subprotocol_B"], event_type=Signals.SUCCESS.value), pydynaa.EventExpression(source=protocol.subprotocols["subprotocol_A"], event_type=Signals.SUCCESS.value)], combine_rule = "AND") #.subprotocols["subprotocol_A"]
    return dc

def print_parameters(parameters: dict):
    """
    Prints the parameters and their values in a structured and aligned format.

    Parameters:
    -----------
    parameters : dict
        A dictionary where keys are parameter names and values are their corresponding values.

    Returns:
    --------
    None
    """
    if not parameters:
        print("No parameters to display.")
        return

    # Determine the length of the longest key for alignment
    max_key_length = max(len(key) for key in parameters.keys())
    
    # Print each key-value pair aligned
    print("BB84 experiment parameters:")
    for key, value in parameters.items():
        if key == "sending_rate":
            print(f"  {key.ljust(max_key_length)} : {value:.0f} {PARAMETER_UNITS[key]}")
        elif key == "sim_duration":
            print(f"  {key.ljust(max_key_length)} : {value/1e9:.2e} s")
        else:
            print(f"  {key.ljust(max_key_length)} : {value} {PARAMETER_UNITS[key]}")




def BB84_Experiment(n: int, distance: float,
                    depolar_rate: float, DCR: float, strategy: float,
                    gate_duration_A: float, gate_duration_B: float, gate_noise_rate_A: float, gate_noise_rate_B: float,
                    dead_time: float, detector_delay: float, 
                    emission_efficiency: float, detection_efficiency: float,
                    distance_factor = 1, classical_std = 0, covery_factor = 3,
                    p_loss_length = 0.2, std = 0.02, speed_fraction = 0.67
                    ):
    """
    Executes only the quantum phase of hte BB84 quantum key distribution (QKD) experiment simulation using NetSquid.

    This function simulates the key distribution process between two nodes, Alice and Bob, over a 
    quantum link with specified parameters. It calculates the performance metrics of the protocol 
    and returns the collected data along with the generated keys.

    Parameters:
    -----------
    n : int
        Number of photons sent during the experiment.
    distance : float
        Physical distance between Alice and Bob in kilometers.
    depolar_rate : float
        Depolarization rate of the quantum channel (Hz).
    gate_duration_A : float
        Gate duration for Alice's quantum processor (ns).
    gate_duration_B : float
        Gate duration for Bob's quantum processor (ns).
    gate_noise_rate_A : float
        Gate noise rate for Alice's quantum processor (Hz).
    gate_noise_rate_B : float
        Gate noise rate for Bob's quantum processor (Hz).
    dead_time : float
        Dead time of Bob's quantum detector (ns).
    detector_delay : float
        Measurement delay of Bob's quantum detector (ns).
    DCR : float
        Dark count rate of Bob's quantum detector (Hz).
    emission_efficiency : float
        Photon emission efficiency of Alice's quantum source. Probability of a photon being lost in the emission stage.
    detection_efficiency : float
        Photon detection efficiency of Bob's detector. Probability of a photon being lost in the detection stage.
    distance_factor : float, optional
        Multiplicative factor to scale the classical link length 
        in terms of the quantum link length (default=1).
    classical_std : float, optional
        Standard deviation that defines the classical timing jitter (default=0).
    covery_factor : int, optional
        Multiplicative factor for Bob's detection window width relative to standard deviation (default=3).
    p_loss_length : float, optional
        Loss rate per kilometer of the quantum channel (dB/km, default=0.2).
    std : float, optional
        Standard deviation of photon flight time in the quantum channel (default=0.02).
    speed_fraction : float, optional
        Fraction of the speed of light in fiber optics (default=2/3).

    Returns:
    --------
    dc : DataCollector
        A data collector containing performance metrics such as QBER and key rates.
    alice_key : list[int]
        Final key generated by Alice.
    bob_key : list[int]
        Final key generated by Bob.
    locals() : Dict{}
        A dictionary with parameter names as keys and their values.


    Typical Values (Example):
        ---------------
        1. Emitter (Alice) parameters:
            - emission_efficiency: 0.2
            - n: number of initial photons (to be given as input)
            - s: sending rate (ns), is calculated during the execution of the protocol
            - gate_duration_A = 1 ns
            - gate_noise_rate_A = 0 Hz
        2. Channel properties:
            - std = 0.02
            - classical_std = 0 (can be fixed)
            - distance_factor = 1
            - speed_fraction = 0.67
            - depolar_rate = 100 Hz
            - p_loss_length = 0.2 dB/km

        3. Detector (Bob) parameters:
            - covery_factor = 3 (can be fixed)
            - DCR = 25 counts/s
            - detector_delay = 0.5 ns
            - dead_time = 100 ns
            - detection_efficiency: 0.6
            - gate_duration_B = 1 ns
            - gate_noise_rate_B = 0 Hz

    Notes:
    ------
    - This function initializes a quantum network with a simple link between Alice and Bob.
    - It configures the BB84 protocol with the provided parameters and runs the simulation.
    - The simulation duration is calculated based on the communication delay and photon processing time.
    - Collected data and keys are returned for analysis.

    """
    ns.sim_reset()
    nodeA = QKDNode("Alice", gate_duration = gate_duration_A, gate_noise_rate = gate_noise_rate_A, 
                    emission_efficiency = emission_efficiency, port_names=["q_channel", "c_channel"])
    nodeB = ReceiverNode("Bob", detector_delay = detector_delay, 
                        dead_time = dead_time, gate_duration = gate_duration_B, 
                        gate_noise_rate = gate_noise_rate_B, DCR = DCR, 
                        detection_efficiency = detection_efficiency, port_names=["q_channel", "c_channel"])
    BB84_network = QKDNetwork("BB84_network")
    BB84_network.set_simple_link(nodeA, nodeB, distance, depolar_rate,
             distance_factor, classical_std,
             p_loss_length, std, speed_fraction)
    
    #Parameter estimation strategy is given as a parameter, since it depends on the requested length.
    protocol = BB84_Protocol(n, BB84_network, nodeA.name, nodeB.name, covery_factor, strategy)
    dc = setup_datacollector(protocol)
    wait_time = distance/(speed_fraction * 300000) * 1e9
    sending_rate = max(3*gate_duration_A, 3*covery_factor*std*wait_time + dead_time + detector_delay + gate_duration_B)
    protocol.start()
    sim_duration = gate_duration_A + 20*wait_time + (n+1)*sending_rate
            #print(f"Round {j}. The simulation will last: {sim_duration} ns.\n")

    res = ns.sim_run(duration = sim_duration)
    #print(dc.dataframe)
    alice_key = dc.dataframe.pop("Alice raw key").iloc[-1]
    bob_key = dc.dataframe.pop("Bob raw key").iloc[-1]
    local_vars = locals()

    # Filter and return only the variables that are in 'parameters' and exist in locals()
    filtered_params = {key: local_vars[key] for key in PARAMETER_UNITS.keys() if key in local_vars}
    return dc, alice_key, bob_key, filtered_params

def list_to_key(key_list):
    key = Key()
    key._size = len(key_list)
    for i in range(len(key_list)):
        key._bits[i] = key_list[i]
    return key

def key_to_list(key):
    list_res = []
    for i in range(key._size):
        list_res.append(key._bits[i])
    return list_res

def transform(a):
    for jj in range(len(a)):
        if a[jj]:
            a[jj]=1
        elif not a[jj]:
            a[jj]=0
    return a

def create_reconciliation2(input_message, error_message, er_estimated):
    correct_key = list_to_key(input_message)
    noisy_key = list_to_key(error_message)
    #We create both keys
    mock_classical_channel = MockClassicalChannel(correct_key)
    rec = Reconciliation('original', mock_classical_channel, noisy_key, er_estimated)
    reconciled_key = rec.reconcile()
    exposed = rec.stats.ask_parity_blocks
    efficiency = rec.stats.efficiency
    duration = rec.stats.elapsed_real_time #rec.stats.elapsed_process_time
    #final_error = correct_key.difference(reconciled_key)/correct_key.get_size()
    alice_final_key = copy.deepcopy(key_to_list(correct_key))
    bob_final_key = copy.deepcopy(key_to_list(rec._reconciled_key))
    return alice_final_key, bob_final_key, exposed, efficiency, duration

def FULL_BB84(config: dict):
    """
    required_length: int, distance: float,
                    depolar_rate: float,
                    gate_duration_A: float, gate_duration_B: float, gate_noise_rate_A: float, gate_noise_rate_B: float,
                    dead_time: float, detector_delay: float, DCR: float,
                    emission_efficiency: float, detection_efficiency: float,
                    strategy = 1/3,
                    distance_factor = 1, classical_std = 0, covery_factor = 3,
                    p_loss_length = 0.2, std = 0.02, speed_fraction = 0.67, C_F = 3, eps = 0.1, alpha = 3, beta = 20,
                    num_photons = None
                    
    Runs a full BB84 QKD experiment simulation using NetSquid. 
    This function includes INFORMATION RECONCILIATION AND PRIVACY AMPLIFICATION.

    This function sets up a QKD network with two nodes (Alice and Bob), applies a specified
    strategy for parameter estimation, simulates quantum transmission, and performs 
    post-processing (error correction and privacy amplification) to generate a final secret key.

    Parameters:
        - required_length (int): Output length requirements given by the user.
        - distance (float): Distance between Alice and Bob in kilometers.
        - depolar_rate (float): Depolarization rate of the quantum channel.
        - gate_duration_A (float): Gate time (ns) for Alice's emission.
        - gate_duration_B (float): Gate time (ns) for Bob's detection.
        - gate_noise_rate_A (float): Noise rate during Alice's gate operation.
        - gate_noise_rate_B (float): Noise rate during Bob's gate operation.
        - dead_time (float): Dead time of Bob's detector (ns).
        - detector_delay (float): Delay before detection (ns).
        - DCR (float): Dark count rate of the detector.
        - emission_efficiency (float): Efficiency of Alice's photon source.
        - detection_efficiency (float): Efficiency of Bob's detector.
        - strategy (float, optional): Parameter estimation strategy (default: 1/3, 1 or 0.5).
        - distance_factor (float): Multiplier for quantum channel length (default: 1).
        - classical_std (float): Standard deviation for classical channel delay (default: 0).
        - covery_factor (float): Coverage factor for uncertainty estimates (default: 3).
        - p_loss_length (float): Channel loss per kilometer (default: 0.2).
        - std (float): Standard deviation for photon timing jitter (default: 0.02).
        - speed_fraction (float): Fraction of the speed of light in fiber (default: 0.67).
        - C_F (float, optional): Confidence factor for number of photons estimation. Default is 3.
        - eps (float, optional): Maximum acceptable failure probability. Default is 0.1.
        - alpha (float, optional): Reconciliation tuning parameter alpha (default=3).
        - beta (float, optional): Reconciliation tuning parameter beta (default=20).
        - num_photons (int): Number of initial photons. Default is None.


    Returns:
        tuple:
            - output_message_CP (list[int]): Final secret key.
            - m (int): Final key length after privacy amplification.
            - new_message_length (int): Key length before privacy amplification.
            - protocol_duration (float): Total duration of the protocol (ns).
            - quantum_phase_duration (float): Duration of the quantum transmission phase (ns).
            - cascade_efficiency (float): Efficiency of the Cascade error correction protocol.
            - Other relevant data (dataframe)
    """

    # === Required / core parameters ===
    required_length = config.get("required_length", PARAMETER_VALUES_0["required_length"])
    distance = config.get("distance")
    num_photons = config.get("num_photons")

    # === Optional with defaults (already in the config dict) ===
    gate_duration_A = config.get("gate_duration_A", PARAMETER_VALUES_0["gate_duration_A"])
    gate_duration_B = config.get("gate_duration_B", PARAMETER_VALUES_0["gate_duration_B"])
    gate_noise_rate_A = config.get("gate_noise_rate_A", PARAMETER_VALUES_0["gate_noise_rate_A"])
    gate_noise_rate_B = config.get("gate_noise_rate_B", PARAMETER_VALUES_0["gate_noise_rate_B"])
    dead_time = config.get("dead_time", PARAMETER_VALUES_0["dead_time"])
    detector_delay = config.get("detector_delay", PARAMETER_VALUES_0["detector_delay"])
    DCR = config.get("DCR", PARAMETER_VALUES_0["DCR"])
    depolar_rate = config.get("depolar_rate", PARAMETER_VALUES_0["depolar_rate"])
    emission_efficiency = config.get("emission_efficiency", PARAMETER_VALUES_0["emission_efficiency"])
    detection_efficiency = config.get("detection_efficiency", PARAMETER_VALUES_0["detection_efficiency"])
    strategy = config.get("strategy", PARAMETER_VALUES_0["strategy"])
    distance_factor = config.get("distance_factor", PARAMETER_VALUES_0["distance_factor"])
    classical_std = config.get("classical_std", PARAMETER_VALUES_0["classical_std"])
    p_loss_length = config.get("p_loss_length", PARAMETER_VALUES_0["p_loss_length"])

    # === Advanced or environment parameters (already in the config dict) ===
    covery_factor = config.get("covery_factor", PARAMETER_VALUES_0["covery_factor"])
    std = config.get("std", PARAMETER_VALUES_0["std"])
    speed_fraction = config.get("speed_fraction", PARAMETER_VALUES_0["speed_fraction"])
    C_F = config.get("C_F", PARAMETER_VALUES_0["C_F"])
    eps = config.get("eps", PARAMETER_VALUES_0["eps"])
    alpha = config.get("alpha", PARAMETER_VALUES_0["alpha"])
    beta = config.get("beta", PARAMETER_VALUES_0["beta"])
    max_eps = config.get("max_eps", PARAMETER_VALUES_0["max_eps"])

    d_lim = limit_distance(limit_error = 0.09122, p_loss_length = p_loss_length,
          emission_efficiency = emission_efficiency, detection_efficiency = detection_efficiency,
          DCR = DCR, speed_fraction = speed_fraction, depolar_rate = depolar_rate,
          std = std, covery_factor = covery_factor)
    if distance > d_lim:
        raise ValueError(f"Protocol aborted: Link distance over limit distance d_lim = {d_lim:.3} km. QBER will be too high for secure key distribution.")

    if num_photons is None and required_length is None:
        raise ValueError("At least one of 'num_photons' or 'required_length' must be provided.")

    if num_photons is not None:
        n = num_photons
        P_extra = 0
        if required_length is None:
            required_length = 0
    else:
        P_extra, n = find_p_extra(d = distance, M = required_length, DCR = DCR, 
                            depolar_rate = depolar_rate, STRATEGY = strategy, 
                            p_loss_length = p_loss_length, emission_efficiency = emission_efficiency, 
                            detection_efficiency = detection_efficiency, speed_fraction = speed_fraction,
                            std = std, covery_factor = covery_factor,
                            C_F = C_F, eps = eps, alpha = alpha, beta = beta)
        
    if strategy == 1:
        n_lim, A, _ = get_n_lim(distance = distance, DCR = DCR, depolar_rate = depolar_rate, 
              M = required_length, P_extra = P_extra, STRATEGY = strategy,
              p_loss_length = p_loss_length, emission_efficiency = emission_efficiency, 
              detection_efficiency = detection_efficiency, speed_fraction = speed_fraction,
              std = std, covery_factor = covery_factor,
              C_F = C_F, eps = eps)
        strategy = [1.0, A] #The second value sets the number of bits used for parameter estimation

    elif strategy == 0.5:
        n_lim, A, _ = get_n_lim(distance = distance, DCR = DCR, depolar_rate = depolar_rate, 
              M = required_length, P_extra = P_extra, STRATEGY = strategy,
              p_loss_length = p_loss_length, emission_efficiency = emission_efficiency, 
              detection_efficiency = detection_efficiency, speed_fraction = speed_fraction,
              std = std, covery_factor = covery_factor,
              C_F = C_F, eps = eps)
        strategy = [0.5, A/np.sqrt(n_lim)]
        
    ns.sim_reset()

    nodeA = QKDNode("Alice", gate_duration = gate_duration_A, gate_noise_rate = gate_noise_rate_A, 
                    emission_efficiency = emission_efficiency, port_names=["q_channel", "c_channel"])
    nodeB = ReceiverNode("Bob", detector_delay = detector_delay, 
                        dead_time = dead_time, gate_duration = gate_duration_B, 
                        gate_noise_rate = gate_noise_rate_B, DCR = DCR, 
                        detection_efficiency = detection_efficiency, port_names=["q_channel", "c_channel"])
    BB84_network = QKDNetwork("BB84_network")
    BB84_network.set_simple_link(nodeA, nodeB, distance, depolar_rate,
             distance_factor, classical_std,
             p_loss_length, std, speed_fraction)
    
    #Parameter estimation strategy is given as a parameter, since it depends on the requested length.
    protocol = BB84_Protocol(n, P_extra, BB84_network, nodeA.name, nodeB.name, covery_factor, strategy)
    dc = setup_datacollector(protocol)
    wait_time = distance/(speed_fraction * 300000) * 1e9
    sending_rate = max(3*gate_duration_A, 3*covery_factor*std*wait_time + dead_time + detector_delay + gate_duration_B)
    protocol.start()
    sim_duration = gate_duration_A + 20*wait_time + (n+1)*sending_rate
            #print(f"Round {j}. The simulation will last: {sim_duration} ns.\n")

    res = ns.sim_run(duration = sim_duration)
    #print(dc.dataframe)

    #Security threshold
    channel_QBER = (dc.dataframe["Estimated QBER"].iloc[-1] - P_extra)/(1 - 2*P_extra)
    if channel_QBER > 0.09122:
        raise RuntimeError(f"Protocol aborted: Estimated QBER too high ({channel_QBER:.5f} > 0.09122)")

    alice_raw_key = dc.dataframe.pop("Alice raw key").iloc[-1]
    bob_raw_key = dc.dataframe.pop("Bob raw key").iloc[-1]

    local_vars = locals()
    filtered_params = {key: local_vars[key] for key in PARAMETER_UNITS.keys() if key in local_vars}

    P_flip = expected_QBER(distance, p_loss_length,
      emission_efficiency, detection_efficiency,
      DCR, speed_fraction, depolar_rate,
      std, covery_factor)
    protocol_duration = filtered_params["sim_duration"]
    quantum_phase_duration = filtered_params["sim_duration"]
    wait_time = distance/(speed_fraction*300000)*1e9

    P_noise_effective = P_flip + P_extra - 2*P_flip*P_extra

    #Information reconciliation
    start_time_postprocessing = time.time()
    input_message_C, error_message_C, exposed_bits, cascade_efficiency, duration_C = create_reconciliation2(alice_raw_key, bob_raw_key, P_noise_effective)

    #Privacy amplification
    max_eps = 0.01 #The maximum acceptable extractor error.
    new_message_length = len(input_message_C)
    k = int(new_message_length*(1 - 2.27*H(P_noise_effective))) #The total min-entropy of the input bits.
    ext = Trevisan(new_message_length, k, max_eps);

    seed_bits = [int(np.random.rand() > 0.5) for _ in range(ext.ext.get_seed_length())]
    output_message_CP = transform(ext.extract(list(input_message_C), seed_bits));

    end_time_postprocessing = time.time()
    protocol_duration += (duration_C + end_time_postprocessing - start_time_postprocessing)*1e9

    m = len(output_message_CP)

    nodeA.connections["Bob"].add_key(output_message_CP)
    nodeB.connections["Alice"].add_key(output_message_CP)

    #Add new data to the dataframe
    dc.dataframe["Output key length"] = m
    dc.dataframe["Total protocol duration (s)"] = protocol_duration*1e-9
    dc.dataframe["Quantum phase duration (s)"] = quantum_phase_duration*1e-9
    dc.dataframe["Cascade efficiency"] = cascade_efficiency
    dc.dataframe["Extra noise probability"] = P_extra
    dc.dataframe["Required output"] = required_length
    dc.dataframe["KBR (Hz)"] = m/(protocol_duration*1e-9)
    dc.dataframe["KBR"] = m/n

    #Returns: 
    #   0) final key
    #   1) dc.dataframe containing other relevant performance parameters
    
    # print("Alice key memory: ", nodeA.connections["Bob"].key_memory)
    # print("Bob key memory: ", nodeB.connections["Alice"].key_memory)
    
    # nodeA.connections["Bob"].get_key_material(1200)
    # nodeB.connections["Alice"].get_key_material(1200)

    # print("Alice key memory: ", nodeA.connections["Bob"].key_memory)
    # print("Bob key memory: ", nodeB.connections["Alice"].key_memory)

    return output_message_CP, dc