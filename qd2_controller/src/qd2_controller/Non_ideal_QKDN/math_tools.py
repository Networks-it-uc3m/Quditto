"""
This file offers all the important mathematical functions to estimate
the theoretical behavior of BB84 protocol in terms of its many parameters:

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
        Photon emission efficiency of Alice's quantum source.
    detection_efficiency : float
        Photon detection efficiency of Bob's detector.
    distance_factor : float
        Multiplicative factor to scale the classical link length 
        in terms of the quantum link length (default=1).
    classical_std : float
        Standard deviation that defines the classical timing jitter (default=0).
    covery_factor : int
        Multiplicative factor for Bob's detection window width relative to standard deviation (default=3).
    p_loss_length : float
        Loss rate per kilometer of the quantum channel (dB/km, default=0.2).
    std : float
        Standard deviation of photon flight time in the quantum channel (default=0.05).
    speed_fraction : float
        Fraction of the speed of light in fiber optics (default=2/3).
    sending_rate : float
        Photon sending rate for Alice.
"""

import numpy as np
from scipy.optimize import fsolve, minimize_scalar

def H2(x):
        #Shannon binary entropy for security rate of BB84
        if x>0 and x<1:
            res = 1-2*(x*np.log2(1/x)+(1-x)*np.log2(1/(1-x)))
            return (res + np.abs(res))/2
        elif x==0:
            return 1
        else:
            return 0

def H(x):
    #Shannon binary entropy for security rate of BB84
    if x>0 and x<1:
        res = -x*np.log2(x) - (1-x)*np.log2(1-x)
        return res #(res + np.abs(res))/2
    elif x==0:
        return 0
    else:
        return 0
           
def P_Loss(distance: float, p_loss_length: float,
          emission_efficiency: float, detection_efficiency: float):
    """
    Probability of losing a photon through the quantum channel, in terms of:
        - distance (km)
        - p_loss_length (dB/km)
        - emission_efficiency
        - detection_efficiency
    """
    p_loss_init = 1 - emission_efficiency * detection_efficiency
    return 1 - (1 - p_loss_init) * 10**(-p_loss_length/10*distance)

def P_Depolar(distance: float, depolar_rate: float, speed_fraction: float):
    """
    Probability in the quantum mixed state of losing all the 
    quantum information, in terms of:
        - distance (km)
        - depolar_rate (Hz)
        - speed_fraction
    """
    return 1-np.exp(-depolar_rate*distance/300000/speed_fraction)

def P_DCR(distance: float, DCR: float, covery_factor: float, std: float, speed_fraction: float):
    """
    Probability of a dark count event happening in a time_window interval of time,
    depending on:
        - DCR: dark count rate (counts/s)
        - time_window (s). 
          Equal to 2 * covery_factor * std * distance / speed_fraction / 300000
    """
    time_window = 2 * covery_factor * std * distance / speed_fraction / 300000
    return (1-np.exp(-DCR * time_window))

def P_X(distance: float, p_loss_length: float,
          emission_efficiency: float, detection_efficiency: float,
          DCR: float, covery_factor: float, std: float, speed_fraction: float):
    """
    Probability of not detecting any signal in certain measuring time interval. Neither Alice's photon nor dark count.
    Depends on:
        - distance (km)
        - p_loss_length (dB/km)
        - emission_efficiency
        - detection_efficiency
        - DCR: dark count rate (counts/s)
        - time_window (s)
    """
    return P_Loss(distance, p_loss_length, emission_efficiency, detection_efficiency) * (1 - P_DCR(distance, DCR, covery_factor, std, speed_fraction))

def expected_QBER(distance: float, p_loss_length: float,
          emission_efficiency: float, detection_efficiency: float,
          DCR: float, speed_fraction: float, depolar_rate: float,
          std: float, covery_factor: float):
    """
    Mathematical expression for the expected Qubit Error Rate (QBER).
    It can be understood as:
    P("Bit flib between Alice and Bob in the sifted key")
    It accounts for all the ways that can produce a bit flip, conditioned to the cases where
    Bob actually measured some quantum signal.
    Depends on:
        - distance (km)
        - p_loss_length (dB/km)
        - emission_efficiency
        - detection_efficiency
        - DCR: dark count rate (counts/s)
        - speed_fraction
        - depolar_rate: Hz
        - std
        - covery_factor
    """
    PDCR = P_DCR(distance, DCR, covery_factor, std, speed_fraction)
    PLOSS = P_Loss(distance, p_loss_length, emission_efficiency, detection_efficiency)
    PD = P_Depolar(distance, depolar_rate, speed_fraction)
    res = 0.25 * PDCR * (PLOSS + 1) + 0.5 * PD * (1 - 0.5 * PDCR) * (1 - PLOSS)
    return res / (1 - PLOSS * (1 - PDCR))

def expected_KBR(distance: float, n: int, p_loss_length: float,
          emission_efficiency: float, detection_efficiency: float,
          DCR: float, speed_fraction: float, depolar_rate: float,
          std: float, covery_factor: float,
          gate_duration_A: float, gate_duration_B: float,
          dead_time: float, detector_delay: float):
    """
    Expected secure key bit rate (KBR) of BB84 protocol. Depends on:
        - distance (km)
        - n. Initially sent photons.
        - p_loss_length (dB/km)
        - emission_efficiency
        - detection_efficiency
        - DCR: dark count rate (counts/s)
        - speed_fraction
        - depolar_rate: Hz
        - std
        - covery_factor
    It returns the KBR and its standard deviation as number of output bits per quantum channel usage.
    It can be easily adapted to output bits per second.
    This calculation is done assuming 1/3 of the raw key bits are used for parameter estimation.
    """
    wait_time = distance/(300000 * speed_fraction) *1e9 #ns
    sending_rate = max(3*gate_duration_A, 3*covery_factor*std*wait_time + dead_time + detector_delay + gate_duration_B)
    PX = P_X(distance, p_loss_length,
          emission_efficiency, detection_efficiency,
          DCR, covery_factor, std, speed_fraction)
    exp_QBER = expected_QBER(distance, p_loss_length, emission_efficiency, detection_efficiency, DCR, speed_fraction, depolar_rate, std, covery_factor)
    k = (1 - 2.27*H(exp_QBER)) * (1 - PX) * n / 3
    m = m_solution(k)
    #return H2(exp_QBER) * (1 - PX) * n / 3 / (n*sending_rate*1e-9 + 11 * distance/(300000*speed_fraction)) # key bits/s
    KBR = (1 - 2.27*H(exp_QBER)) * (1 - PX) / 3 - (6 + 4*np.log2(m/0.01))/n
    p = 0.5*(1 - PX)
    delta_l = 2/3*np.sqrt(n*p*(1 - p))
    delta_KBR = (1 - 2.27*H(exp_QBER))*delta_l*np.sqrt(1+ (4/m)**2)/n #+ (4/m)**2 inside sqrt
    return KBR, delta_KBR

def m_solution(k, eps = 0.01):
    """
    This function calculates m numerically in terms of k.
    m is the output key length after privacy amplification, using the Trevisan extractor.
    k is a lower bound of the key min-entropy, from the eavesdropper point of view.
    """
    def equation(m):
        return m - (k - 6 - 4*np.log2(m / eps))

    # Initial guess for m
    m_initial_guess = k + 1  
    
    # Solve for m
    return fsolve(equation, m_initial_guess)[0]

def limit_distance(limit_error: float, p_loss_length: float,
          emission_efficiency: float, detection_efficiency: float,
          DCR: float, speed_fraction: float, depolar_rate: float,
          std: float, covery_factor: float):
    """
    This function calculates the limit distance for secure key exchange in terms of the QBER threshold.
    threshold. This calculation does not consider finite key effects.
    """
    def equation(distance, p_loss_length,
          emission_efficiency, detection_efficiency,
          DCR, speed_fraction, depolar_rate,
          std, covery_factor):
        return expected_QBER(distance, p_loss_length, emission_efficiency, detection_efficiency, DCR, speed_fraction, depolar_rate, std, covery_factor) - limit_error 
    d0 = 70 #initial guess
    solution = fsolve(lambda distance: equation(distance, p_loss_length, emission_efficiency, detection_efficiency, DCR, speed_fraction, depolar_rate, std, covery_factor), d0)
    return solution[0]

def get_n_lim(distance, DCR, depolar_rate, M, P_extra, STRATEGY = 1,
              p_loss_length = 0.2, emission_efficiency = 0.2, 
              detection_efficiency = 0.6, speed_fraction = 0.67,
              std = 0.02, covery_factor = 3,
              C_F = 3, eps = 0.1, alpha = 3, beta = 20):
    """
    TRUE CALCULATION. AUXILIARY FUNCTION.
    Minimum number of bits after sifting (not photons) needed for correct parameter estimation.
    It is an initial limit, a more restrictive lower bound needs to be given.
    Parameters:
    - d: distance
    - DCR: dark count rates
    - depolar_rate: noise parameter
    - P_extra: extra probability for controlled randomization phase. Extra noise.
    - M: output length requirements
    - STRATEGY (int, optional): Parameter estimation strategy to use 
            (1 = fixed number, 0.5 = square root scaling, else: g = fixed fraction). Default is 1/3.
    - C_F: covery factor in the quantum phase
    - eps: accuracy standard for dQBER/QBER <= f(eps)
    - alpha: accuracy parameter for dQBER/QBER <= f(eps). Default: 3
    - beta: accuracy parameter for dQBER/QBER <= f(eps). Default: 20
    """
    p = 0.5*(1 - P_X(distance = distance, p_loss_length = p_loss_length,
          emission_efficiency = emission_efficiency, 
          detection_efficiency = detection_efficiency,
          DCR = DCR, covery_factor = covery_factor, std = std, speed_fraction = speed_fraction))
    P_flip_o = expected_QBER(distance = distance, p_loss_length = p_loss_length,
          emission_efficiency = emission_efficiency, 
          detection_efficiency = detection_efficiency,
          DCR = DCR, speed_fraction = speed_fraction, 
          depolar_rate = depolar_rate,
          std = std, covery_factor = covery_factor)
    
    P_flip = P_flip_o + P_extra - 2*P_flip_o*P_extra
    F = 1.27 #Cascade fidelity
    max_eps = 0.01 #Trevisan security parameter
    l_F = (M + 6 + 4*np.log2(M/max_eps))/(1 - (1 + F)*H(P_flip))

    func = eps + alpha*eps*10**(-beta*P_flip)
    A = 1/(func*func)*(1/P_flip - 1) #(P_flip*(1 - P_flip))/(P_flip_o*P_flip_o)

    if STRATEGY == 0.5:
        def equation(x, C_q, p, l, A):
            return x**3 - C_q*np.sqrt(1 - p)*x**2 - (l + A)*x + 0.5 * A*C_q*np.sqrt(1 - p)
        D = 0.25 * (C_F*np.sqrt(1 - p) + np.sqrt(C_F*C_F*(1 - p) + 4*(l_F + A)))**2
        n0 = max(2*A, D) #initial guess
        solution = fsolve(lambda x: equation(x, C_F, p, l_F, A), n0)
        return solution[0]**2, A, D
    elif STRATEGY == 1:
        D = 0.25 * (C_F*np.sqrt(1 - p) + np.sqrt(C_F*C_F*(1 - p) + 4*(l_F + A)))**2
        return max(2*A, D), A, D #initial guess
    else:
        D = 0.25 * (C_F*np.sqrt(1 - p) + np.sqrt(C_F*C_F*(1 - p) + 4*l_F/(1 - STRATEGY)))**2
        return max(A/STRATEGY, D), A, D
    
def get_minimum_photons(distance, M, DCR, depolar_rate, P_extra, STRATEGY = 1/3,
                        p_loss_length = 0.2, emission_efficiency = 0.2, 
                        detection_efficiency = 0.6, speed_fraction = 0.67,
                        std = 0.02, covery_factor = 3,
                        C_F = 3, eps = 0.1, alpha = 3, beta = 20):
    """
    Estimate the minimum number of photons required to generate a secure key 
    of length M over a quantum link with given physical parameters.

    Args:
        - distance (float): Distance of the quantum channel in kilometers.
        - DCR (float): Dark count rate of the detector (in Hz).
        - depolar_rate (float): Depolarization rate of the channel.
        - M (int): Target length of the final secret key.
        - P_extra: extra probability for controlled randomization phase. Extra noise.
        - STRATEGY (int, optional): Parameter estimation strategy to use 
            (1 = fixed number, 0.5 = square root scaling, else: g = fixed fraction). Default is 1/3.
        - p_loss_length (float, optional): Attenuation coefficient of the fiber (in dB/km). Default is 0.2.
        - emission_efficiency (float, optional): Efficiency of the photon source. Default is 0.9.
        - detection_efficiency (float, optional): Efficiency of the photon detector. Default is 0.9.
        - speed_fraction (float, optional): Fraction of the speed of light in the fiber. Default is 0.67.
        - std (float, optional): Standard deviation of the channel loss model. Default is 0.05.
        - covery_factor (float, optional): Confidence multiplier for statistical estimation. Default is 3.
        - C_F (float, optional): Confidence factor for number of photons estimation. Default is 3.
        - eps (float, optional): Maximum acceptable failure probability. Default is 0.05.

    Returns:
        float: Minimum number of photons required to meet the key generation target under the given conditions.
    """
    p = 0.5*(1 - P_X(distance = distance, p_loss_length = p_loss_length,
          emission_efficiency = emission_efficiency, 
          detection_efficiency = detection_efficiency,
          DCR = DCR, covery_factor = covery_factor, std = std, speed_fraction = speed_fraction))
    n_lim, A, _ = get_n_lim(distance = distance, DCR = DCR, depolar_rate = depolar_rate, M = M, P_extra = P_extra, STRATEGY = STRATEGY,
              p_loss_length = p_loss_length, emission_efficiency = emission_efficiency, 
              detection_efficiency = detection_efficiency, speed_fraction = speed_fraction,
              std = std, covery_factor = covery_factor,
              C_F = C_F, eps = eps, alpha = alpha, beta = beta)
    if STRATEGY == 0.5:
        #part1 = C_q*np.sqrt(1 - p) + A/np.sqrt(n_lim)
        #part2 = 4*(l - (0.5*A*C_q*np.sqrt(1 - p))/np.sqrt(n_lim))
        #res = 0.25 * (part1 + np.sqrt(part1**2 + part2))**2 #ES IGUAL QUE NLIM
        #print(n_lim, "  ", 2*A)
        res = max(n_lim, 4*A*A/n_lim)
    else:
        res = n_lim
    return int(res/p)

def find_p_extra(d, M, DCR, depolar_rate, STRATEGY, 
                            p_loss_length = 0.2, emission_efficiency = 0.2, 
                            detection_efficiency = 0.6, speed_fraction = 0.67,
                            std = 0.02, covery_factor = 3,
                            C_F = 3, eps = 0.1, alpha = 3, beta = 20):
    """
    Find the optimal value of P_extra (artificial noise) that minimizes
    the required initial number of photon pulses, based on link parameters
    and error rate estimates.

    Parameters:
        d (float): Distance between Alice and Bob (km).
        M (int): Size of the raw key.
        DCR (float): Dark count rate of detectors.
        depolar_rate (float): Depolarization rate of the quantum channel.
        STRATEGY (str): Information reconciliation strategy.
        p_loss_length (float, optional): Loss coefficient per length (default=0.2).
        emission_efficiency (float, optional): Photon emission efficiency (default=0.2).
        detection_efficiency (float, optional): Photon detection efficiency (default=0.6).
        speed_fraction (float, optional): Fraction of light speed in fiber (default=0.67).
        std (float, optional): Standard deviation for QBER estimation (default=0.02).
        covery_factor (float, optional): Coverage factor for QBER confidence interval (default=3).
        C_F (float, optional): Confidence factor (default=3).
        eps (float, optional): Security parameter epsilon (default=0.1).
        alpha (float, optional): Reconciliation tuning parameter alpha (default=3).
        beta (float, optional): Reconciliation tuning parameter beta (default=20).

    Returns:
        tuple:
            - P_extra (float): Optimal extra noise to be added.
            - min_photons (float): Minimum required number of photons corresponding to P_extra.
            Returns (0, -1) if the initial QBER exceeds the security threshold.
    """
    Q_t = 0.09122
    P_flip = expected_QBER(distance = d, p_loss_length = p_loss_length,
          emission_efficiency = emission_efficiency, 
          detection_efficiency = detection_efficiency,
          DCR = DCR, speed_fraction = speed_fraction, 
          depolar_rate = depolar_rate,
          std = std, covery_factor = covery_factor)
    
    def f(x):
        return get_minimum_photons(distance = d, M = M, DCR = DCR, depolar_rate = depolar_rate, P_extra = x, STRATEGY = STRATEGY, 
                            p_loss_length = p_loss_length, emission_efficiency = emission_efficiency, 
                            detection_efficiency = detection_efficiency, speed_fraction = speed_fraction,
                            std = std, covery_factor = covery_factor,
                            C_F = C_F, eps = eps, alpha = alpha, beta = beta)
    if P_flip >= Q_t:
        return 0, -1
    else:
        res1 = minimize_scalar(f, bounds=((Q_t - P_flip)/2, Q_t - P_flip), method='bounded', options={'xatol': 1e-8})
        res2 = minimize_scalar(f, bounds=(1e-6, (Q_t - P_flip)/2), method='bounded', options={'xatol': 1e-8})
        if res1.fun < res2.fun:
            res = res1
        else:
            res = res2
        while res.fun > f(1e-6):
            res = minimize_scalar(f, bounds=(0, res.x/2), method='bounded', options={'xatol': 1e-8})
        return res.x, res.fun