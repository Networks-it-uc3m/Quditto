class QKDLinkInformer():
    """
    When a QKD connection is stablished, each one of the participating nodes gathers and stores knowledge about
    the link status, and also information about the other node.
    This can be modelized using this new class, to which both nodes will have access.

    Parameters:
    -----------
    key_memory : List
        List of keys shared between both nodes via the QKD connection.
        Each node will have key storage dedicated for each one of its connections
    distance : float
        Physical distance between nodes (in kilometers).
    std : float
        Relative standard deviation for the flight duration in the quantum channel.
    p_loss_length : float
        Rate at which detection probability decreases with channel length (in dB/km).
    speed_fraction : float
        Fraction of the speed of light for fiber-optic communication.
    depolar_rate : float
        Depolarizing rate for qubits (in Hz).
    """
    def __init__(self, distance: float, 
                 std: float, p_loss_length: float, speed_fraction: float, 
                 depolar_rate: float, 
                 key_memory = []):
        self.key_memory = key_memory
        self.distance = distance
        self.std = std
        self.p_loss_length = p_loss_length
        self.speed_fraction = speed_fraction
        self.depolar_rate = depolar_rate

    def __repr__(self):
        return (f"QKD_link(distance={self.distance:.2f}, std={self.std:.2f}, p_loss_length={self.p_loss_length:.2f}, " +
                f"speed_fraction={self.speed_fraction:.2f}, depolar_rate={self.depolar_rate:.2f})")

    def add_key(self, key: list):
        self.key_memory += key

    def get_key_material(self, required_length):
        """
        Returns and removes the first `required_length` bits from self.key_memory.
        Raises a ValueError if not enough bits are available.
        """
        if len(self.key_memory) >= required_length:
            result = self.key_memory[:required_length]
            self.key_memory = self.key_memory[required_length:]  # Remove used bits
            return result
        else:
            raise ValueError(f"Not enough key material. Required: {required_length}, available: {len(self.key_memory)}")
    
    def get_last_key(self):
        if self.key_memory != []:
            return self.key_memory[len(self.key_memory) - 1]
        else:
            return[]
            #raise IndexError("Key memory is empty!")
    def empty_key_memory(self):
        self.key_memory = []
    def pop_key_element(self, position: int):
        return self.key_memory.pop[position]
    
