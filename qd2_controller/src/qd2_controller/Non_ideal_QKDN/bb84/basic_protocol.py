import sys

import numpy as np
from nodes.qkd_node import QKDNode
from netsquid.protocols import NodeProtocol

class BasicProtocol(NodeProtocol):
    """
    A base class for defining protocols with additional functionalities on top of NodeProtocol.

    Attributes:
        node (QKDNode): The node associated with the protocol.
    Methods:
        save_key: stores the new key in the Node's dedicated memory
        H2: computes the Shannon binary entropy.
        sift: performs the key sifting phase.
        sample_bits: gets a sample of the key, popping those elements from the original list.
        error_rate: Computes the error rate (shared functionality).
        pop_elements: Extracts elements from `arr1` based on a Boolean mask in `arr2`.
    """
    def __init__(self, node: QKDNode, *args, **kwargs):
        """
        Initializes the BasicProtocol for a specific QKDNode.

        Args:
            node (QKDNode): A QKDNode object representing the node for this protocol.
            *args, **kwargs: Additional arguments passed to the parent NodeProtocol.
        
        Raises:
            TypeError: If the provided node is not a QKDNode.
        """
        
        # Call the parent class's initializer
        super().__init__(node, *args, **kwargs)
    
    def save_key(self, key: list, other_party_ID: str):
        """
        Saves a cryptographic key to the memory of a connection with another party.

        Parameters:
        ----------
        key : list[int]
            The key to be saved, represented as a list of integers.
        
        other_party_ID : str
            The identity (name) of the other party to which the key is associated.

        Raises:
        -------
        KeyError
            If `other_party_ID` is not in the `connections` dictionary.
        """
        if other_party_ID in self.node.connections:
            self.node.connections[other_party_ID].add_key(key)
        else:
            raise KeyError(f"The connection '{other_party_ID}' is missing from the connections list.")

    def H2(self, x: float):
        """
        Calculates the Shannon binary entropy for the security rate of BB84.

        Args:
            x (float): A probability value between 0 and 1 (exclusive).

        Returns:
            float: The binary entropy value, clipped to the range [0, 1].

        Notes:
            - The function computes the binary entropy using the formula:
            H(x) = 1 - 2 * (x * log2(1/x) + (1-x) * log2(1/(1-x))).
            - Values of `x` outside the range (0, 1) are assigned a default entropy of 1.
        """
        if x>0 and x<1:
            res = 1-2*(x*np.log2(1/x)+(1-x)*np.log2(1/(1-x)))
            return (res + np.abs(res))/2
        else:
            return 1

    def sift(self, a_bases: list, b_bases: list, bits: list):
        """
        Performs the sifting phase of a QKD protocol by removing bits where bases differ.

        Args:
            a_bases (list[int]): A list of bases used by the first party.
            b_bases (list[int]): A list of bases used by the second party.
            bits (list[int]): A list of bits transmitted in the protocol.

        Returns:
            list[int]: A list of "good" bits where both parties used the same basis.

        Notes:
            - Sifting is a key step in BB84 to retain only the bits where measurement bases match.
        """
        good_bits = []
        for q in range(len(a_bases)):
            if a_bases[q] == b_bases[q]:
                # If both used the same basis, add
                # this to the list of 'good' bits
                good_bits.append(bits[q])
        return good_bits
        
    def sample_bits(self, bits: list, selection: list):
        """
        Creates a sample from a list of bits based on a selection and removes those bits.

        Args:
            bits (list[int]): The original list of bits (modified in-place).
            selection (list[int]): Indices of bits to sample from the `bits` list.

        Returns:
            list[int]: A list of sampled bits.

        Notes:
            - This function modifies the `bits` list by removing the sampled elements.
            - Indices in `selection` are wrapped using modular arithmetic to handle out-of-range indices.
        """
        sample = []
        for i in selection:
            i = np.mod(i, len(bits))
            sample.append(bits.pop(i))
        return sample

    def error_rate(self, a: list, b: list):
        """
        Calculates the error rate between two bitstrings.

        Args:
            a (list[int]): The first bitstring.
            b (list[int]): The second bitstring.

        Returns:
            float: The fraction of mismatched bits (error rate).

        Raises:
            ValueError: If the two input lists have different lengths.

        Notes:
            - Error rate is computed as the ratio of mismatched bits to the total bit count.
            - An error message is printed if lengths differ, though this case should be avoided.
        """
        res=0
        if len(a) != len(b):
            raise ValueError("Lists are not of the same length.")
        else:
            for i in range(0, len(a)):
                if a[i] != b[i]:
                    res+=1
            return res/len(a)
    
    def pop_elements(self, arr1, arr2):
        """
        Extracts elements from `arr1` based on a Boolean mask in `arr2`.

        Args:
            arr1 (array-like): The array of values to extract from.
            arr2 (array-like): A Boolean array (or binary mask) indicating which elements to extract.

        Returns:
            numpy.ndarray: A new array containing elements from `arr1` where `arr2` equals 1.

        Raises:
            ValueError: If `arr1` and `arr2` do not have the same shape.

        Notes:
            - Both `arr1` and `arr2` are converted to NumPy arrays for processing.
            - This function is useful for selecting elements conditionally.
        """

        # Ensure both arrays are NumPy ndarrays
        arr1 = np.asarray(arr1)
        arr2 = np.asarray(arr2)
    
        # Check if both arrays have the same length
        if arr1.shape != arr2.shape:
            raise ValueError("Both arrays must have the same shape.")
        
        # Use Boolean masking to keep elements from arr1 where arr2 is 1
        result = arr1[arr2 == 1]
        return result