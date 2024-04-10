from quditto_client import interfaces_pb2, interfaces_pb2_grpc
import grpc
from enum import Enum

PORT = 31942


class Status(Enum):
    """Status as defined in ETSI GS QKD 004

    """    
    SUCCESSFUL = 0
    SUCCESSFUL_NO_PEER = 1
    GET_KEY_FAILED_INSUFFICIENT_KEY = 2
    GET_KEY_FAILED_PEER_NOT_CONNECTED = 3
    NO_QKD_CONNECTION = 4
    OPEN_CONNECT_FAILED_KSID_IN_USE = 5
    TIMEOUT_ERROR = 6
    OPEN_FAILED_QOS = 7
    GET_KEY_FAILED_METADATA_INSUFFICIENT = 8
    STREAM_NOT_FOUND = 9


class Client004:
    """Client for the ETSI QKD 004 interface

    """    
    def __init__(self):
        self.channel = None
        self.c = None

    def connect(self, ip):
        """Connect to a QKD node

        Args:
            ip (str): IP address of the QKD node
        """        
        self.c = grpc.insecure_channel(ip + ":" + str(PORT))
        self.channel = interfaces_pb2_grpc.ApplicationInterfaceStub(self.c)

    def open_connect(self, src, dst, key_chunk_size, ttl, ksid):
        """No fully complete version of open_connect in ETSI QKD GS 004.

        Refer to the standard for understanding the behaviour

        Args:
            src (str): src url (app@server)
            dst (str): dst url (app@server)
            key_chunk_size (int): key chunk size in number of bytes
            ttl (int): TTL of the keys in seconds
            ksid (bytes): ksid for the stream. It must be a 16 byte array or None (the server will create one)

        Returns:
            The parameters as described in the standard
        """
        # Timeout not implemented yet
        qos = interfaces_pb2.QoS(key_chunk_size=key_chunk_size, timeout=1000, ttl=ttl,
                                 metadata_mimetype="application/json")
        request = interfaces_pb2.OpenConnectRequest(source=src, destination=dst, qos=qos, ksid=ksid)
        response = self.channel.open_connect(request)
        response = {
            "key_chunk_size": response.qos.key_chunk_size,
            "ttl": response.qos.ttl,
            "ksid": response.ksid,
            "status": Status(response.status)
        }
        return response

    def get_key(self, ksid, index=None):
        """get_key in ETSI QKD GS 004.

        Args:
            ksid (bytes): ksid. It must be a 16 byte array
            index (int, optional): index of the key or None for the last one. Defaults to None.

        Returns:
            The parameters as described in the standard.
        """
        request = None
        if index is None:
            request = interfaces_pb2.GetKeyRequest(ksid=ksid, metadata_size=100)
        else:
            request = interfaces_pb2.GetKeyRequest(ksid=ksid, index=index, metadata_size=100)
        response = self.channel.get_key(request)
        response = {
            "index": response.index,
            "key_buffer": response.key_buffer,
            "metadata": response.metadata_buffer,
            "status": Status(response.status)
        }
        return response

    def close(self, ksid):
        """get_key in ETSI QKD GS 004.

        Args:
            ksid (bytes): ksid. It must be a 16 byte array

        Returns:
            Status: status as defined in the standard
        """
        request = interfaces_pb2.CloseRequest(ksid=ksid)
        response = self.channel.close(request)
        return Status(response.status)

    def disconnect(self):
        """Disconnect from the server
        
        """
        self.c.close()
