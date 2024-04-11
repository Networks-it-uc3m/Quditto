from simulaqron.network import Network
from simulaqron.settings import Config as SimulaqronConfig
import tempfile
import asyncio
import queue
import socket
import random
from concurrent.futures import ThreadPoolExecutor
import json
import threading
from cqc.pythonLib import CQCConnection, qubit, CQCTimeoutError
import base64
import time

import logging
import bitarray


def init():
    global logger
    logger = logging.getLogger(__name__)


class QBackend:
    """The Quantum backend class

    The Quantum backend class is in charge of exchanging the keys through simulqron
    with other quantum nodes in the network.
    
    """

    def __init__(self, config):
        self.simul_network_file_path = None
        self.qkd_executors = None
        self.qnetwork = None
        self.muxdemux = None
        self.config = config

    def start(self):
        """It starts the backend

        The method blocks until all the backend links have been established and the 
        backend is fully functional. It raises an exception if any error happens
        """
        logger.debug("Creating temporary file with simulaqron network configuration")
        with tempfile.NamedTemporaryFile(mode="w+", delete=False, encoding='utf-8',
                                         suffix=".json") as simul_network_file:
            self.simul_network_file_path = simul_network_file.name
            simulaqron_network_config = QBackend.generate_simulaqron_config(self.config)
            logger.debug("Simulaqron conf: \n" + simulaqron_network_config)
            simul_network_file.write(simulaqron_network_config)

        simulaqron_config_set = {
            "_read_user": "False",
            "max_qubits": 1000,
            "max_registers": 1000,
            "conn_retry_time": 0.5,
            "recv_timeout": 100,  # (x 100 ms)
            "recv_retry_time": 0.1,  # (seconds)
            "log_level": "logging.WARNING",
            "backend": "\"stabilizer\"",
            "network_config_file": "r\"" + self.simul_network_file_path + "\"",
            "app_file": "None",
            "cqc_file": "None",
            "vnode_file": "None",
            "nodes_file": "None",
            "topology_file": "None",
            "noisy_qubits": "False",
            "t1": "1.0"
        }

        logger.debug("Updating simulaqron configuration")
        simulaqron_config = SimulaqronConfig()
        for (key, value) in simulaqron_config_set.items():
            exec("simulaqron_config." + key + " = " + str(value))
        simulaqron_config.update_settings()

        node_name = self.config.node_name
        try:
            self.qnetwork = Network(name="default", nodes=[node_name], force=True, new=False)
            logger.info("Starting the simulaqron network")
            self.qnetwork.start(wait_until_running=True)
            logger.info("Simulaqron network succesfully started")
            logger.info("Starting qkd process executors")
            self.qkd_executors = {}
            for (node_name, _, _) in self.config.neighbours:
                logger.info("Starting pool executor for " + node_name)
                self.qkd_executors[node_name] = ThreadPoolExecutor(max_workers=1)
            logger.info("Starting quantum muxdemux")
            self.muxdemux = QuantumMuxDemux(self.config)
            self.muxdemux.start()
        except Exception:
            logger.exception("Exception while initializing simulaqron")

    def stop(self):
        """This method stops the quantum backend
        
        All the components are stopped and the simulaqron config is set
        to default.
        """
        logger.info("Stopping simulaqron network")
        self.qnetwork.stop()
        logger.info("Simulaqron network stopped")
        logger.debug("Setting simulaqron settings to default")
        simulaqron_config = SimulaqronConfig()
        simulaqron_config.update_settings(default=True)
        logger.info("Stopping quantum muxdemux")
        self.muxdemux.stop()

    async def exchange_key(self, ksid, dst_node, byte_length):
        logger.debug("Exchange key for KSID: " + str(ksid) + " has been called")
        loop = asyncio.get_event_loop()
        task = lambda: self.exchange_key_blocking_as_initiator(dst_node, ksid, byte_length)
        result = await loop.run_in_executor(self.qkd_executors[dst_node], task)
        return result

    async def wait_for_key(self, dst_node):
        loop = asyncio.get_event_loop()
        task = lambda: self.exchange_key_blocking_as_waiter(dst_node)
        result = await loop.run_in_executor(self.qkd_executors[dst_node], task)
        logger.info("New key received from " + str(dst_node))
        return result

    def exchange_key_blocking_as_initiator(self, dst_node, ksid, byte_length):
        node_id = self.config.node_id
        remote_node_id = self.config.get_node_id(dst_node)
        logger.info("Exchanging key as initiator for KSID " + str(ksid))
        start = time.time()

        try:
            self.muxdemux.send_classical(dst_node, ksid)
            self.muxdemux.recv_classical(dst_node)
            self.muxdemux.send_classical(dst_node, bytes((byte_length,)))
            key_bits = ""
            discarded_bits = 0
            good_bits = 0
            while good_bits != byte_length * 8:
                logger.debug("Creating EPR with " + dst_node)
                base = random.randint(0, 2)
                m = None
                sent = False
                while not sent:
                    try:
                        with CQCConnection(self.config.node_name,  appID=remote_node_id) as node:
                            q = node.createEPR(dst_node, remote_appID=node_id)
                            # Not even necessary to measure in another basis, just simulate it
                            m = q.measure()
                            sent = True
                    except:
                        pass
                b = '0' if m == 0 else '1'
                self.muxdemux.send_classical(dst_node, (base,))
                logger.debug("EPR created and based sent. Waiting for remote base")
                (base_remote,) = self.muxdemux.recv_classical(dst_node)
                if base_remote == base:
                    logger.debug("Bit: " + str(b))
                    key_bits = key_bits + b
                    good_bits = good_bits + 1
                else:
                    logger.debug("Discarded bit")
                    discarded_bits = discarded_bits + 1
            key = bytes(bitarray.bitarray(key_bits))
            end = time.time()
            exchange_duration = (end - start)
            return key, exchange_duration, discarded_bits
        except Exception:
            logger.exception("Exception when exchanging key as initiator")

    def exchange_key_blocking_as_waiter(self, dst_node):
        node_id = self.config.get_node_id(dst_node)
        logger.info("Exchanging key as waiter for node " + str(dst_node))
        start = time.time()

        try:
            ksid = self.muxdemux.recv_classical(dst_node)
            logger.debug("Starting to receive key for KSID " + str(ksid) + " as a waiter")
            self.muxdemux.send_classical(dst_node, b"a")
            (size,) = self.muxdemux.recv_classical(dst_node)
            logger.debug("Key for KSID " + str(ksid) + " will be " + str(size) + " bytes long")
            key_bits = ""
            good_bits = 0
            discarded_bits = 0

            while good_bits != (size * 8):
                logger.debug("Receiving bit")
                base = random.randint(0, 2)
                m = None
                received = False
                while not received:
                    try:
                        with CQCConnection(self.config.node_name, appID=node_id) as node:
                            q = node.recvEPR()
                            m = q.measure()
                            received = True
                    except Exception:
                        pass
                logger.debug("Received EPR")
                b = '0' if m == 0 else '1'
                (remote_base, ) = self.muxdemux.recv_classical(dst_node)
                if remote_base == base:
                    logger.debug("Bit :" + str(b))
                    key_bits = key_bits + b
                    good_bits = good_bits + 1
                else:
                    discarded_bits = discarded_bits + 1
                    logger.debug("Discarded qbit")
                self.muxdemux.send_classical(dst_node, (base,))
            key = bytes(bitarray.bitarray(key_bits))
            end = time.time()
            exchange_duration = end - start
            return ksid, key, exchange_duration, discarded_bits
        except Exception:
            logger.exception("Exception when exchanging key as waiter")

    def sendQubit(self, cqc, dst_node, q):
        """
        qA = cqc.createEPR(dst_node)
        q.cnot(qA)
        q.H()
        a = q.measure()
        b = qA.measure()
        self.muxdemux.send_classical(dst_node, (a, b))
        logger.debug("Sent qubit to " + dst_node)
        """
        pass

    def recvQubit(self, dst_node):
        """
        qB = self.muxdemux.recv_EPR(dst_node)
        data = self.muxdemux.recv_classical(dst_node)
        message = list(data)
        a = message[0]
        b = message[1]
        if b == 1: qB.X()
        if a == 1: qB.Z()
        logger.debug("Received qubit from " + dst_node)
        return qB
        """

    def generate_simulaqron_config(config):
        nodes = {config.node_name: QBackend.generate_simulaqron_node_config(config.node_ip)}
        for (node_name, node_ip, _) in config.neighbours:
            nodes[node_name] = QBackend.generate_simulaqron_node_config(node_ip)
        config_dict = {"default": {"nodes": nodes, "topology": None}}
        return json.dumps(config_dict)

    def generate_simulaqron_node_config(ip):
        config_dict = {"app_socket": [ip, 8000], "cqc_socket": [ip, 8001], "vnode_socket": [ip, 8002]}
        return config_dict


class QuantumMuxDemux:

    def __init__(self, config):
        self.classical_thread = None
        self.classical_buffer = {}
        for (name, _, _) in config.neighbours:
            self.classical_buffer[name] = queue.Queue()
        self.config = config
        self.stop_event = threading.Event()
        self.lock = threading.Lock()

    def start(self):
        self.classical_thread = threading.Thread(target=self.classical_receiver_thread_loop)
        self.classical_thread.start()

    def stop(self):
        self.stop_event.set()
        self.classical_thread.join()

    def classical_receiver_thread_loop(self):
        logger.info("Starting classical receiver thread loop")
        serversocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # bind the socket to a public host, and a well-known port
        serversocket.bind((self.config.node_ip, 9999))
        serversocket.listen(100)
        while True:
            (clientsocket, address) = serversocket.accept()
            try:
                data = b''
                recve = False
                while not recve:
                    part = clientsocket.recv(1)
                    data += part
                    if len(part) < 1:
                        recve = True
                recv_mes = data
                clientsocket.close()
                logger.debug("Classical message received. Demultiplexing...")
                recv_json = json.loads(recv_mes.decode())
                host = recv_json["node_name"]
                value = base64.b64decode(recv_json["value"])
                logger.info("Received classical message from " + host + ": " + str(value))
                self.classical_buffer[host].put(value)
            except Exception:
                logger.exception("Exception while receiving classical message")
        logger.info("Classical receiver thread loop stopping")

    def recv_classical(self, remote_node):
        return self.classical_buffer[remote_node].get()

    def send_classical(self, remote_name, value):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect((self.config.get_node_ip(remote_name), 9999))
            prepared_value = base64.b64encode(bytes(value)).decode()
            data = {"node_name": self.config.node_name, "value": prepared_value}
            data_json = json.dumps(data)
            s.send(data_json.encode())
            s.close()
        except:
            logger.exception("Exception while sending classical message")
