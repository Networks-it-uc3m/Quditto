import logging
import grpc
import secrets
from concurrent import futures
from qd2_node.grpc_serialization import interfaces_pb2
from enum import Enum
from qd2_node.grpc_serialization import interfaces_pb2_grpc
from qd2_node.database import ApplicationURI
import json


def init():
    global logger
    logger = logging.getLogger(__name__)


APPLICATION_INTERFACE_PORT = "31942"
MANAGEMENT_INTERFACE_PORT = "31973"

APPLICATION_INTERFACE_ADDRESS = "0.0.0.0" + ":" + APPLICATION_INTERFACE_PORT
MANAGEMENT_INTERFACE_ADDRESS = "0.0.0.0" + ":" + MANAGEMENT_INTERFACE_PORT


class _GRPCApplicationInterface(interfaces_pb2_grpc.ApplicationInterfaceServicer):
    class Status(Enum):
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

    def __init__(self, database, config, key_synchronizator):
        self.database = database
        self.config = config
        self.key_synchronizator = key_synchronizator

    async def open_connect(self, request, context):
        """gRPC OPEN_CONNECT method from ETSI GS QKD 004 V2.1.1 (2020-08).

        It sanitizes the request, executes the internal sanitized method and
        adapts to response.
        """

        try:
            logger.info("New open_connect request received: \n" + str(request))
            logger.debug("Validating arguments")
            error_message = None
            if len(request.source) > 2000 or len(request.destination) > 2000:
                error_message = "URLs must be 2000 UTF-8 characters long or less"
            source = ApplicationURI(request.source)
            destination = ApplicationURI(request.destination)
            if (not source.is_correct()) or (not destination.is_correct()):
                error_message = "Incorrect URI"
            if request.HasField("ksid") and len(request.ksid) != 16:
                error_message = "Incorrect KSID"
            if len(request.qos.metadata_mimetype) > 128:
                error_message = "Incorrect mimetype"
            if error_message is not None:
                logger.debug("Error in argument: " + error_message)
                logger.debug("Sending gRPC INVALID_ARGUMENT status")
                await context.abort(grpc.StatusCode.INVALID_ARGUMENT, error_message)
            logger.debug("All arguments are correct")
            internal_req_src = source
            internal_req_dst = destination
            internal_req_qos = {
                "key_chunk_size": request.qos.key_chunk_size,
                "timeout": request.qos.timeout,
                "ttl": request.qos.ttl,
                "metadata_mimetype": request.qos.metadata_mimetype
            }

            internal_req_ksid = request.ksid if request.HasField("ksid") else None

            internal_resp_qos, internal_resp_ksid, internal_resp_status = await self.sanitized_open_connect(
                internal_req_src,
                internal_req_dst,
                internal_req_qos,
                internal_req_ksid)

            wire_ksid = b"" if internal_resp_ksid is None else internal_resp_ksid

            if internal_resp_qos is not None:
                resp_key_chunk_size = internal_resp_qos["key_chunk_size"]
                resp_timeout = internal_resp_qos["timeout"]
                resp_ttl = internal_resp_qos["ttl"]
                resp_metadata_mimetype = internal_resp_qos["metadata_mimetype"]
            else:
                resp_key_chunk_size = 0
                resp_priority = 0
                resp_timeout = 0
                resp_ttl = 0
                resp_metadata_mimetype = ""

            wire_qos = interfaces_pb2.QoS(key_chunk_size=resp_key_chunk_size,
                                          timeout=resp_timeout,
                                          ttl=resp_ttl,
                                          metadata_mimetype=resp_metadata_mimetype)
            wire_status = internal_resp_status.value

            response = interfaces_pb2.OpenConnectResponse(qos=wire_qos, ksid=wire_ksid, status=wire_status)

            logger.info("Sending response: " + str(response))
            return response

        except Exception:
            logger.exception("Exception in open connect handler", exc_info=True)
            await context.abort(grpc.StatusCode.INTERNAL, "Internal error.")

    async def get_key(self, request, context):
        """gRPC GET_KEY method from ETSI GS QKD 004 V2.1.1 (2020-08).

        It sanitizes the request, executes the internal sanitized method and
        adapts to response.
        """
        logger.info("New GET_KEY request received:\n" + str(request))
        if len(request.ksid) != 16:
            logger.debug("Incorrect size for KSID argument")
            logger.debug("Sending gRPC INVALID_ARGUMENT status")
            await context.abort(grpc.StatusCode.INVALID_ARGUMENT, "Incorrect KSID")
        index, key_buffer, metadata, status = await self.sanizitized_get_key(request.ksid, request.index,
                                                                             request.metadata_size)
        response = interfaces_pb2.GetKeyResponse(index=index, key_buffer=key_buffer, metadata_buffer=metadata,
                                                 status=status.value)
        logger.info("Sending response: " + str(response))
        return response

    async def close(self, request, context):
        """gRPC Close method from ETSI GS QKD 004 V2.1.1 (2020-08).

        It sanitizes the request, executes the internal sanitized method and
        adapts to response.
        """
        logger.info("New CLOSE request received" + str(request))
        if len(request.ksid) != 16:
            await context.abort(grpc.StatusCode.INVALID_ARGUMENT, "Incorrect KSID")
        status = await self.sanitized_close(request.ksid)
        response = interfaces_pb2.CloseResponse(status=status.value)
        logger.info("Sending response: " + str(response))
        return response

    async def sanitized_open_connect(self, source, destination, qos: dict, ksid: bytes):
        """OPEN_CONNECT method from ETSI GS QKD 004 V2.1.1 (2020-08).
        
        In case the ksid is provided as an input parameter, the same ksid is returned
        as an output parameter. In case an error is set in the status, the ksid and the qos
        will be set to None. The caller of this function must set the ksid to None if there
        is not one.

        Args:
            source: source
            destination: destination
            qos (qos): QoS
            ksid (bytes): key_stream_id

        Returns:
            tuple[QOS, bytes, ApplicationInterfaceStatus]:
                A tuple that contains the following output values:
                    - QoS
                    - ksid
                    - status
        """
        assert (type(qos) == dict and
                type(qos.get("key_chunk_size")) == int and 0 <= qos.get("key_chunk_size") <= 4294967295 and
                type(qos.get("timeout")) == int and 0 <= qos.get("timeout") <= 4294967295 and
                type(qos.get("ttl")) == int and 0 <= qos.get("ttl") <= 4294967295 and
                type(qos.get("metadata_mimetype")) == str and len(qos.get("metadata_mimetype")) <= 128)
        assert (ksid is None or (type(ksid) == bytes and len(ksid) == 16))

        logger.debug("Making sure the qos parameters are allowed")
        if qos["metadata_mimetype"] != "application/json":
            qos["metadata_mimetype"] = "application/json"
            logger.info("Not supported mimetype, answering with an error")
            return qos, ksid, _GRPCApplicationInterface.Status.OPEN_FAILED_QOS
        other_server = destination.get_server()
        if source.get_server() != self.config.node_name:
            other_server = source.get_server()

        if other_server < self.config.node_name:
            initiator = False
        else:
            initiator = True

        exists = await self.database.key_stream_exists(ksid)
        if ksid is not None and exists:
            await self.database.lock_stream_id(ksid)
            registered_source = (await self.database.get_source(ksid)).uri
            registered_destination = (await self.database.get_destination(ksid)).uri
            if not (source.uri == registered_source and destination.uri == registered_destination):
                logger.info("The KSID " + str(ksid) + " requested is already associated to another set of applications")
                status = _GRPCApplicationInterface.Status.OPEN_CONNECT_FAILED_KSID_IN_USE
                await self.database.unlock_stream_id(ksid)
                return None, None, status
            logger.info("The KSID " + str(ksid) + " was already created by the remote application. Opening it")
            await self.database.set_key_stream_open_status(ksid, True)
            remote = await self.database.get_other_host(ksid)
            if initiator:
                await self.key_synchronizator.notify_new_key_stream(ksid, remote, qos["key_chunk_size"], qos["ttl"])
            ip = self.config.get_node_ip(remote)
            await send_app_open(ip, ksid)
            await self.database.unlock_stream_id(ksid)
            return qos, ksid, _GRPCApplicationInterface.Status.SUCCESSFUL

        elif (ksid is not None and not exists) or ksid is None:

            if ksid is None:
                # If a random 16-byte id is in use, just return timeout (what are the odds anyway?)
                ksid = await get_random_ksid()

                logger.info("New KSID generated: " + str(ksid))

                if await self.database.key_stream_exists(ksid):
                    status = _GRPCApplicationInterface.Status.TIMEOUT_ERROR
                    return None, None, status
            await self.database.lock_stream_id(ksid)
            await self.database.register_key_stream(ksid, source, destination, qos["key_chunk_size"], qos["timeout"],
                                                    qos["ttl"])

            try:
                management_status = await self.send_new_application(other_server, source, destination, ksid,
                                                                    qos["key_chunk_size"], qos["timeout"], qos["ttl"])
            except Exception:
                logger.exception("Send new application for KSID: " + str(ksid) + "raised an exception")
                status = _GRPCApplicationInterface.Status.TIMEOUT_ERROR
                await self.database.delete_key_stream(ksid)
                await self.database.unlock_stream_id(ksid)
                return None, None, status
            if management_status == _GRPCKeyManagementInterface.Status.OK:
                await self.database.unlock_stream_id(ksid)
                return qos, ksid, _GRPCApplicationInterface.Status.SUCCESSFUL_NO_PEER
            elif management_status == _GRPCKeyManagementInterface.Status.KSID_NOT_AVAILABLE:
                status = _GRPCApplicationInterface.Status.TIMEOUT_ERROR
                await self.database.delete_key_stream(ksid)
                await self.database.unlock_stream_id(ksid)
                return None, None, status

    async def sanizitized_get_key(self, ksid: bytes, index: int, metadata_size: int):
        """GET_KEY method from ETSI GS QKD 004 V2.1.1 (2020-08).

        Args:
            ksid (bytes): key_stream_id
            index (int): Index
            metadata_size (int): size of metadata

        Returns:
            tuple[int, bytes, bytes, ApplicationInterfaceStatus]:
                A tuple that contains the following output values:
                    - Index
                    - Key_buffer
                    - Metadata
                    - status
        """
        assert (type(index) == int and 0 <= index <= 4294967295)
        assert (type(ksid) == bytes and len(ksid) == 16)
        assert (type(metadata_size) == int and 0 <= metadata_size <= 4294967295)
        if not metadata_size >= 25:
            logger.info("Get key was called for KSID " + str(ksid) + " but metadata size is insufficient")
            return 0, b"", b"", _GRPCApplicationInterface.Status.GET_KEY_FAILED_METADATA_INSUFFICIENT

        await self.database.lock_stream_id(ksid)

        if not await self.database.key_stream_exists(ksid):
            await self.database.unlock_stream_id(ksid)
            return 0, b"", b"", _GRPCApplicationInterface.Status.STREAM_NOT_FOUND

        if not await self.database.key_stream_is_open(ksid):
            logger.warning("Get key was called for KSID " + str(ksid) + " but the peer is not connected")
            await self.database.unlock_stream_id(ksid)
            return 0, b"", b"", _GRPCApplicationInterface.Status.GET_KEY_FAILED_PEER_NOT_CONNECTED

        key = await self.database.get_key(ksid)
        await self.database.unlock_stream_id(ksid)
        if key is None:
            logger.info("No key available, sending insufficient key")
            return 0, b"", b"", _GRPCApplicationInterface.Status.GET_KEY_FAILED_INSUFFICIENT_KEY
        (buffer, creation_time, exchange_time, discarded_bits, index) = key
        metadata = {
            "created_time": str(creation_time),
            "exchange_duration": exchange_time,
            "discarded_bits": discarded_bits
        }
        metadata = json.dumps(metadata)
        return index, buffer, metadata.encode(), _GRPCApplicationInterface.Status.SUCCESSFUL

    async def sanitized_close(self, ksid: bytes):
        """CLOSE method from ETSI GS QKD 004 V2.1.1 (2020-08).

        Args:
            ksid (bytes): key_stream_id

        Returns:
            ApplicationInterfaceStatus: status
        """
        assert (type(ksid) == bytes and len(ksid) == 16)
        await self.database.lock_stream_id(ksid)
        if not await self.database.key_stream_exists(ksid):
            await self.database.unlock_stream_id(ksid)
            return _GRPCApplicationInterface.Status.STREAM_NOT_FOUND
        await self.database.delete_key_stream(ksid)
        await self.database.unlock_stream_id(ksid)
        return _GRPCApplicationInterface.Status.SUCCESSFUL

    async def send_new_application(self, other_server, src, dst, ksid, key_chunk_size, timeout, ttl):
        src = src.uri
        dst = dst.uri
        ip = self.config.get_node_ip(other_server)
        assert (ip is not None)

        logger.info("Opening key management connection with node:" + dst + "with IP " + str(ip))
        async with grpc.aio.insecure_channel(str(ip) + ":" + MANAGEMENT_INTERFACE_PORT) as channel:
            stub = interfaces_pb2_grpc.InterKMEInterfaceStub(channel)
            logger.info("Sending new_app request: src:" + src + ", dst: " + dst + " to IP " + str(ip))
            new_app_request = interfaces_pb2.NewAppRequest(source=src, destination=dst, ksid=ksid,
                                                           key_chunk_size=key_chunk_size, timeout=timeout, ttl=ttl)
            response = await stub.new_app(new_app_request)
            logger.info("Response from " + str(ip) + ": " + str(response))
        return _GRPCKeyManagementInterface.Status(response.status)


async def send_app_open(ip, ksid):
    logger.debug("Sending app open to ip " + str(ip) + " for ksid " + str(ksid))
    async with grpc.aio.insecure_channel(str(ip) + ":" + MANAGEMENT_INTERFACE_PORT) as channel:
        stub = interfaces_pb2_grpc.InterKMEInterfaceStub(channel)
        request = interfaces_pb2.AppOpenRequest(ksid = ksid)
        await stub.app_open(request)


async def get_random_ksid():
    return secrets.token_bytes(16)


class _GRPCKeyManagementInterface(interfaces_pb2_grpc.InterKMEInterfaceServicer):
    class Status(Enum):
        OK = 0
        KSID_NOT_AVAILABLE = 1

    def __init__(self, database, config, key_synchronizator):
        self.database = database
        self.key_synchronizator = key_synchronizator
        self.config = config

    async def new_app(self, request, context):
        logger.debug("New new_app received: \n" + str(request))
        await self.database.lock_stream_id(request.ksid)
        if await self.database.key_stream_exists(request.ksid):
            await self.database.set_key_stream_open_status(request.ksid, True)
            remote_node = await self.database.get_other_host(request.ksid)
            remote_ip = self.config.get_node_ip(remote_node)
            await send_app_open(remote_ip, request.ksid)
        else:
            await self.database.register_key_stream(request.ksid, ApplicationURI(request.source), ApplicationURI(request.destination),
                                                    request.key_chunk_size, request.timeout, request.ttl)
        await self.database.unlock_stream_id(request.ksid)
        status = _GRPCKeyManagementInterface.Status.OK.value
        response = interfaces_pb2.NewAppResponse(status=status)
        return response

    async def app_open(self, request, context):
        logger.debug("New app open received: \n" + str(request))
        await self.database.lock_stream_id(request.ksid)
        await self.database.set_key_stream_open_status(request.ksid, True)
        remote_node = await self.database.get_other_host(request.ksid)
        if remote_node > self.config.node_name:
            logger.debug("This node is initiator for KSID " + str(request.ksid))
            kcs = await self.database.get_key_chunk_size(request.ksid)
            ttl = await self.database.get_ttl(request.ksid)
            await self.database.set_key_stream_open_status(request.ksid, True)
            await self.key_synchronizator.notify_new_key_stream(request.ksid, remote_node, kcs, ttl)
        await self.database.unlock_stream_id(request.ksid)
        response = interfaces_pb2.AppOpenResponse()
        return response


class KeyManagementSubsystem:
    """The class implementing the QKD application interface
    
    Class that implements the QKD application interface defined in
    ETSI GS QKD 004 V2.1.1 (2020-08). 
    
    All the inputs to all the functions whose name starts
    with "sanitized" in this class MUST be sanitized. 

    The three defined sanitized methods match to the API functions of from ETSI GS QKD 004 V2.1.1 (2020-08).
    Refer to ETSI GS QKD 004 V2.1.1 (2020-08) to understand each parameter and output.

    The matching types between python variable and ETSI GS QKD 004 V2.1.1 (2020-08) can be extracted from the 
    assertions.
    """

    def __init__(self, config, database, key_synchronizator):
        self.management_server = None
        self.application_server = None
        self.config = config
        self.database = database
        self.key_synchronizator = key_synchronizator

    async def start(self):
        self.application_server = grpc.aio.server()
        grp_servicer = _GRPCApplicationInterface(self.database, self.config, self.key_synchronizator)
        interfaces_pb2_grpc.add_ApplicationInterfaceServicer_to_server(grp_servicer, self.application_server)
        self.application_server.add_insecure_port(APPLICATION_INTERFACE_ADDRESS)
        await self.application_server.start()

        self.management_server = grpc.aio.server()
        grp_servicer = _GRPCKeyManagementInterface(self.database, self.config, self.key_synchronizator)
        interfaces_pb2_grpc.add_InterKMEInterfaceServicer_to_server(grp_servicer, self.management_server)
        self.management_server.add_insecure_port(MANAGEMENT_INTERFACE_ADDRESS)
        await self.management_server.start()

    async def stop(self):
        await self.application_server.stop(15)
        await self.management_server.stop(15)
