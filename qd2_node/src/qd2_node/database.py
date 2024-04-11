import logging
import queue
import time
from asyncio import Lock, Condition, Semaphore


def init():
    global logger
    logger = logging.getLogger(__name__)


QUEUE_MAX_SIZE = 5


class _Key:

    def __init__(self, buffer, exchange_duration, discarded_bits):
        self.creation_time = time.time()
        self.buffer = buffer
        self.exchange_duration = exchange_duration
        self.discarded_bits = discarded_bits


class _KeyStream:

    def __init__(self, src, dst, key_chunk_size, timeout, ttl):
        self.src = src
        self.dst = dst
        self.ttl = ttl
        self.event_queue = queue.Queue()
        self.timeout = timeout
        self.key_chunk_size = key_chunk_size
        self.queue = queue.Queue()
        self.oldest_added_index = 0
        self.newest_added_index = -1
        self.available_spaces = Semaphore(value=0)


class ApplicationURI:
    def __init__(self, uri):
        self.uri = uri

    def is_correct(self):
        return len(self.uri.split("@")) == 2

    def get_app(self):
        return self.uri.split("@")[0]

    def get_server(self):
        return self.uri.split("@")[1]


class Database:

    def __init__(self, config):
        self.key_streams = {}
        self.database_lock = Lock()
        self.ksid_locks = {}
        self.ksid_locks_counters = {}
        self.config = config

    async def lock_stream_id(self, ksid):
        logger.debug("Locking KSID: " + str(ksid))
        await self.database_lock.acquire()
        if ksid not in self.ksid_locks:
            self.ksid_locks[ksid] = Condition()
            self.ksid_locks_counters[ksid] = 0
        lock = self.ksid_locks[ksid]
        self.ksid_locks_counters[ksid] += 1
        self.database_lock.release()
        await lock.acquire()
        logger.debug("KSID: " + str(ksid) + " locked")

    async def unlock_stream_id(self, ksid):
        logger.debug("Unlocking KSID: " + str(ksid))
        await self.database_lock.acquire()
        lock = self.ksid_locks[ksid]
        lock.release()
        self.ksid_locks_counters[ksid] -= 1
        if self.ksid_locks_counters[ksid] == 0:
            self.ksid_locks.pop(ksid)
            self.ksid_locks_counters.pop(ksid)
        self.database_lock.release()
        logger.debug("KSID: " + str(ksid) + "unlocked")

    async def key_stream_has_no_keys(self, ksid):
        return self.key_streams[ksid].queue.qsize() == 0

    async def set_key_stream_open_status(self, ksid, status):
        self.key_streams[ksid].open = status

    async def key_stream_is_open(self, ksid):
        return self.key_streams[ksid].open

    async def start_exchanging_keys(self, ksid):
        logger.debug("Creating slots for KSID: " + str(ksid))
        for _ in range(QUEUE_MAX_SIZE):
            self.key_streams[ksid].available_spaces.release()

    async def return_free_space(self, ksid):
        logger.debug("Returning slot for KSID: " + str(ksid))
        self.key_streams[ksid].available_spaces.release()

    async def wait_key_stream(self, ksid):
        await self.lock_stream_id(ksid)
        if ksid not in self.key_streams:
            return
        sem = self.key_streams[ksid].available_spaces
        await self.unlock_stream_id(ksid)
        logger.debug("Waiting for space in KSID: " + str(ksid))
        await sem.acquire()
        logger.debug("Received new space notification in KSID: " + str(ksid))

    async def register_key_stream(self, ksid, src, dst, key_chunk_size, timeout, ttl):
        logger.debug("Registering KSID: " + str(ksid))
        key_stream = _KeyStream(src, dst, key_chunk_size, timeout, ttl)
        self.key_streams[ksid] = key_stream

    async def delete_key_stream(self, ksid):
        logger.debug("Deleting KSID: " + str(ksid))
        key_s = self.key_streams.pop(ksid)
        key_s.available_spaces.release()

    async def key_stream_exists(self, ksid):
        return ksid in self.key_streams

    async def check_application_in_ksid(self, ksid, app_id):
        result = False
        if ksid in self.key_streams:
            key_stream = self.key_streams[ksid]
            if app_id == key_stream.src or app_id == key_stream.dst:
                result = True
        return result

    async def get_key_chunk_size(self, ksid):
        ks = self.key_streams[ksid]
        return ks.key_chunk_size

    async def get_other_host(self, ksid):
        ks = self.key_streams[ksid]
        src = ks.src.get_server()
        dst = ks.dst.get_server()
        if self.config.node_name == src:
            return dst
        return src

    async def get_ttl(self, ksid):
        if ksid not in self.key_streams:
            return None
        ttl = self.key_streams[ksid].ttl

        return ttl

    async def get_destination(self, ksid):
        if ksid not in self.key_streams:
            return None
        destination = self.key_streams[ksid].dst

        return destination

    async def get_source(self, ksid):
        if ksid not in self.key_streams:
            return None
        source = self.key_streams[ksid].src

        return source

    async def get_key(self, ksid, index=None):
        logger.debug("Retrieving key from KSID: " + str(ksid))
        available = 0
        if ksid not in self.key_streams:
            return None
        key_stream = self.key_streams[ksid]
        key = None
        if index is None:
            if await self.key_stream_has_no_keys(ksid):
                return None
            key = key_stream.queue.get()
            index = key_stream.oldest_added_index
            available = 1
        else:
            if not key_stream.oldest_added_index <= index <= key_stream.newest_added_index:
                key = None
            elif len(key_stream.queue) == 0:
                key = None
            else:
                queue_index = index - key_stream.oldest_added_index
                for _ in range(key_stream.oldest_added_index, index):
                    await key_stream.queue.get()
                    available = available + 1
                key = await key_stream.queue.get()
                available = available + 1
        if key is None:
            return None
        key_stream.oldest_added_index = index + 1
        for _ in range(available):
            key_stream.available_spaces.release()
        return key.buffer, key.creation_time, key.exchange_duration, key.discarded_bits, index

    async def push_key(self, ksid, new_key, exchanging_time, discarded_bits):
        logger.debug("Pushing new key into KSID: " + str(ksid) + ". Key: " + str(new_key))
        if ksid not in self.key_streams:
            return
        key_stream = self.key_streams[ksid]
        key_stream.newest_added_index += 1
        key_stream.queue.put(_Key(new_key, exchanging_time, discarded_bits))
        return key_stream.newest_added_index
