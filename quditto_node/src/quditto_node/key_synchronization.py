import asyncio
import logging


def init():
    global logger
    logger = logging.getLogger(__name__)


class KeySynchronizationSubsystem:

    def __init__(self, config, database, backend):
        self.key_waiters = None
        self.config = config
        self.database = database
        self.backend = backend

    def start(self, waiter_for_nodes):
        self.key_waiters = []
        for n in waiter_for_nodes:
            logger.info("Creating waiting key stream loop for " + str(n))
            self.key_waiters.append(asyncio.ensure_future(self.waiter_key_stream_loop(n)))

    def stop(self):
        logger.info("Stopping the key synchronization subsystem")
        for t in self.key_waiters:
            t.cancel()

    async def delete_key_on_timeout(self, ksid, index, ttl):
        await asyncio.sleep(ttl)
        logger.info("Deleting key of KSID " + str(ksid) + " and index " + str(index) + " because it exceeds the TTL")
        await self.database.lock_stream_id(ksid)
        await self.database.get_key(ksid, index)
        await self.database.unlock_stream_id(ksid)

    async def waiter_key_stream_loop(self, dst_node):
        try:
            while True:
                logger.debug("Waiter key stream loop for " + dst_node + " waiting for a key")
                (ksid, new_key, exchange_time, discarded_bits) = await self.backend.wait_for_key(dst_node)
                logger.debug("New key no waiter key stream loop " + dst_node + " for KSID " + str(ksid))
                await self.database.lock_stream_id(ksid)
                if await self.database.key_stream_exists(ksid):
                    ttl = await self.database.get_ttl(ksid)
                    index = await self.database.push_key(ksid, new_key, exchange_time, discarded_bits)
                    asyncio.ensure_future(self.delete_key_on_timeout(ksid, index, ttl))
                await self.database.unlock_stream_id(ksid)
        except Exception:
            logger.exception("Exception in waiter key stream")

    async def initiator_key_stream_loop(self, ksid, dst_node, bit_length, ttl):

        while True:
            logger.debug("Initiator key stream loop for KSID" + str(ksid) + " waiting for free space for keys")
            await self.database.wait_key_stream(ksid)
            logger.debug("Initiator key stream loop for KSID" + str(ksid) + " has been notified of new space")
            await self.database.lock_stream_id(ksid)
            exists = await self.database.key_stream_exists(ksid)
            await self.database.unlock_stream_id(ksid)
            if not exists:
                break
            logger.debug("Initiator key stream loop for KSID" + str(ksid) + " will now exchange a key")
            new_key, exchanging_time, discarded_bits = await self.backend.exchange_key(ksid, dst_node, bit_length)
            logger.debug("Initiator key stream loop for KSID" + str(ksid) + " has exchanged a key")
            await self.database.lock_stream_id(ksid)
            exists = await self.database.key_stream_exists(ksid)
            if not exists:
                await self.database.unlock_stream_id(ksid)
                break
            index = await self.database.push_key(ksid, new_key, exchanging_time, discarded_bits)
            await self.database.unlock_stream_id(ksid)
            asyncio.ensure_future(self.delete_key_on_timeout(ksid, index, ttl))

    async def notify_new_key_stream(self, ksid, dst_node, bit_length, ttl):
        logger.debug("Notifying new key space for KSID " + str(ksid))
        asyncio.ensure_future(self.initiator_key_stream_loop(ksid, dst_node, bit_length, ttl))
        await self.database.start_exchanging_keys(ksid)
