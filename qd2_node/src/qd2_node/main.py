import logging
import sys
import os
from datetime import datetime

import asyncio
import qd2_node.backend as backend
import qd2_node.key_synchronization as key_synchronization
import qd2_node.configuration as configuration
import qd2_node.database as database
import qd2_node.key_management as key_management

import time
import aioconsole
import daemon
from logging.handlers import QueueListener
from logging import FileHandler, StreamHandler
import queue
from logging.handlers import QueueHandler

CONFIG_FILE = os.path.join(os.getcwd(), "config.json")


def init():
    # https://stackoverflow.com/questions/45842926/python-asynchronous-logging

    global logger

    log_queue = queue.Queue()
    queue_handler = QueueHandler(log_queue)

    logger = logging.getLogger("qd2_node")

    logger.setLevel(logging.DEBUG)
    log_file_name = "qd2_log" + str(int(time.time())) + ".log"
    file_handler_path = os.path.join(os.getcwd(), log_file_name)
    file_handler = FileHandler(file_handler_path)
    formatter = logging.Formatter('%(asctime)s : %(levelname)s : %(name)s : %(message)s')
    file_handler.setFormatter(formatter)
    file_handler.setFormatter(formatter)
    queue_listener = QueueListener(log_queue, file_handler)
    queue_listener.start()
    root = logging.getLogger()
    root.addHandler(queue_handler)

class MainLoop:

    def __init__(self):
        self.key_manager = None
        self.key_synchronizator = None
        self.backend = None
        self.database = None

    async def start(self, config):
        init()

        backend.init()
        database.init()
        key_management.init()
        key_synchronization.init()

        logger.info("Initializing database")
        self.database = database.Database(config)

        logger.info("Starting the backend")
        self.backend = backend.QBackend(config)
        self.backend.start()

        logger.info("Starting the key synchronizator")
        self.key_synchronizator = key_synchronization.KeySynchronizationSubsystem(
            config, self.database, self.backend)

        neighbour_node_names = [name for (name, _, _) in config.neighbours]
        waiter_for_nodes = list(filter(lambda x: x < config.node_name, neighbour_node_names))
        self.key_synchronizator.start(waiter_for_nodes)

        logger.info("Starting the application interface")
        self.key_manager = key_management.KeyManagementSubsystem(config, self.database, self.key_synchronizator)
        await self.key_manager.start()

    async def stop(self):
        logger.info("Stopping key manager")
        await self.key_manager.stop()

        logger.info("Stopping key synchronizator")
        self.key_synchronizator.stop()

        logger.info("Stopping quantum backend")
        self.backend.stop()


async def non_daemon_start(config_file):
    config = configuration.Config(config_file)
    main_daemon = MainLoop()
    await main_daemon.start(config)
    await aioconsole.ainput(' ')
    #Stopping gracefully this software sucks. Just kill it


def cli():
    argc = len(sys.argv)
    cwd = os.getcwd()
    with daemon.DaemonContext():
        os.chdir(cwd)
        loop = asyncio.get_event_loop()
        loop.run_until_complete(non_daemon_start(CONFIG_FILE))
        exit(0)


if __name__ == "__main__":
    cli()
