import json


class Config:
    """Manages the configuration at a program level

    Class that is used to load and managed the configuration 
    needed by all the components of this software.
    """

    def __init__(self, config_file):
        """Loads the configuration from a file

        Args:
            config_file (str): path to the configuration file
            
        """
        raw_config = None
        with open(config_file) as file:
            raw_config = json.load(file)
        self.node_name = raw_config["node_name"]
        self.node_ip = raw_config["node_ip"]
        self.node_id = raw_config["node_id"]
        self.neighbours = []
        for neighbour in raw_config["neighbour_nodes"]:
            self.neighbours.append((neighbour["node_name"], neighbour["node_ip"], neighbour["node_id"]))

    def get_node_ip(self, remote_node):
        for (name, ip, _) in self.neighbours:
            if name == remote_node:
                return ip

    def get_node_id(self, remote_node):
        for (name, _, node_id) in self.neighbours:
            if name == remote_node:
                return node_id
