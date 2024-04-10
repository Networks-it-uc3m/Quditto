import click
from src import orchestratorlib
import yaml
import logging


log_format = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
logging.basicConfig(level=logging.INFO, filename='/tmp/quditto_orchestrator.log', format=log_format, filemode='a')
logger = logging.getLogger(__name__)



# Auxiliary functions:
def update_key_for_id(yaml_data, target_node, key_to_modify, new_value):
    for item in yaml_data:
        print(f'Testing the new function: {item}')
        if item.get('hosts') == target_node:
            item[key_to_modify] = new_value

#  Definition of the CLI commands
@click.group()
def cli():
    """Command-line interface to execute the quditto-orchestrator"""
    pass


# Command to start the qkd-orchestator
# This install the necessary packages on the quditto nodes, and execute simulaqron
@cli.command()
@click.argument('config_file', required=True, type=click.File(mode='r'))
@click.argument('inv_file', required=True, type=click.File(mode='r'))
@click.option('--osm_hostname', type=str, required=False,
              default=None, help="osm host ip-address to handle the topology deployment")
@click.option('--vim_account', type=str, required=False,
              default=None, help="vim attched in OSM that where executing of the nodes")
@click.option('--ssh_key', type=click.Path(exists=True), required=False, help="ssh keys to access to the nodes via SSH")
def start(config_file, inv_file, osm_hostname, vim_account, ssh_key):
    """execute an emulated QKD network based on a configuration file (yaml)"""
    # Ejemplo de cómo escribir trazas desde la clase principal
    logger.info("Installation of the quditto_node requirements in every node")
    
    yaml_config_file = yaml.safe_load(config_file.read())
    yaml_inv_file =  yaml.safe_load(inv_file.read())
    
    # Get the nodes of the simulated network from the configuration file 
    nodes_array = yaml_config_file["nodes"]
    
    
    # If OSM is not specified, execute the quditto_node installation function
    if osm_hostname is not None:
        from src import osmclientlib
        click.echo(f"Starting the execution with OSM({osm_hostname})")
        click.echo(f"ssh_keys Input file: {ssh_key}")
                
        # Depending on the number of the nodes, the NSD will change
        # but will be based on the jinja2 template defined
        package_name = "qkd_nsd_" + osmclientlib.generate_random_alphanumeric_string(8)
        vld_name = package_name + "_vld"
        rendered_yaml = osmclientlib.create_nsd_yaml(package_name=package_name,
                                        vendor="networks_it_uc3m",
                                        vnfd_name="hackfest_basic-vnf",
                                        vld_name=vld_name,
                                        vnfd_nodes=nodes_array,
                                        vim_net=True,
                                        vim_network_name="control-provider")
        
        if not osmclientlib.check_nsd_exists(rendered_yaml, osm_hostname):
            osmclientlib.upload_nsd_2_osm(rendered_yaml, osm_hostname)
        
        # Instantiate the already created
        instantiation_name = "test_" + osmclientlib.generate_random_alphanumeric_string(4)
        logger.info(f'NSD with the QKD network, proceeding with its instantiation. Instance name: "{instantiation_name}"')
        response = osmclientlib.instantiate_osm_nsd(package_name, instantiation_name, vim_account, osm_hostname=osm_hostname, ssh_key=ssh_key)
        osm_startTime = response[0]['startTime']
        osm_statusEnteredTime = response[0]['statusEnteredTime']
        osm_instantiation_time = osm_statusEnteredTime - osm_startTime
        logger.info(f'Instance name "{instantiation_name}" completed. Instantiation time: {osm_instantiation_time}')
        
        
        # Obtain the IP addresses returned by OSM and update the inventory file
        dict_nodes_ip = {}
        for node in nodes_array:
            node_name = node["node_name"]
            node_ip = osmclientlib.get_vnf_ip(node_name, osm_hostname=osm_hostname)
            click.echo(f'Node "{node_name}" with IP (obtained from OSM) "{node_ip}"')
            dict_nodes_ip.update({node_name: node_ip})
        
        # Modify the inventory file with the IP addreses obtained from OSM 
        for host_name, new_ip in dict_nodes_ip.items():
            if 'all' in yaml_inv_file and 'hosts' in yaml_inv_file['all'] and host_name in yaml_inv_file['all']['hosts']:
                yaml_inv_file['all']['hosts'][host_name]['ansible_host'] = new_ip

        
        # Modify the config file with the IP addreses obtained from OSM 
        for node in yaml_config_file['nodes']:
            for host_name, new_ip in dict_nodes_ip.items():
                if node['node_name'] == host_name:
                    node['node_ip'] = new_ip
                           
    # Install the quditto_node requirements and place the topology for the qkd network to simulate (in every node)
    orchestratorlib.install(config_file=yaml_config_file, inv_file=yaml_inv_file)
    
    # Once configured, lets run the quditto_node
    orchestratorlib.run(inv_file=yaml_inv_file)


# Command to stop the simulated qkd-network, deleting 
# the ns-instace deployed with OSM
@cli.command()
@click.option('--osm_hostname', type=str, required=True,
              default=None, help="osm host ip-address to handle the ns removal")
@click.option('--ns_instance', type=str, required=True,
              default=None, help="ns instance to be removed")
def remove_instance(osm_hostname, ns_instance):
    """ Function to remove an OSM NS instance"""
    logger.info(f'Deleting OSM NS instance {ns_instance}')
    osmclientlib.remove_osm_nsd(instance_name=ns_instance, osm_hostname=osm_hostname)
    
# Command to stop the simulated qkd-network stopping SimulaQron
#(thought for pre-deployed machine pools)

@cli.command()
@click.argument('inv_file', required=True, type=click.File(mode='r'))

def stop(inv_file):
    """ Function to stop the DT of a QKD Network """
    logger.info(f'Stopping QKD network')
    yaml_inv_file = yaml.safe_load(inv_file.read())
    orchestratorlib.stop(inv_file = yaml_inv_file)

if __name__ == "__main__":
    cli()
