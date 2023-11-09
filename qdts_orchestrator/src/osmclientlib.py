import random
import string
import yaml
from jinja2 import Environment, FileSystemLoader, PackageLoader
from osmclient import client
from osmclient.common.exceptions import ClientException
import pkg_resources
import os


# Definition of auxiliary functions used in the cli qdts_orchestrator app:
# This function upload the NSD yaml to OSM
def upload_nsd_2_osm(rendered_yaml, osm_hostname="127.0.0.1"):
    myclient = client.Client(host=osm_hostname, sol005=True)
    file_path = 'output.yaml'
    # Write the rendered content to the YAML file
    with open(file_path, 'w') as yaml_file:
        yaml_file.write(rendered_yaml)
    myclient.nsd.create(file_path)
    

# Check if the nsd already exists on OSM to not upload it
def check_nsd_exists(rendered_yaml, osm_hostname="127.0.0.1"):
    exist = False
    rendered_yaml = yaml.safe_load(rendered_yaml)
    nsd_name = rendered_yaml['nsd']['nsd'][0]['id']
    myclient = client.Client(host=osm_hostname, sol005=True)
    filter = "name=" + nsd_name
    resp = myclient.nsd.list(filter)
    if len(resp) > 0:
        exist = True
    return exist

# Instantiate nsd
def instantiate_osm_nsd(nsd_name, instance_name, vim_account, osm_hostname="127.0.0.1", ssh_key=None):
    myclient = client.Client(host=osm_hostname, sol005=True)
    myclient.ns.create(nsd_name=nsd_name, nsr_name=instance_name,
                       account=vim_account, wait=True, ssh_keys=ssh_key)
    response = myclient.ns.list_op(instance_name)
    return response

# Delete an OSM instance
def remove_osm_nsd(instance_name, osm_hostname="127.0.0.1"):
    myclient = client.Client(host=osm_hostname, sol005=True)
    myclient.ns.delete(name=instance_name, wait=True)
    

# Get the IP address of a specific VNF
def get_vnf_ip(vnf_id, osm_hostname="127.0.0.1"):
    filter = "member-vnf-index-ref=" + vnf_id
    myclient = client.Client(host=osm_hostname, sol005=True)
    resp = myclient.vnf.list(filter=filter)

    if len(resp) == 1:
        return resp[0].get("ip-address")
    else:
        print(f'Not available IP for "{vnf_id}"')
        return None


# Generate a yaml content based on the QKD orchestrator config file
def create_nsd_yaml(package_name, vendor, vnfd_name,
                    vld_name, vnfd_nodes, vim_network_name=None, vim_net=False):
    #current_directory = os.getcwd()
    package_path = pkg_resources.resource_filename(__name__, "")
    template_path = os.path.join(package_path, "templates")
    env = Environment(loader=FileSystemLoader(template_path))
    #print("Current working directory:", current_directory)
    #template_dir = 'my_package/templates'
    #env= Environment(loader=FileSystemLoader("src/templates/"))
    template = env.get_template('nsd.template.yaml.j2')
    content = {
        "name": package_name,
        "vendor": vendor,
        "vnfd_name": vnfd_name,
        "vim_net": vim_net,
        "vld_name": vld_name,
        "vim_network_name": vim_network_name,
        "nodes": vnfd_nodes,
    }

    return template.render(content)


# function to generate random string of variable length
def generate_random_alphanumeric_string(length):
    characters = string.ascii_letters + string.digits
    return ''.join(random.choice(characters) for _ in range(length))