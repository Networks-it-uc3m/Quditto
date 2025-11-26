MAIN_TF = """\
terraform {
  required_providers {
    openstack = {
      source  = "terraform-provider-openstack/openstack"
      version = "~> 1.54"
    }
  }
}

provider "openstack" {
  auth_url    = var.auth_url
  region      = var.region
  user_name   = var.user_name
  password    = var.password
  tenant_id   = var.tenant_id
  domain_name = var.domain_name
}

variable "cluster_name"   { type = string }
variable "count_cp"       { type = number }
variable "count_worker"   { type = number }
variable "image_name"     { type = string }
variable "flavor_name"    { type = string }
variable "keypair_name"   { type = string }
variable "network_uuid"   { type = string }

# Provider variables
variable "auth_url"       { type = string }
variable "region"         { type = string }
variable "user_name"      { type = string }
variable "password"       { type = string }
variable "tenant_id"      { type = string }
variable "domain_name"    { type = string }

# --- Security group that allows EVERYTHING (temporary!) ---
resource "openstack_networking_secgroup_v2" "k8s_allow_all" {
  name        = "${var.cluster_name}-allow-all"
  description = "Security group (temporary): allow all traffic"
}

resource "openstack_networking_secgroup_rule_v2" "allow_all_ingress_v4" {
  direction         = "ingress"
  ethertype         = "IPv4"
  remote_ip_prefix  = "0.0.0.0/0"
  security_group_id = openstack_networking_secgroup_v2.k8s_allow_all.id
}

resource "openstack_networking_secgroup_rule_v2" "allow_all_ingress_v6" {
  direction         = "ingress"
  ethertype         = "IPv6"
  remote_ip_prefix  = "::/0"
  security_group_id = openstack_networking_secgroup_v2.k8s_allow_all.id
}

# --- Control plane instance ---
resource "openstack_compute_instance_v2" "cp" {
  name        = "${var.cluster_name}-cp"
  image_name  = var.image_name
  flavor_name = var.flavor_name
  key_pair    = var.keypair_name

  network {
    uuid = var.network_uuid
  }

  security_groups = [openstack_networking_secgroup_v2.k8s_allow_all.name]
}

# --- Worker instances ---
resource "openstack_compute_instance_v2" "worker" {
  count       = var.count_worker
  name        = "${var.cluster_name}-worker-${count.index + 1}"
  image_name  = var.image_name
  flavor_name = var.flavor_name
  key_pair    = var.keypair_name

  network {
    uuid = var.network_uuid
  }

  security_groups = [openstack_networking_secgroup_v2.k8s_allow_all.name]
}

# --- Outputs ---
output "control_plane_ip" {
  value = openstack_compute_instance_v2.cp.access_ip_v4
}

output "worker_ips" {
  value = [for w in openstack_compute_instance_v2.worker : w.access_ip_v4]
}
"""
