# Quditto Charts

This directory contains Helm charts for deploying the Quditto project on Kubernetes. Each chart is responsible for deploying a component of the Quditto system, which consists of quantum nodes, key management entities, a nodes orchestrator, and an admission controller.

## Prerequisites

Before launching these charts, ensure you have the following installed on your system:
- Kubernetes
- Helm
- L2S-M https://github.com/Networks-it-uc3m/L2S-M

## Installation

To deploy Quditto using these charts, navigate to the root directory of this project and run the following command:

```bash
helm install quditto-chart ./chart
```

## Charts Overview
### Qnodes

The qnodes chart deploys a simulated quantum node. These are simulated using the Simulaqron project. 

    Chart.yaml: Metadata about the qnodes chart.
    templates/deployment.yaml: Qnode deployemnt.
    templates/service.yaml: Cluster IP Service for each qnode.

### KMES

The kmes chart deploys the quantum key management entities. These entities are responsible for the secure management of cryptographic keys and other sensitive data in a quantum environment.

    Chart.yaml: Metadata about the kmes chart.
    templates/deployment.yaml: kme deployment.
    templates/l2networks.yaml: Kubernetes configuration for layer 2 networks, that connect the kmes.

### Orchestrator

The orchestrator chart deploys the orchestrator for quantum nodes. It manages and coordinates the activities and operations of multiple quantum nodes.

    Chart.yaml: Metadata about the orchestrator chart.
    templates/config-cm.yaml: Kubernetes config map forthe qnode configurations
    templates/deployment.yaml: Kubernetes deployment configuration.
    templates/inventory-cm.yaml: Kubernetes config map for the orchestrator connection to the qnodes.

### Admission Control

The admission-control chart deploys the admission controller, which is responsible for the regulation and management of access to the quantum network.

    Chart.yaml: Metadata about the admission control chart.
    templates/deployment.yaml: admission controller deployment.

### General Files

    Chart.yaml: Defines this as a Helm chart and provides metadata.
    values.yaml: Contains default configuration values for this chart. By default it's meant to be deployed in the UC3M - EHU VLAN infrastructure, a cluster with 6 nodes. 

For more information on customizing your deployments with Helm values, please refer to the Helm documentation and the values.yaml file within each chart sub-directory.