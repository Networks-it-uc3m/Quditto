CONFIG_DIR=./config
NETWORKS_DIR=$(CONFIG_DIR)/networks
DEPLOYMENTS_DIR=$(CONFIG_DIR)/deployments
CM_DIR=$(CONFIG_DIR)/cm

.PHONY: build-deployment

build-deployment: $(NETWORKS_DIR) $(DEPLOYMENTS_DIR) $(CM_DIR)
	touch $(CONFIG_DIR)/all.yaml
	helm template ./chart > $(CONFIG_DIR)/all.yaml
	$(eval YAML_FILES := $(shell csplit -s -f $(CONFIG_DIR)/tmp_ $(CONFIG_DIR)/all.yaml '/^---$$/' {*}))
	@for file in $(YAML_FILES); do \
		kind=$$(yq e '.kind' $$file); \
		if [ $$kind = "Deployment" ]; then \
			mv $$file $(DEPLOYMENTS_DIR)/deployment_$$(yq e '.metadata.name' $$file).yaml; \
		elif [ $$kind = "ConfigMap" ]; then \
			mv $$file $(CM_DIR)/cm_$$(yq e '.metadata.name' $$file).yaml; \
		elif [ $$kind = "Service" ]; then \
			mv $$file $(NETWORKS_DIR)/service_$$(yq e '.metadata.name' $$file).yaml; \
		elif [ $$kind = "L2Network" ]; then \
			mv $$file $(NETWORKS_DIR)/network_$$(yq e '.metadata.name' $$file).yaml; \
		else \
			mv $$file $(CONFIG_DIR)/misc_$$(yq e '.metadata.name' $$file).yaml; \
		fi \
	done
	rm $(CONFIG_DIR)/all.yaml

$(NETWORKS_DIR):
	mkdir -p $(NETWORKS_DIR)

$(DEPLOYMENTS_DIR):
	mkdir -p $(DEPLOYMENTS_DIR)

$(CM_DIR):
	mkdir -p $(CM_DIR)
https://gitlab.eclipse.org/eclipse-research-labs/codeco-project/acm/-/blob/rht-integration/scripts/post_deploy.sh?ref_type=heads