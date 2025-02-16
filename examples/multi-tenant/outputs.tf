output "tenant_networks" {
  description = "Network information for each tenant"
  value = {
    for tenant, config in module.multi_tenant_landing_zone : tenant => {
      vnet_id     = config.vnet_id
      subnet_ids  = config.subnet_ids
      nsg_ids     = config.nsg_ids
    }
  }
}

output "tenant_security" {
  description = "Security configurations for each tenant"
  value = {
    for tenant, config in module.multi_tenant_landing_zone : tenant => {
      key_vault_id = config.key_vault_id
      log_analytics_workspace_id = config.log_analytics_workspace_id
      policy_assignments = config.policy_assignments
    }
  }
  sensitive = true
}

output "shared_services" {
  description = "Shared services hub information"
  value = {
    vnet_id = module.shared_services.hub_vnet_id
    firewall_ip = module.shared_services.firewall_private_ip
    bastion_host = module.shared_services.bastion_host_id
  }
}