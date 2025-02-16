module "multi_tenant_landing_zone" {
  source = "../../modules/landing-zone"

  for_each = var.tenants

  tenant_config = {
    name        = each.key
    environment = each.value.environment
    location    = each.value.location
    
    network = {
      address_space = each.value.network_range
      subnets       = each.value.subnets
      
      isolation_config = {
        enable_forced_tunneling = true
        allowed_external_ips    = each.value.allowed_ips
      }
    }
    
    security = {
      enable_ddos_protection = true
      enable_threat_detection = true
      
      hsm_config = {
        sku_name = "Premium"
        key_rotation_days = 90
        geo_redundant = true
      }
    }
    
    compliance = {
      frameworks = each.value.compliance_frameworks
      monitoring_retention_days = 365
      alert_recipients = each.value.alert_contacts
    }
  }
}

# Shared Services Hub
module "shared_services" {
  source = "../../modules/shared-services"

  hub_config = {
    name        = "shared-services-hub"
    location    = var.hub_location
    address_space = var.hub_address_space
    
    services = {
      enable_firewall          = true
      enable_vpn_gateway       = true
      enable_express_route     = true
      enable_bastion_host      = true
    }
    
    security = {
      log_analytics_workspace_id = module.central_logging.workspace_id
      security_center_subscription = true
      enable_defender_for_cloud    = true
    }
  }
}

# Tenant Network Peering
resource "azurerm_virtual_network_peering" "tenant_to_hub" {
  for_each = var.tenants

  name                      = "tenant-${each.key}-to-hub"
  resource_group_name       = module.multi_tenant_landing_zone[each.key].resource_group_name
  virtual_network_name      = module.multi_tenant_landing_zone[each.key].vnet_name
  remote_virtual_network_id = module.shared_services.hub_vnet_id
  
  allow_virtual_network_access = true
  allow_forwarded_traffic     = true
  allow_gateway_transit       = false
  use_remote_gateways         = true
}