module "swift_landing_zone" {
  source = "../../modules/landing-zone"

  environment = "production"
  region      = "switzerlandnorth"

  network_config = {
    address_space       = "10.1.0.0/16"
    swift_subnet       = "10.1.1.0/24"
    management_subnet  = "10.1.2.0/24"
    
    security_rules = {
      swift_isolation = {
        name                       = "swift-isolation"
        priority                   = 100
        direction                  = "Inbound"
        access                     = "Deny"
        protocol                   = "*"
        source_port_range         = "*"
        destination_port_range    = "*"
        source_address_prefix     = "*"
        destination_address_prefix = "10.1.1.0/24"
      }
    }
  }

  hsm_config = {
    sku_name = "Premium"
    key_sizes = {
      rsa_key_2048 = 2048
      rsa_key_4096 = 4096
    }
    network_acls = {
      bypass         = "AzureServices"
      default_action = "Deny"
      ip_rules       = ["trusted-ip-range"]
    }
  }

  monitoring_config = {
    retention_days = 365
    alert_config = {
      security_violations = {
        threshold = 0
        window_size = "PT5M"
      }
    }
  }
}