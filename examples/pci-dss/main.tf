module "pci_network" {
  source = "../../modules/secure-network"

  network_config = {
    name                = "pci-network"
    resource_group_name = var.resource_group_name
    address_space       = ["10.2.0.0/16"]
    
    subnets = {
      card_data = {
        name           = "card-data-subnet"
        address_prefix = "10.2.1.0/24"
        security_rules = [
          {
            name                       = "deny-internet"
            priority                   = 100
            direction                  = "Outbound"
            access                     = "Deny"
            protocol                   = "*"
            source_port_range         = "*"
            destination_port_range    = "*"
            source_address_prefix     = "VirtualNetwork"
            destination_address_prefix = "Internet"
          }
        ]
      }
      
      processing = {
        name           = "payment-processing"
        address_prefix = "10.2.2.0/24"
        service_endpoints = ["Microsoft.KeyVault"]
      }
    }
  }

  security_config = {
    enable_ddos_protection = true
    enable_firewall        = true
    
    firewall_rules = {
      payment_gateway = {
        name        = "payment-gateway"
        priority    = 100
        action      = "Allow"
        rules = [
          {
            name                  = "payment-api"
            source_addresses     = ["payment-gateway-subnet"]
            destination_ports    = ["443"]
            destination_addresses = ["payment-api"]
            protocols           = ["TCP"]
          }
        ]
      }
    }
  }

  monitoring_config = {
    enable_flow_logs         = true
    retention_days          = 365
    traffic_analytics_interval = "10"
  }

  tags = {
    Environment = "Production"
    Compliance  = "PCI-DSS"
    SecurityZone = "Critical"
  }
}