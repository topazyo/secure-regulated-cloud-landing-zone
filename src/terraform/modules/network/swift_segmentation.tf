module "swift_network" {
  source = "./modules/network"

  network_config = {
    name                = "swift-scr-network"
    resource_group_name = var.resource_group_name
    address_space       = ["10.1.0.0/16"]
    location           = var.location
    
    subnets = {
      hsm = {
        name           = "hsm-subnet"
        address_prefix = "10.1.1.0/24"
        security_rules = [
          {
            name                       = "Allow_HSM_Traffic"
            priority                   = 100
            direction                  = "Inbound"
            access                     = "Allow"
            protocol                   = "Tcp"
            source_port_range         = "*"
            destination_port_range    = "443"
            source_address_prefix     = "VirtualNetwork"
            destination_address_prefix = "GEN2-HSM-SUBNET"
          }
        ]
      }
      payment = {
        name           = "payment-subnet"
        address_prefix = "10.1.2.0/24"
        security_rules = [
          {
            name                       = "Restrict_Payment_Traffic"
            priority                   = 100
            direction                  = "Inbound"
            access                     = "Allow"
            protocol                   = "Tcp"
            source_port_range         = "*"
            destination_port_range    = "443"
            source_address_prefix     = "SWIFT-IP-RANGES"
            destination_address_prefix = "PAYMENT-SUBNET"
          }
        ]
      }
    }
  }
}