resource "azurerm_network_security_group" "microsegmented_nsg" {
  name                = "microsegmented-nsg-${var.environment}"
  location            = var.location
  resource_group_name = var.resource_group_name

  dynamic "security_rule" {
    for_each = var.microsegmentation_rules
    content {
      name                         = security_rule.value.name
      priority                     = security_rule.value.priority
      direction                    = security_rule.value.direction
      access                       = security_rule.value.access
      protocol                     = security_rule.value.protocol
      source_port_range           = security_rule.value.source_port_range
      destination_port_range      = security_rule.value.destination_port_range
      source_address_prefix       = security_rule.value.source_address_prefix
      destination_address_prefix  = security_rule.value.destination_address_prefix
      description                 = security_rule.value.description
    }
  }

  tags = merge(var.tags, {
    "SecurityLevel" = "Critical"
    "ComplianceFramework" = "SWIFT-SCR"
  })
}

resource "azurerm_subnet_network_security_group_association" "microsegment" {
  for_each = var.protected_subnets

  subnet_id                 = each.value
  network_security_group_id = azurerm_network_security_group.microsegmented_nsg.id
}