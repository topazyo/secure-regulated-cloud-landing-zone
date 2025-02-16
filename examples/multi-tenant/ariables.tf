variable "tenants" {
  type = map(object({
    environment = string
    location    = string
    network_range = string
    subnets     = map(object({
      name           = string
      address_prefix = string
      service_endpoints = list(string)
      delegation     = optional(object({
        name    = string
        service = string
      }))
    }))
    allowed_ips = list(string)
    compliance_frameworks = list(string)
    alert_contacts = list(string)
  }))

  default = {
    finance = {
      environment = "production"
      location    = "switzerlandnorth"
      network_range = "10.1.0.0/16"
      subnets = {
        swift = {
          name           = "swift-network"
          address_prefix = "10.1.1.0/24"
          service_endpoints = ["Microsoft.KeyVault"]
        }
        payment = {
          name           = "payment-processing"
          address_prefix = "10.1.2.0/24"
          service_endpoints = ["Microsoft.KeyVault", "Microsoft.Sql"]
        }
      }
      allowed_ips = ["trusted-payment-gateway-ip"]
      compliance_frameworks = ["PCI-DSS", "SWIFT-SCR"]
      alert_contacts = ["security@finance.company.com"]
    }
    healthcare = {
      environment = "production"
      location    = "westeurope"
      network_range = "10.2.0.0/16"
      subnets = {
        patient_data = {
          name           = "patient-records"
          address_prefix = "10.2.1.0/24"
          service_endpoints = ["Microsoft.KeyVault", "Microsoft.Storage"]
        }
        analytics = {
          name           = "health-analytics"
          address_prefix = "10.2.2.0/24"
          service_endpoints = ["Microsoft.KeyVault", "Microsoft.AzureCosmosDB"]
        }
      }
      allowed_ips = ["trusted-healthcare-ips"]
      compliance_frameworks = ["HIPAA", "GDPR"]
      alert_contacts = ["security@healthcare.company.com"]
    }
  }
}