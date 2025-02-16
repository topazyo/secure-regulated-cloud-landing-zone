package test

import (
    "testing"
    "fmt"
    "github.com/gruntwork-io/terratest/modules/terraform"
    "github.com/gruntwork-io/terratest/modules/azure"
    "github.com/stretchr/testify/assert"
)

func TestSecureNetworkDeployment(t *testing.T) {
    t.Parallel()

    subscriptionID := azure.GetSubscriptionID(t)
    uniqueID := random.UniqueId()
    resourceGroupName := fmt.Sprintf("terraform-test-%s", uniqueID)

    terraformOptions := &terraform.Options{
        TerraformDir: "../../examples/secure-network",
        Vars: map[string]interface{}{
            "resource_group_name": resourceGroupName,
            "environment":        "test",
            "location":          "switzerlandnorth",
            "address_space":     []string{"10.0.0.0/16"},
        },
        EnvVars: map[string]string{
            "ARM_SUBSCRIPTION_ID": subscriptionID,
        },
    }

    defer terraform.Destroy(t, terraformOptions)
    terraform.InitAndApply(t, terraformOptions)

    // Test Network Segmentation
    vnetName := terraform.Output(t, terraformOptions, "vnet_name")
    subnets := azure.GetVirtualNetworkSubnets(t, vnetName, resourceGroupName, subscriptionID)

    // Verify subnet isolation
    swiftSubnet := subnets["swift-subnet"]
    assert.NotNil(t, swiftSubnet.NetworkSecurityGroup)
    
    nsgRules := azure.GetNSGRules(t, *swiftSubnet.NetworkSecurityGroup.ID, subscriptionID)
    assert.Equal(t, "Deny", nsgRules[0].Access)
    assert.Equal(t, "Inbound", nsgRules[0].Direction)

    // Test HSM Configuration
    keyVaultName := terraform.Output(t, terraformOptions, "key_vault_name")
    keyVault := azure.GetKeyVault(t, keyVaultName, resourceGroupName, subscriptionID)
    
    assert.Equal(t, "Premium", *keyVault.Properties.Sku.Name)
    assert.True(t, *keyVault.Properties.EnablePurgeProtection)
}