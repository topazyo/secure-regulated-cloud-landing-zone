package test

import (
    "testing"
    "encoding/json"
    "github.com/gruntwork-io/terratest/modules/terraform"
    "github.com/gruntwork-io/terratest/modules/azure"
    "github.com/stretchr/testify/assert"
)

func TestComplianceConfiguration(t *testing.T) {
    t.Parallel()

    terraformOptions := &terraform.Options{
        TerraformDir: "../../examples/compliance",
        Vars: map[string]interface{}{
            "environment": "test",
            "location":    "switzerlandnorth",
        },
    }

    defer terraform.Destroy(t, terraformOptions)
    terraform.InitAndApply(t, terraformOptions)

    // Test Policy Assignments
    policyAssignments := azure.GetPolicyAssignments(t, resourceGroupName, subscriptionID)
    
    // Verify PCI-DSS policies
    pciPolicies := filterPoliciesByFramework(policyAssignments, "PCI-DSS")
    assert.GreaterOrEqual(t, len(pciPolicies), 3)
    
    // Verify encryption requirements
    encryptionPolicy := findPolicyByName(pciPolicies, "encryption-requirements")
    assert.Equal(t, "Audit", encryptionPolicy.EnforcementMode)
    
    // Test Log Analytics Configuration
    workspaceName := terraform.Output(t, terraformOptions, "log_analytics_workspace_name")
    workspace := azure.GetLogAnalyticsWorkspace(t, workspaceName, resourceGroupName, subscriptionID)
    
    assert.Equal(t, 365, *workspace.RetentionInDays)
}