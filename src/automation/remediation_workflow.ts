import { AutomationClient } from '@azure/arm-automation';
import { DefaultAzureCredential } from '@azure/identity';

export class RemediationWorkflow {
  private client: AutomationClient;

  constructor(subscriptionId: string) {
    this.client = new AutomationClient(
      new DefaultAzureCredential(),
      subscriptionId
    );
  }

  async createRemediationRunbook(): Promise<void> {
    // @ts-ignore
    const runbookContent = `
      param(
        [Parameter(Mandatory=$true)]
        [string]$ResourceGroupName,

        [Parameter(Mandatory=$true)]
        [string]$ViolationType
      )

      switch ($ViolationType) {
        "NetworkSegmentation" {
          # Apply NSG rules
          $nsg = Get-AzNetworkSecurityGroup -ResourceGroupName $ResourceGroupName
          Add-AzNetworkSecurityRuleConfig \`
            -NetworkSecurityGroup $nsg \`
            -Name "DenyAllInbound" \`
            -Access Deny \`
            -Protocol * \`
            -Direction Inbound \`
            -Priority 4096 \`
            -SourceAddressPrefix * \`
            -SourcePortRange * \`
            -DestinationAddressPrefix * \`
            -DestinationPortRange *

          Set-AzNetworkSecurityGroup -NetworkSecurityGroup $nsg
        }
        "Encryption" {
          # Enable encryption
          $storageAccounts = Get-AzStorageAccount -ResourceGroupName $ResourceGroupName
          foreach ($sa in $storageAccounts) {
            Set-AzStorageAccount \`
              -ResourceGroupName $ResourceGroupName \`
              -Name $sa.StorageAccountName \`
              -EnableHttpsTrafficOnly $true \`
              -MinimumTlsVersion TLS1_2
          }
        }
      }
    `;

    await this.client.runbook.createOrUpdate(
      'RemediationRunbook',
      {
        name: 'AutoRemediation',
        location: 'westeurope',
        runbookType: 'PowerShell',
        publishContentLink: {
          uri: runbookContent
        }
      }
    );
  }
}