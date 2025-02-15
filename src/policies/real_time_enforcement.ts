import { PolicyClient } from '@azure/arm-policy';
import { DefaultAzureCredential } from '@azure/identity';

export class RealTimePolicyEnforcement {
  private client: PolicyClient;

  constructor(subscriptionId: string) {
    this.client = new PolicyClient(
      new DefaultAzureCredential(),
      subscriptionId
    );
  }

  async enforceNetworkSegmentation(): Promise<void> {
    const policyDefinition = {
      properties: {
        displayName: 'Enforce network segmentation',
        policyType: 'Custom',
        mode: 'All',
        description: 'Enforces network segmentation for regulated workloads',
        parameters: {},
        policyRule: {
          if: {
            allOf: [
              {
                field: 'type',
                equals: 'Microsoft.Network/virtualNetworks'
              },
              {
                field: 'Microsoft.Network/virtualNetworks/subnets[*].networkSecurityGroup.id',
                exists: 'false'
              }
            ]
          },
          then: {
            effect: 'deny'
          }
        }
      }
    };

    await this.client.policyDefinitions.createOrUpdate(
      'networkSegmentationPolicy',
      policyDefinition
    );
  }
}