import { PolicyClient } from '@azure/arm-policy';
import { DefaultAzureCredential } from '@azure/identity';
import * as yaml from 'js-yaml';
import * as fs from 'fs';

export class PolicyDeployer {
  private client: PolicyClient;
  private readonly subscriptionId: string;

  constructor(subscriptionId: string) {
    this.client = new PolicyClient(
      new DefaultAzureCredential(),
      subscriptionId
    );
    this.subscriptionId = subscriptionId;
  }

  async deployPolicies(): Promise<void> {
    const policyDefinitions = this.loadPolicyDefinitions();
    
    for (const policy of policyDefinitions) {
      await this.createOrUpdatePolicy(policy);
      await this.assignPolicy(policy);
    }
  }

  private loadPolicyDefinitions(): PolicyDefinition[] {
    const policyFile = fs.readFileSync('./config/policies.yaml', 'utf8');
    return yaml.load(policyFile) as PolicyDefinition[];
  }

  private async createOrUpdatePolicy(policy: PolicyDefinition): Promise<void> {
    const policyDefinition = {
      displayName: policy.displayName,
      description: policy.description,
      policyType: 'Custom',
      mode: policy.mode,
      parameters: policy.parameters,
      policyRule: policy.rule
    };

    await this.client.policyDefinitions.createOrUpdate(
      policy.name,
      policyDefinition
    );
  }

  private async assignPolicy(policy: PolicyDefinition): Promise<void> {
    const assignment = {
      displayName: `${policy.displayName} Assignment`,
      policyDefinitionId: `/subscriptions/${this.subscriptionId}/providers/Microsoft.Authorization/policyDefinitions/${policy.name}`,
      parameters: policy.assignmentParameters,
      enforcementMode: policy.enforcement
    };

    await this.client.policyAssignments.create(
      policy.scope,
      `${policy.name}-assignment`,
      assignment
    );
  }
}

interface PolicyDefinition {
  name: string;
  displayName: string;
  description: string;
  mode: string;
  parameters: any;
  rule: any;
  scope: string;
  assignmentParameters: any;
  enforcement: 'Default' | 'DoNotEnforce';
}