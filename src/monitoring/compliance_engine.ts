import { AzureMonitorClient, MetricAlert } from '@azure/arm-monitor';
import { DefaultAzureCredential } from '@azure/identity';

export class ComplianceMonitor {
  private client: AzureMonitorClient;
  private readonly subscriptionId: string;

  constructor(subscriptionId: string) {
    this.subscriptionId = subscriptionId;
    this.client = new AzureMonitorClient(
      new DefaultAzureCredential(), 
      subscriptionId
    );
  }

  async setupComplianceAlerts(resourceGroup: string): Promise<void> {
    const alerts: MetricAlert[] = [
      {
        name: 'HSMLatencyAlert',
        description: 'Monitor HSM latency for compliance',
        severity: 1,
        enabled: true,
        scopes: [`/subscriptions/${this.subscriptionId}/resourceGroups/${resourceGroup}`],
        evaluationFrequency: 'PT1M',
        windowSize: 'PT5M',
        criteria: {
          'odata.type': 'Microsoft.Azure.Monitor.SingleResourceMultipleMetricCriteria',
          allOf: [
            {
              name: 'HSMLatency',
              metricNamespace: 'Microsoft.KeyVault/managedHSMs',
              metricName: 'ServiceLatency',
              operator: 'GreaterThan',
              threshold: 100,
              timeAggregation: 'Average'
            }
          ]
        }
      }
    ];

    for (const alert of alerts) {
      await this.client.metricAlerts.createOrUpdate(
        resourceGroup,
        alert.name,
        alert
      );
    }
  }
}