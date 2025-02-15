import { NetworkWatcherClient } from '@azure/arm-network';
import { DefaultAzureCredential } from '@azure/identity';

export class NetworkFlowAnalyzer {
  private networkClient: NetworkWatcherClient;
  private readonly config: NetworkAnalyzerConfig;

  constructor(subscriptionId: string, config: NetworkAnalyzerConfig) {
    this.networkClient = new NetworkWatcherClient(
      new DefaultAzureCredential(),
      subscriptionId
    );
    this.config = config;
  }

  async analyzeNetworkFlows(): Promise<FlowAnalysisResult> {
    const flowLogs = await this.collectFlowLogs();
    const analysis = await this.performAnalysis(flowLogs);
    
    if (analysis.violationsDetected) {
      await this.enforceSegmentation(analysis.violations);
    }

    return analysis;
  }

  private async performAnalysis(flowLogs: any[]): Promise<FlowAnalysisResult> {
    const analysis: FlowAnalysisResult = {
      violationsDetected: false,
      violations: [],
      recommendations: []
    };

    for (const flow of flowLogs) {
      if (this.isViolatingFlow(flow)) {
        analysis.violationsDetected = true;
        analysis.violations.push({
          sourceIP: flow.sourceAddress,
          destinationIP: flow.destinationAddress,
          protocol: flow.protocol,
          violationType: this.determineViolationType(flow)
        });
      }
    }

    return analysis;
  }

  private async enforceSegmentation(violations: NetworkViolation[]): Promise<void> {
    for (const violation of violations) {
      await this.createBlockingRule(violation);
    }
  }

  private async createBlockingRule(violation: NetworkViolation): Promise<void> {
    const rule = {
      name: `block-violation-${Date.now()}`,
      protocol: violation.protocol,
      sourceAddressPrefix: violation.sourceIP,
      destinationAddressPrefix: violation.destinationIP,
      access: 'Deny',
      priority: 100,
      direction: 'Inbound'
    };

    await this.networkClient.securityRules.createOrUpdate(
      this.config.resourceGroup,
      this.config.nsgName,
      rule.name,
      rule
    );
  }
}

interface NetworkAnalyzerConfig {
  resourceGroup: string;
  nsgName: string;
  allowedFlows: {
    source: string;
    destination: string;
    protocol: string;
  }[];
}

interface FlowAnalysisResult {
  violationsDetected: boolean;
  violations: NetworkViolation[];
  recommendations: string[];
}

interface NetworkViolation {
  sourceIP: string;
  destinationIP: string;
  protocol: string;
  violationType: string;
}