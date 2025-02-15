import { BlobServiceClient } from '@azure/storage-blob';
import { DefaultAzureCredential } from '@azure/identity';
import { ComplianceValidationResult } from './types';

export class ComplianceReporter {
  private blobClient: BlobServiceClient;
  private readonly config: ReporterConfig;

  constructor(config: ReporterConfig) {
    const credential = new DefaultAzureCredential();
    this.blobClient = BlobServiceClient.fromConnectionString(
      config.storageConnectionString
    );
    this.config = config;
  }

  async generateReport(validationResult: ComplianceValidationResult): Promise<void> {
    try {
      // Generate detailed report
      const report = await this.createDetailedReport(validationResult);

      // Store report
      await this.storeReport(report);

      // Generate notifications
      await this.notifyStakeholders(report);

      // Archive historical data
      await this.archiveReport(report);
    } catch (error) {
      await this.handleReportingFailure(error);
      throw error;
    }
  }

  private async createDetailedReport(result: ComplianceValidationResult): Promise<ComplianceReport> {
    const report: ComplianceReport = {
      metadata: {
        generatedAt: new Date().toISOString(),
        environment: this.config.environment,
        version: '1.0'
      },
      summary: {
        overallStatus: result.overallStatus,
        criticalFindings: this.countCriticalFindings(result),
        complianceScore: this.calculateComplianceScore(result)
      },
      details: {
        regulatoryCompliance: this.formatRegulatoryCompliance(result.details.regulatoryCompliance),
        securityControls: this.formatSecurityControls(result.details.securityControls),
        recommendations: this.prioritizeRecommendations(result.recommendations)
      },
      trends: await this.analyzeTrends(result)
    };

    return report;
  }

  private async storeReport(report: ComplianceReport): Promise<void> {
    const containerClient = this.blobClient.getContainerClient('compliance-reports');
    const blobName = `report-${report.metadata.generatedAt}.json`;
    const blobClient = containerClient.getBlockBlobClient(blobName);

    await blobClient.upload(
      JSON.stringify(report, null, 2),
      Buffer.byteLength(JSON.stringify(report))
    );
  }

  private async notifyStakeholders(report: ComplianceReport): Promise<void> {
    const notifications = this.generateNotifications(report);

    for (const notification of notifications) {
      await this.sendNotification(notification);
    }
  }

  private async analyzeTrends(result: ComplianceValidationResult): Promise<ComplianceTrends> {
    const historicalData = await this.getHistoricalData();
    
    return {
      complianceScoreTrend: this.calculateTrend(
        historicalData.map(d => d.summary.complianceScore)
      ),
      violationsTrend: this.calculateViolationsTrend(historicalData),
      remediationEfficiency: this.calculateRemediationEfficiency(historicalData)
    };
  }
}

interface ReporterConfig {
  storageConnectionString: string;
  environment: string;
  notificationConfig: {
    recipients: string[];
    criticalOnly: boolean;
  };
  retentionPolicy: {
    days: number;
    archiveLocation: string;
  };
}

interface ComplianceReport {
  metadata: {
    generatedAt: string;
    environment: string;
    version: string;
  };
  summary: {
    overallStatus: string;
    criticalFindings: number;
    complianceScore: number;
  };
  details: {
    regulatoryCompliance: any;
    securityControls: any;
    recommendations: any;
  };
  trends: ComplianceTrends;
}

interface ComplianceTrends {
  complianceScoreTrend: number[];
  violationsTrend: {
    critical: number[];
    high: number[];
    medium: number[];
    low: number[];
  };
  remediationEfficiency: {
    averageTimeToRemediate: number;
    successRate: number;
  };
}