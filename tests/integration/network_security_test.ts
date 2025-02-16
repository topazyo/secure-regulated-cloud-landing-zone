import { describe, before, it } from 'mocha';
import { expect } from 'chai';
import { NetworkSecurityValidator } from '../../src/security/network_validator';
import { TestEnvironment } from '../utils/test_environment';

describe('Network Security Integration Tests', () => {
  let validator: NetworkSecurityValidator;
  let testEnv: TestEnvironment;

  before(async () => {
    testEnv = await TestEnvironment.create({
      subscriptionId: process.env.TEST_SUBSCRIPTION_ID,
      resourceGroup: 'test-security-rg',
      location: 'switzerlandnorth'
    });

    validator = new NetworkSecurityValidator({
      subscriptionId: testEnv.subscriptionId,
      resourceGroup: testEnv.resourceGroup
    });
  });

  describe('SWIFT Network Isolation', () => {
    it('should deny unauthorized access to SWIFT network', async () => {
      const testResult = await validator.testNetworkAccess({
        source: 'external-network',
        destination: 'swift-network',
        port: 443,
        protocol: 'HTTPS'
      });

      expect(testResult.access).to.equal('Denied');
      expect(testResult.reason).to.equal('NetworkSecurityRule');
    });

    it('should allow authorized payment gateway access', async () => {
      const testResult = await validator.testNetworkAccess({
        source: 'payment-gateway',
        destination: 'swift-network',
        port: 443,
        protocol: 'HTTPS'
      });

      expect(testResult.access).to.equal('Allowed');
      expect(testResult.matchedRule).to.equal('swift-authorized-access');
    });
  });

  describe('Network Segmentation Compliance', () => {
    it('should validate network segmentation meets compliance requirements', async () => {
      const complianceResult = await validator.validateNetworkSegmentation();

      expect(complianceResult.status).to.equal('Compliant');
      expect(complianceResult.validations).to.deep.include({
        control: 'network-isolation',
        status: 'Passed'
      });
    });
  });

  after(async () => {
    await testEnv.cleanup();
  });
});