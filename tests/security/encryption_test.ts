import { describe, before, it } from 'mocha';
import { expect } from 'chai';
import { EncryptionValidator } from '../../src/security/encryption_validator';
import { KeyVaultClient } from '@azure/keyvault-keys';
import { DefaultAzureCredential } from '@azure/identity';

describe('Encryption Security Tests', () => {
  let validator: EncryptionValidator;
  let keyVaultClient: KeyVaultClient;

  before(async () => {
    const credential = new DefaultAzureCredential();
    keyVaultClient = new KeyVaultClient(
      process.env.KEY_VAULT_URL!,
      credential
    );

    validator = new EncryptionValidator({
      subscriptionId: process.env.SUBSCRIPTION_ID!,
      keyVaultUrl: process.env.KEY_VAULT_URL!
    });
  });

  describe('HSM-Backed Key Management', () => {
    it('should enforce FIPS 140-2 Level 3 compliance', async () => {
      const keyConfig = {
        name: 'test-key',
        keyType: 'RSA-HSM',
        keySize: 4096
      };

      const key = await validator.createAndValidateKey(keyConfig);
      expect(key.keyType).to.equal('RSA-HSM');
      expect(key.keySize).to.equal(4096);
    });

    it('should enforce key rotation policy', async () => {
      const rotationPolicy = await validator.getKeyRotationPolicy('test-key');
      
      expect(rotationPolicy.lifetimeActions).to.deep.include({
        trigger: { timeBeforeExpiry: 'P30D' },
        action: { type: 'Rotate' }
      });
    });

    it('should prevent non-compliant key creation', async () => {
      const nonCompliantConfig = {
        name: 'weak-key',
        keyType: 'RSA',
        keySize: 1024
      };

      await expect(validator.createAndValidateKey(nonCompliantConfig))
        .to.be.rejectedWith('Key configuration does not meet security requirements');
    });
  });

  describe('Data Encryption Validation', () => {
    it('should validate storage account encryption', async () => {
      const storageValidation = await validator.validateStorageEncryption(
        process.env.STORAGE_ACCOUNT!
      );

      expect(storageValidation.encryption).to.deep.equal({
        keyType: 'Account-managed',
        algorithm: 'AES256',
        enabled: true
      });
    });

    it('should validate in-transit encryption', async () => {
      const transitValidation = await validator.validateTransitEncryption();
      
      expect(transitValidation.tlsVersion).to.equal('1.2');
      expect(transitValidation.cipherSuites).to.include(
        'TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384'
      );
    });
  });

  describe('Key Access Control', () => {
    it('should enforce just-in-time access', async () => {
      const accessRequest = await validator.requestKeyAccess({
        keyName: 'test-key',
        duration: 'PT1H',
        justification: 'Emergency maintenance'
      });

      expect(accessRequest.status).to.equal('Approved');
      expect(accessRequest.expiration).to.be.lessThan(
        Date.now() + 3600000 // 1 hour
      );
    });
  });

  after(async () => {
    // Cleanup test resources
    await validator.cleanup();
  });
});