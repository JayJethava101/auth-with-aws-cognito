import { Injectable } from '@nestjs/common';
import { KMSClient, EncryptCommand, DecryptCommand } from '@aws-sdk/client-kms';

@Injectable()
export class KmsService {
  private readonly kmsClient: KMSClient;
  private readonly keyId: string;

  constructor() {
    if (!process.env.AWS_ACCESS_KEY_ID || !process.env.AWS_SECRET_ACCESS_KEY || !process.env.AWS_KMS_KEY_ID) {
      throw new Error('AWS credentials and KMS key ID must be provided');
    }

    this.kmsClient = new KMSClient({
      region: process.env.AWS_REGION || 'us-east-1',
      credentials: {
        accessKeyId: process.env.AWS_ACCESS_KEY_ID,
        secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY,
      },
    });
    this.keyId = process.env.AWS_KMS_KEY_ID;
  }

  async encrypt(text: string): Promise<string> {
    const command = new EncryptCommand({
      KeyId: this.keyId,
      Plaintext: Buffer.from(text),
    });

    const response = await this.kmsClient.send(command);
    if (!response.CiphertextBlob) {
      throw new Error('Encryption failed: No ciphertext returned');
    }
    return Buffer.from(response.CiphertextBlob).toString('base64');
  }

  async decrypt(encryptedText: string): Promise<string> {
    const command = new DecryptCommand({
      CiphertextBlob: Buffer.from(encryptedText, 'base64'),
    });

    const response = await this.kmsClient.send(command);
    if (!response.Plaintext) {
      throw new Error('Decryption failed: No plaintext returned');
    }
    return Buffer.from(response.Plaintext).toString();
  }
} 