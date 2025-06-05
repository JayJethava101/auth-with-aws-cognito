import { CognitoIdentityProviderClient, ListUserPoolsCommand } from '@aws-sdk/client-cognito-identity-provider';

async function testConnection() {
  const client = new CognitoIdentityProviderClient({
    region: 'ap-south-1',
    // Use the same credentials
    credentials: {
        accessKeyId: "",
        secretAccessKey: "",
      },
  });
  
  try {
    // A simple operation that should work with basic permissions
    const command = new ListUserPoolsCommand({ MaxResults: 10 });
    const response = await client.send(command);
    console.log('Connection successful:', response);
  } catch (error) {
    console.error('Connection failed:', error);
  }
}

testConnection();