const crypto = require('crypto');
const fs = require('fs');
const axios = require('axios');

function createSecret() {
  // Read the private key from file
  const privateKey = fs.readFileSync('key.pem', 'utf8');
  
  // Generate timestamp in milliseconds
  const timestamp = Math.floor(Date.now()).toString();
  console.log('HERE' + timestamp);
  
  // Create a buffer for the timestamp
  const buffer = Buffer.from(timestamp);
  
  // Encrypt the timestamp using the private key
  const encrypted = crypto.privateEncrypt(
    {
      key: privateKey,
      padding: crypto.constants.RSA_PKCS1_PADDING
    },
    buffer
  );
  
  // Encode the encrypted data in base64
  const base64CryptTime = encrypted.toString('base64');
  return base64CryptTime;
}

async function getOAuthToken() {
  const secret = createSecret();
  
  const params = {
    grant_type: 'client_credentials',
    client_id: 'API_KEY',
    client_secret: secret
  };
  
  try {
    const response = await axios.post(
      'https://ident.familysearch.org/cis-web/oauth2/v3/token',
      null,
      {
        params: params,
        timeout: 10000,
        httpsAgent: new (require('https').Agent)({ rejectUnauthorized: false }) // Equivalent to verify: false
      }
    );
    
    console.log(response.data);
    return response.data;
  } catch (error) {
    console.error('Error fetching OAuth token:', error.message);
    throw error;
  }
}

// Execute the function
getOAuthToken();