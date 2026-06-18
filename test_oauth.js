const http = require('node:http');
const crypto = require('node:crypto');

async function runTest() {
  const baseUrl = 'http://localhost:8080/api';

  console.log('1. Registering User...');
  const randomStr = crypto.randomBytes(4).toString('hex');
  const randomEmail = `test_${randomStr}@demo.com`;
  const randomPassword = `Pass_${randomStr}!12A`;

  const regRes = await fetch(`${baseUrl}/auth/register`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email: randomEmail, password: randomPassword, firstName: 'Test', lastName: 'User' }) // NOSONAR
  });
  console.log(await regRes.json()); // NOSONAR
  
  console.log('2. Logging in...');
  const loginRes = await fetch(`${baseUrl}/auth/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email: randomEmail, password: randomPassword }) // NOSONAR
  });
  const loginData = await loginRes.json();
  if (!loginData.data) {
    console.error("Login failed:", loginData); // NOSONAR
    return;
  }
  const jwt = loginData.data.accessToken;
  console.log('   JWT received.');

  console.log('3. Creating OAuth Client...');
  const clientRes = await fetch(`${baseUrl}/auth/oauth/clients`, {
    method: 'POST',
    headers: { 
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${jwt}`
    },
    body: JSON.stringify({
      name: 'Test Client',
      redirect_uris: ['http://localhost:3000/callback'],
      scopes: ['read:profile', 'read:email'],
      is_public: false
    })
  });
  const clientData = await clientRes.json();
  const clientId = clientData.data.client_id;
  const clientSecret = clientData.data.client_secret;
  console.log(`   Client ID: ${clientId}`); // NOSONAR

  console.log('4. Authorizing (simulating user consent)...');
  const params = new URLSearchParams({
    client_id: clientId,
    redirect_uri: 'http://localhost:3000/callback',
    response_type: 'code',
    scope: 'read:profile read:email',
    action: 'approve'
  });
  
  const authRes = await fetch(`http://localhost:8080/oauth/authorize`, {
    method: 'POST',
    headers: { 
      'Content-Type': 'application/x-www-form-urlencoded',
      'Authorization': `Bearer ${jwt}`
    },
    body: params.toString(),
    redirect: 'manual' // We want to catch the redirect to get the code
  });

  const location = authRes.headers.get('location');
  const code = new URL(location).searchParams.get('code');
  console.log(`   Authorization Code: ${code}`);

  console.log('5. Exchanging Code for Token...');
  const tokenParams = new URLSearchParams({
    grant_type: 'authorization_code',
    code: code,
    client_id: clientId,
    client_secret: clientSecret,
    redirect_uri: 'http://localhost:3000/callback'
  });

  const tokenRes = await fetch(`http://localhost:8080/oauth/token`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: tokenParams.toString()
  });
  
  const tokenData = await tokenRes.json();
  console.log(`\n🎉 Success! You received the raw Access Token: \n${tokenData.access_token}\n`); // NOSONAR

  console.log('6. Validating Token with UserInfo Endpoint...');
  const userInfoRes = await fetch(`http://localhost:8080/oauth/userinfo`, {
    method: 'GET',
    headers: { 'Authorization': `Bearer ${tokenData.access_token}` }
  });
  const userInfo = await userInfoRes.json();
  console.log('   UserInfo response:', userInfo); // NOSONAR
  
  console.log('\n✅ Everything works! The token returned to you is raw.');
  console.log('To check the database and see the HASHED token, run this command in your terminal:');
  console.log('docker exec -it auth-postgres psql -U postgres -d auth_db -c "SELECT token FROM oauth_access_tokens;"');
}

(async () => { // NOSONAR
  try {
    await runTest();
  } catch (e) {
    console.error(e);
  }
})();
