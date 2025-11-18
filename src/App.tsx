import React, { useState, useEffect } from 'react';
import { LogIn, LogOut, User, Key, Check, X } from 'lucide-react';

export default function ClerkPKCETest() {
  const [config, setConfig] = useState({
    issuerUrl: 'https://dynamic-antelope-48.clerk.accounts.dev',
    clientId: 'N7eToShSxeT8O3vL',
    redirectUri: window.location.origin,
  });


  const [isConfigured, setIsConfigured] = useState(false);
  const [user, setUser] = useState(null);
  const [tokens, setTokens] = useState(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  // Check if we're returning from OAuth callback
  useEffect(() => {
    const params = new URLSearchParams(window.location.search);
    const code = params.get('code');
    const state = params.get('state');

    if (code && state) {
      handleCallback(code, state);
    }
  }, []);

  // Generate random string for PKCE
  const generateRandomString = (length: number) => {
    const array = new Uint8Array(length);
    crypto.getRandomValues(array);
    return Array.from(array, byte => byte.toString(16).padStart(2, '0')).join('');
  };

  // Generate code verifier and challenge
  const generatePKCE = async () => {
    const verifier = generateRandomString(32);
    const encoder = new TextEncoder();
    const data = encoder.encode(verifier);
    const hash = await crypto.subtle.digest('SHA-256', data);
    const challenge = btoa(String.fromCharCode(...new Uint8Array(hash)))
      .replace(/\+/g, '-')
      .replace(/\//g, '_')
      .replace(/=/g, '');

    return { verifier, challenge };
  };

  const handleLogin = async () => {
    if (!config.issuerUrl || !config.clientId) {
      setError('Please configure Issuer URL and Client ID first');
      return;
    }

    try {
      setLoading(true);
      setError(null);

      // Generate PKCE values
      const { verifier, challenge } = await generatePKCE();
      const state = generateRandomString(16);

      // Store values in sessionStorage
      sessionStorage.setItem('pkce_verifier', verifier);
      sessionStorage.setItem('oauth_state', state);
      sessionStorage.setItem('clerk_config', JSON.stringify(config));

      // Build authorization URL
      const authUrl = new URL(`${config.issuerUrl}/oauth/authorize`);
      authUrl.searchParams.append('client_id', config.clientId);

      authUrl.searchParams.append('redirect_uri', config.redirectUri);
      authUrl.searchParams.append('response_type', 'code');
      authUrl.searchParams.append('scope', 'openid profile email public_metadata private_metadata');
      authUrl.searchParams.append('state', state);
      authUrl.searchParams.append('code_challenge', challenge);
      authUrl.searchParams.append('code_challenge_method', 'S256');

      // Redirect to Clerk
      window.location.href = authUrl.toString();
    } catch (err) {
      setError(`Login failed: ${err.message}`);
      setLoading(false);
    }
  };

  const handleCallback = async (code: string, state: string) => {
    try {
      setLoading(true);

      // Retrieve stored values
      const storedState = sessionStorage.getItem('oauth_state');
      const verifier: string = sessionStorage.getItem('pkce_verifier') as string;
      const storedConfig = JSON.parse(sessionStorage.getItem('clerk_config') as string);

      // Validate state
      if (state !== storedState) {
        throw new Error('State mismatch - possible CSRF attack');
      }

      if (!storedConfig) {
        throw new Error('Configuration not found');
      }

      if (!verifier) {
        throw new Error('PKCE verifier not found in session storage. This might be a browser privacy setting issue.');
      }

      const tokenParams = {
        grant_type: 'authorization_code',
        code: code,
        redirect_uri: storedConfig.redirectUri,
        client_id: storedConfig.clientId,
        code_verifier: verifier,
      };

      const tokenResponse = await fetch(`${storedConfig.issuerUrl}/oauth/token`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
        },
        body: new URLSearchParams(tokenParams),
      });


      if (!tokenResponse.ok) {
        const errorData = await tokenResponse.json();
        throw new Error(`Token exchange failed: ${errorData.error_description || errorData.error || tokenResponse.statusText}`);
      }

      const tokenData = await tokenResponse.json();
      setTokens(tokenData);

      // Decode ID token to get user info (simple base64 decode)
      if (tokenData.id_token) {
        const payload = JSON.parse(atob(tokenData.id_token.split('.')[1]));
        setUser(payload);
      }

      // Clean up
      sessionStorage.removeItem('pkce_verifier');
      sessionStorage.removeItem('oauth_state');

      // Restore config
      setConfig(storedConfig);
      setIsConfigured(true);

      // Clean URL
      window.history.replaceState({}, document.title, window.location.pathname);

      setLoading(false);
    } catch (err) {
      setError(`Callback failed: ${err.message}`);
      setLoading(false);

      // Clean up on error
      sessionStorage.clear();
      window.history.replaceState({}, document.title, window.location.pathname);
    }
  };

  const handleLogout = () => {
    setUser(null);
    setTokens(null);
    setError(null);
    sessionStorage.clear();
  };

  const handleConfigSave = () => {
    if (config.issuerUrl && config.clientId) {
      setIsConfigured(true);
      setError(null);
    } else {
      setError('Please fill in all configuration fields');
    }
  };

  if (!isConfigured) {
    return (
      <div className="min-h-screen w-full bg-gradient-to-br from-blue-50 to-indigo-100 p-8">
        <div className="max-w-2xl mx-auto">
          <div className="bg-white rounded-lg shadow-lg p-8">
            <div className="flex items-center gap-3 mb-6">
              <Key className="w-8 h-8 text-indigo-600" />
              <h1 className="text-3xl font-bold text-gray-800">Clerk PKCE Test</h1>
            </div>

            <div className="space-y-4 mb-6">
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-2">
                  Clerk Issuer URL
                </label>
                <input
                  type="text"
                  placeholder="https://your-app.clerk.accounts.dev"
                  value={config.issuerUrl}
                  onChange={(e) => setConfig({ ...config, issuerUrl: e.target.value })}
                  className="w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-indigo-500 focus:border-transparent"
                />
                <p className="text-xs text-gray-500 mt-1">Your Clerk domain (no trailing slash)</p>
              </div>

              <div>
                <label className="block text-sm font-medium text-gray-700 mb-2">
                  Client ID
                </label>
                <input
                  type="text"
                  placeholder="your-client-id"
                  value={config.clientId}
                  onChange={(e) => setConfig({ ...config, clientId: e.target.value })}
                  className="w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-indigo-500 focus:border-transparent"
                />
              </div>

              <div>
                <label className="block text-sm font-medium text-gray-700 mb-2">
                  Redirect URI
                </label>
                <input
                  type="text"
                  value={config.redirectUri}
                  onChange={(e) => setConfig({ ...config, redirectUri: e.target.value })}
                  className="w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-indigo-500 focus:border-transparent"
                />
                <p className="text-xs text-gray-500 mt-1">Must be registered in Clerk</p>
              </div>
            </div>

            <button
              onClick={handleConfigSave}
              className="w-full bg-indigo-600 text-white py-3 rounded-lg font-medium hover:bg-indigo-700 transition-colors"
            >
              Save Configuration
            </button>

            {error && (
              <div className="mt-4 p-4 bg-red-50 border border-red-200 rounded-lg flex items-start gap-2">
                <X className="w-5 h-5 text-red-500 flex-shrink-0 mt-0.5" />
                <p className="text-sm text-red-700">{error}</p>
              </div>
            )}
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen min-w-screen bg-gradient-to-br from-blue-50 to-indigo-100 p-8">
      <div className="max-w-4xl mx-auto">
        <div className="bg-white rounded-lg shadow-lg p-8">
          <div className="flex items-center justify-between mb-8">
            <div className="flex items-center gap-3">
              <Key className="w-8 h-8 text-indigo-600" />
              <h1 className="text-3xl font-bold text-gray-800">Clerk PKCE Test</h1>
            </div>
            <button
              onClick={() => setIsConfigured(false)}
              className="text-sm text-gray-600 hover:text-gray-800"
            >
              Edit Config
            </button>
          </div>

          {loading ? (
            <div className="text-center py-12">
              <div className="inline-block animate-spin rounded-full h-12 w-12 border-4 border-indigo-600 border-t-transparent"></div>
              <p className="mt-4 text-gray-600">Processing authentication...</p>
            </div>
          ) : user ? (
            <div className="space-y-6 text-gray-700">
              <div className="flex items-center gap-2 text-green-600 mb-4">
                <Check className="w-6 h-6" />
                <h2 className="text-xl font-semibold">Successfully Authenticated!</h2>
              </div>

              <div className="bg-gray-50 rounded-lg p-6">
                <div className="flex items-center gap-3 mb-4">
                  <User className="w-6 h-6 text-gray-600" />
                  <h3 className="text-lg font-semibold text-gray-800">User Information</h3>
                </div>
                <pre className="bg-white p-4 rounded border border-gray-200 overflow-x-auto text-sm">
                  {JSON.stringify(user, null, 2)}
                </pre>
              </div>

              <div className="bg-gray-50 rounded-lg p-6">
                <h3 className="text-lg font-semibold text-gray-800 mb-4">Tokens</h3>
                <div className="space-y-3">
                  <div>
                    <p className="text-sm font-medium text-gray-600 mb-1">Access Token</p>
                    <p className="text-xs bg-white p-3 rounded border border-gray-200 break-all font-mono">
                      {tokens.access_token}
                    </p>
                  </div>
                  {tokens.id_token && (
                    <div>
                      <p className="text-sm font-medium text-gray-600 mb-1">ID Token</p>
                      <p className="text-xs bg-white p-3 rounded border border-gray-200 break-all font-mono">
                        {tokens.id_token}
                      </p>
                    </div>
                  )}
                  {tokens.refresh_token && (
                    <div>
                      <p className="text-sm font-medium text-gray-600 mb-1">Refresh Token</p>
                      <p className="text-xs bg-white p-3 rounded border border-gray-200 break-all font-mono">
                        {tokens.refresh_token}
                      </p>
                    </div>
                  )}
                </div>
              </div>

              <button
                onClick={handleLogout}
                className="w-full bg-red-600 text-white py-3 rounded-lg font-medium hover:bg-red-700 transition-colors flex items-center justify-center gap-2"
              >
                <LogOut className="w-5 h-5" />
                Logout
              </button>
            </div>
          ) : (
            <div className="text-center py-12">
              <div className="mb-6">
                <div className="inline-flex items-center justify-center w-20 h-20 bg-indigo-100 rounded-full mb-4">
                  <LogIn className="w-10 h-10 text-indigo-600" />
                </div>
                <h2 className="text-2xl font-bold text-gray-800 mb-2">Ready to Test</h2>
                <p className="text-gray-600">Click below to start the PKCE authentication flow</p>
              </div>

              <button
                onClick={handleLogin}
                className="bg-indigo-600 text-white px-8 py-3 rounded-lg font-medium hover:bg-indigo-700 transition-colors inline-flex items-center gap-2"
              >
                <LogIn className="w-5 h-5" />
                Login with Clerk
              </button>

              <div className="mt-8 p-4 bg-blue-50 rounded-lg text-left">
                <h3 className="font-semibold text-gray-800 mb-2">PKCE Flow Steps:</h3>
                <ol className="text-sm text-gray-700 space-y-1 list-decimal list-inside">
                  <li>Generate code verifier and challenge (SHA-256)</li>
                  <li>Redirect to Clerk with challenge</li>
                  <li>User authenticates with Clerk</li>
                  <li>Return with authorization code</li>
                  <li>Exchange code + verifier for tokens</li>
                </ol>
              </div>
            </div>
          )}

          {error && (
            <div className="mt-6 p-4 bg-red-50 border border-red-200 rounded-lg flex items-start gap-2">
              <X className="w-5 h-5 text-red-500 flex-shrink-0 mt-0.5" />
              <p className="text-sm text-red-700">{error}</p>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}