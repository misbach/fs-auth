/**
 * Uses the FamilySearch Client Credentials flow to generate and return a token.
 * 
 * See: https://www.familysearch.org/developers/docs/guides/client-secret
 */

export default {
    async fetch(request, env, context) {
        async function get(request, env, context) {
            let clientId = env.CLIENT_ID;
            // The PRIVATE_KEY env variable should contain only the Base64 encoded key data, not the BEGIN/END headers
            // Generate a key and corresponding certificate as follows:
            //   # openssl genrsa -out private-key.pem 2048
            //   # openssl req -new -x509 -key private-key.pem -out public-cert.pem -days 1825
            let keyData = Uint8Array.from(atob(env.PRIVATE_KEY), (m) => m.codePointAt(0));

            let algo = {name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-512'};
            let key = await crypto.subtle.importKey('pkcs8', keyData, algo, false, ['sign']);

            let time = String(Date.now());
            let bytes = new TextEncoder().encode(time);
            let encrypted = await crypto.subtle.sign(algo, key, bytes)
            let binString = Array.from(new Uint8Array(encrypted), (m) => String.fromCodePoint(m)).join('');
            let clientSecret = btoa(binString) + ':' + time;

            let data = new FormData();
            data.append('grant_type', 'client_credentials');
            data.append('client_id', clientId);
            data.append('client_secret', clientSecret);

            let url = 'https://ident.familysearch.org/cis-web/oauth2/v3/token?' + new URLSearchParams(data).toString();

            let response = await fetch(url, {method: 'POST'});
            let token = await response.json();

            return new Response(JSON.stringify(token), {status: response.status, statusText: response.statusText, headers: corsHeaders()});
        }

        async function options(request, env, context) {
            let headers = {'Allow': 'GET, OPTIONS'};
            if (request.headers.get('Origin')
                && request.headers.get('Access-Control-Request-Method')
                && request.headers.get('Access-Control-Request-Headers')) {
                headers = {
                    ...corsHeaders(),
                    'Access-Control-Allow-Headers': request.headers.get('Access-Control-Request-Headers'),
                };
            }
            return new Response(null, {headers: headers});
        }

        return {
            'GET': get,
            'OPTIONS': options,
        }[request.method](request, env, context);

        function corsHeaders() {
            return {
                'Access-Control-Allow-Origin': '*',
                'Access-Control-Allow-Methods': 'GET,OPTIONS',
                'Access-Control-Max-Age': '86400',
            };
        }
    }
};