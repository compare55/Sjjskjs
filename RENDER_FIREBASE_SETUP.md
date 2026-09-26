# Render + Firebase setup

This build uses Firebase Realtime Database through the Firebase Admin SDK.
Do NOT put the Firebase service-account JSON/private key inside the ZIP or GitHub repository.

## Render Web Service
Build Command:
npm install

Start Command:
npm start

## Environment variables

FIREBASE_DATABASE_URL=https://comparex-cebd8-default-rtdb.asia-southeast1.firebasedatabase.app/
FIREBASE_PROJECT_ID=comparex-cebd8
FIREBASE_CLIENT_EMAIL=<client_email from your Firebase service-account JSON>
FIREBASE_PRIVATE_KEY=<private_key from your Firebase service-account JSON>
ADMIN_KEY=<your own strong admin key>
NODE_ENV=production

You may alternatively use one variable:
FIREBASE_SERVICE_ACCOUNT_JSON=<entire service-account JSON as one-line JSON>

If FIREBASE_SERVICE_ACCOUNT_JSON is set, it takes precedence over the three separate credential variables.

## Important
The service-account private key uploaded during setup is a secret. Rotate/revoke that key in Firebase after this setup because it was shared in the chat. Then create a new key and use the new value in Render.
