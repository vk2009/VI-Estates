# VI-Estates

This project is a demo casino-style experience with server-side account storage.

## Run locally

1. Install dependencies:
   ```bash
   npm install
   ```

2. Start the server:
   ```bash
   npm start
   ```

3. Open `http://localhost:3000` in your browser.

## Backend

- `server.js` serves the static frontend and provides REST API endpoints.
- Accounts are stored in SQLite at `data/vi_estates.sqlite`.
- Sessions are stored in the database and authenticated via Bearer token.

