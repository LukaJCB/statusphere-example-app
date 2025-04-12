# AT Protocol "Statusphere" Example App

An example application covering:

- Signin via OAuth
- Fetch information about users (profiles)
- Listen to the network firehose for new data
- Publish data on the user's account using a custom schema

See https://atproto.com/guides/applications for a guide through the codebase.

## Getting Started

```sh
git clone https://github.com/bluesky-social/statusphere-example-app.git
cd statusphere-example-app
cp .env.template .env
npm install
npm run dev
# Navigate to http://localhost:8080
```


To run the rust client example you will need 2 bsky accounts, fetch a token by logging in and pass them both along with their DIDs as well as the message you want to upload: 

```sh
cd client
cargo run -- \
"<cookie_alice>" \ 
"<did_alice>" \
"<cookie_bob>" \
"<did_bob>" \
"Hello (private) world"
```
