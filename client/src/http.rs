use openmls::prelude::{tls_codec::*, *};
use serde::Deserialize as JsonDeserialize;
use std::fmt;

use openmls::prelude::tls_codec::Deserialize;

use reqwest::Client;

use base64::prelude::*;

#[derive(JsonDeserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct Message {
    pub message: String,
}

#[derive(JsonDeserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct Status {
    pub uri: String,
    pub author_did: String,
    pub status: String,
    pub nonce: String,
    pub created_at: String,
    pub indexed_at: String,
}

impl fmt::Display for Status {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "[author: {}, status: {}, created: {}, indexed: {}]",
            self.author_did, self.status, self.created_at, self.indexed_at
        )
    }
}

#[derive(JsonDeserialize, Debug)]
#[serde(rename_all = "camelCase")]
struct JsonKeyPackage {
    package: String,
}

pub async fn upload_message(
    client: &Client,
    cookie: &String,
    msg: &MlsMessageOut,
) -> Result<(), Box<dyn std::error::Error>> {
    let base64_encoded = BASE64_STANDARD.encode(msg.tls_serialize_detached()?);
    let params = [("message", base64_encoded)];
    let _ = client
        .post("http://127.0.0.1:8080/message")
        .form(&params)
        .header("Cookie", cookie)
        .send()
        .await?;

    Ok(())
}

pub async fn upload_status(
    client: &Client,
    cookie: &String,
    status: &String,
    nonce: &String,
) -> Result<String, Box<dyn std::error::Error>> {
    let params = [("status", status), ("nonce", nonce)];
    let resp: String = client
        .post("http://127.0.0.1:8080/status")
        .form(&params)
        .header("Cookie", cookie)
        .send()
        .await?
        .text()
        .await?;

    Ok(resp)
}

pub async fn get_statuses(client: &Client) -> Result<Vec<Status>, Box<dyn std::error::Error>> {
    let resp: Vec<Status> = client
        .get("http://127.0.0.1:8080/status")
        .send()
        .await?
        .json()
        .await?;

    Ok(resp)
}

pub async fn get_latest_message(
    client: &Client,
) -> Result<Option<Message>, Box<dyn std::error::Error>> {
    let resp: Vec<Message> = client
        .get("http://127.0.0.1:8080/message")
        .send()
        .await?
        .json()
        .await?;

    Ok(resp.first().cloned())
}

pub async fn upload_key_materials(
    client: &Client,
    cookie: &String,
    key_package: &KeyPackage,
) -> Result<(), Box<dyn std::error::Error>> {
    let base64_encoded = BASE64_STANDARD.encode(key_package.tls_serialize_detached()?);
    let params = [("keyPackage", base64_encoded)];
    let _ = client
        .post("http://127.0.0.1:8080/keyPackage")
        .form(&params)
        .header("Cookie", cookie)
        .send()
        .await?;

    Ok(())
}

pub async fn fetch_key_materials(
    client: &Client,
    did: &String,
    provider: &impl OpenMlsProvider,
) -> Result<Option<KeyPackage>, Box<dyn std::error::Error>> {
    let resp: Option<JsonKeyPackage> = client
        .get("http://127.0.0.1:8080/keyPackage/".to_owned() + did)
        .send()
        .await?
        .json()
        .await?;

    match resp {
        None => Ok(None),
        Some(s) => Ok(
            KeyPackageIn::tls_deserialize_exact(BASE64_STANDARD.decode(s.package)?)?
                .validate(provider.crypto(), ProtocolVersion::Mls10)
                .map(|kp| Some(kp))?,
        ),
    }
}
