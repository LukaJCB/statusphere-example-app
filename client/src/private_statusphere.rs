use base64::prelude::*;
use openmls::prelude::{tls_codec::*, *};
use openmls_basic_credential::SignatureKeyPair;
use openmls_traits::signatures::Signer;

use crate::http::*;
use aes_gcm_siv::{
    aead::{
        generic_array::{typenum, GenericArray},
        Aead, AeadCore, KeyInit, OsRng,
    },
    Aes256GcmSiv,
};
use reqwest::Client;
use std::collections::HashMap;

pub struct User {
    pub did: String,
    pub cookie: String,
    pub credential: CredentialWithKey,
    pub key_package: KeyPackage,
    pub signature_keypair: SignatureKeyPair,
}

impl User {
    pub fn from_options(
        did: Option<&String>,
        cookie: Option<&String>,
        identity: Vec<u8>,
        provider: &impl OpenMlsProvider,
        ciphersuite: Ciphersuite,
    ) -> Option<User> {
        match (did, cookie) {
            (Some(d), Some(c)) => {
                let (credential_with_key, signer) =
                    generate_credential_with_key(identity, ciphersuite.signature_algorithm());
                let key_package =
                    generate_key_package(ciphersuite, provider, &signer, &credential_with_key);
                Some(User {
                    did: d.to_owned(),
                    cookie: c.to_owned(),
                    credential: credential_with_key,
                    key_package: key_package.key_package().clone(),
                    signature_keypair: signer,
                })
            }
            _ => None,
        }
    }
}

// A helper to create and store credentials.
fn generate_credential_with_key(
    identity: Vec<u8>,
    signature_algorithm: SignatureScheme,
) -> (CredentialWithKey, SignatureKeyPair) {
    let credential = BasicCredential::new(identity);
    let signature_keys =
        SignatureKeyPair::new(signature_algorithm).expect("Error generating a signature key pair.");

    (
        CredentialWithKey {
            credential: credential.into(),
            signature_key: signature_keys.public().into(),
        },
        signature_keys,
    )
}

// A helper to create key package bundles.
fn generate_key_package(
    ciphersuite: Ciphersuite,
    provider: &impl OpenMlsProvider,
    signer: &SignatureKeyPair,
    credential_with_key: &CredentialWithKey,
) -> KeyPackageBundle {
    // Create the key package
    KeyPackage::builder()
        .build(ciphersuite, provider, signer, credential_with_key.clone())
        .expect("Could not create KeyPackage")
}

// parse the record key from the full uri
fn uri_to_rkey(uri: &String) -> Option<&str> {
    uri.split("/").last()
}

// Turn a single message into a staged welcome and fail if the message is not a welcome message
pub fn expect_welcome(msg: &Message, provider: &impl OpenMlsProvider) -> StagedWelcome {
    let decoded = BASE64_STANDARD
        .decode(&msg.message)
        .expect("Could not decode Base64");

    let mls_message_in =
        MlsMessageIn::tls_deserialize_exact(decoded).expect("Could not tls deserialize");

    let welcome = match mls_message_in.extract() {
        MlsMessageBodyIn::Welcome(welcome) => welcome,
        _ => unreachable!("Unexpected message type."),
    };

    StagedWelcome::new_from_welcome(
        provider,
        &MlsGroupJoinConfig::builder()
            .use_ratchet_tree_extension(true)
            .build(),
        welcome,
        // The public tree is need and transferred out of band.
        // It is also possible to use the [`RatchetTreeExtension`]
        None, //Some(bob_group.export_ratchet_tree().into()),
    )
    .expect("Error creating a staged join from Welcome")
}

// Turn a single message into a payload and fail if the message is not an application message
pub fn expect_application_message(
    message: &Message,
    group: &mut MlsGroup,
    provider: &impl OpenMlsProvider,
) -> Vec<u8> {
    let decoded = BASE64_STANDARD
        .decode(&message.message)
        .expect("Could not decode Base64");

    let mls_message_in =
        MlsMessageIn::tls_deserialize_exact(decoded).expect("Could not tls deserialize");

    let protocol_message: ProtocolMessage = mls_message_in
        .try_into_protocol_message()
        .expect("Expected a PublicMessage or a PrivateMessage");

    let processed_message = group
        .process_message(provider, protocol_message)
        .expect("Could not process message.");

    if let ProcessedMessageContent::ApplicationMessage(application_message) =
        processed_message.into_content()
    {
        application_message.into_bytes()
    } else {
        unreachable!("Unexpected message type.")
    }
}

// Serialize a Hashmap of DEKs
pub fn deks_to_bytes(deks: &HashMap<String, String>) -> Vec<u8> {
    let s = deks
        .iter()
        .map(|(k, v)| format!("{}:{}", k, v))
        .collect::<Vec<String>>(); // fold(String::new(), |acc, (k,v)| format!("{}|{}:{}", acc, k, v));

    return s.join("|").as_bytes().to_vec();
}

// Deserialize a Hashmap of DEKs
pub fn deks_from_bytes(b: Vec<u8>) -> HashMap<String, String> {
    let mut m: HashMap<String, String> = HashMap::new();
    let s = String::from_utf8(b).expect("Could not convert bytes to String");

    for kv in s.split("|") {
        let mut it = kv.split(":");
        let k = it.next().expect("Missing key");
        let v = it.next().expect("Missing value");
        m.insert(k.to_owned(), v.to_owned());
    }
    m
}

// encrypt the status with a new key, upload it and send the DEKs for all the statuses to the group
pub async fn encrypt_upload_send_deks(
    client: &Client,
    cookie: &String,
    status: &String,
    mls_group: &mut MlsGroup,
    signer: &impl Signer,
    provider: &impl OpenMlsProvider,
    keys: &mut HashMap<String, String>,
) -> Result<(), Box<dyn std::error::Error>> {
    let key = Aes256GcmSiv::generate_key(OsRng);
    let (ct, nonce) = encrpyt_status(status, &key)?;

    let status_id = upload_status(client, cookie, &ct, &nonce).await?;

    keys.insert(status_id, BASE64_STANDARD.encode(key));

    let msg_out = send_deks(mls_group, signer, keys, provider);

    upload_message(client, cookie, &msg_out).await?;
    Ok(())
}

// decrypt a single status with the given map of DEKs
pub fn decrypt_status(deks: &HashMap<String, String>, status: Status) -> Option<Status> {
    let status_id = uri_to_rkey(&status.uri)?;
    let key = BASE64_STANDARD
        .decode(deks.get(status_id)?)
        .expect("BASE64 decoding error");
    let nonce = BASE64_STANDARD
        .decode(&status.nonce)
        .expect("BASE64 decoding error");
    let ciphertext = BASE64_STANDARD
        .decode(&status.status)
        .expect("BASE64 decoding error");

    Some(Status {
        status: decrypt_ciphertext(&nonce, &ciphertext, &key),
        ..status
    })
}

// decrypt a single ciphertext with a single DEK
fn decrypt_ciphertext(nonce: &Vec<u8>, ciphertext: &Vec<u8>, key: &Vec<u8>) -> String {
    let cipher = Aes256GcmSiv::new(key.as_slice().into());
    let decrypted = cipher
        .decrypt(nonce.as_slice().into(), ciphertext.as_slice())
        .expect("Could not decrypt");
    String::from_utf8(decrypted).expect("Could not decode utf8")
}

// encrypt a single status and return the ciphertext and the nonce
fn encrpyt_status(
    status: &String,
    key: &GenericArray<u8, typenum::U32>,
) -> Result<(String, String), Error> {
    let cipher = Aes256GcmSiv::new(key);
    let nonce = Aes256GcmSiv::generate_nonce(&mut OsRng); // 96-bits; unique per message
    let ciphertext = cipher
        .encrypt(&nonce, status.as_bytes())
        .expect("Could not encrypt status");
    Ok((
        BASE64_STANDARD.encode(ciphertext),
        BASE64_STANDARD.encode(nonce),
    ))
}

// create a group message containing a map of DEKs
fn send_deks(
    mls_group: &mut MlsGroup,
    signer: &impl Signer,
    deks: &HashMap<String, String>,
    provider: &impl OpenMlsProvider,
) -> MlsMessageOut {
    mls_group
        .create_message(provider, signer, deks_to_bytes(deks).as_slice())
        .expect("Error creating application message.")
}

// Fetch the public keys for a given DID and return a tuple of messages adding them
async fn create_add_member_messages(
    client: &Client,
    mls_group: &mut MlsGroup,
    signer: &impl Signer,
    provider: &impl OpenMlsProvider,
    did: &String,
) -> Result<(MlsMessageOut, MlsMessageOut), Box<dyn std::error::Error>> {
    if let Some(kp) = fetch_key_materials(client, did, provider).await? {
        let (mls_message_out, welcome_out, _group_info) = mls_group
            .add_members(provider, signer, &[kp])
            .expect("Failed to add member");

        Ok((mls_message_out, welcome_out))
    } else {
        Err("No member found".into())
    }
}

// Add a member by a given DID and send them the given DEKs
pub async fn add_member(
    client: &Client,
    cookie: &String,
    mls_group: &mut MlsGroup,
    signer: &impl Signer,
    provider: &impl OpenMlsProvider,
    identifier: &String,
    deks: &HashMap<String, String>,
) -> Result<(), Box<dyn std::error::Error>> {
    let (mls_message_out, welcome_out) =
        create_add_member_messages(client, mls_group, signer, provider, identifier).await?;

    upload_message(client, cookie, &mls_message_out).await?;
    upload_message(client, cookie, &welcome_out).await?;

    if !deks.is_empty() {
        let out = send_deks(mls_group, signer, deks, provider);

        upload_message(client, cookie, &out).await?;
    }

    Ok(())
}
