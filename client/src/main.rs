use openmls::prelude::*;
use reqwest::Client;
use std::{collections::HashMap, env};

mod http;
mod private_statusphere;

use http::*;
use private_statusphere::*;

#[tokio::main]
async fn main() {
    // Define ciphersuite ...
    let ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;
    // ... and the crypto provider to use.
    let provider = &openmls_rust_crypto::OpenMlsRustCrypto::default();

    let args: Vec<String> = env::args().collect();

    let cookie_alice = args.get(1);
    let did_alice = args.get(2);

    let cookie_bob = args.get(3);

    let did_bob = args.get(4);

    let status = args.get(5);

    let client = reqwest::Client::new();

    let alice = User::from_options(
        did_alice,
        cookie_alice,
        "alice".into(),
        provider,
        ciphersuite,
    );

    let bob = User::from_options(did_bob, cookie_bob, "bob".into(), provider, ciphersuite);

    match (alice, bob, status) {
        (Some(a), Some(b), Some(s)) => scenario(a, b, s, &client, provider).await.unwrap(),
        _ => panic!("Please pass all the command line args"),
    }
}

async fn scenario(
    alice: User,
    bob: User,
    status: &String,
    client: &Client,
    provider: &impl OpenMlsProvider,
) -> Result<(), Box<dyn std::error::Error>> {
    //alice uploads her key materials
    upload_key_materials(&client, &alice.cookie, &alice.key_package).await?;

    //bob uploads her key materials
    upload_key_materials(&client, &bob.cookie, &bob.key_package).await?;

    //alice creates a group
    let mut alice_group = MlsGroup::new(
        provider,
        &alice.signature_keypair,
        &MlsGroupCreateConfig::builder()
            .use_ratchet_tree_extension(true)
            .build(),
        alice.credential,
    )
    .expect("An unexpected error occurred.");

    // Alice creates a hashmap for storing her data encryption keys
    let mut alice_deks: HashMap<String, String> = HashMap::new();

    //alice fetches bob's key materials, adds him and uploads the message
    add_member(
        &client,
        &alice.cookie,
        &mut alice_group,
        &alice.signature_keypair,
        provider,
        &bob.did,
        &alice_deks,
    )
    .await?;

    // Alice merges the pending commit that adds bob.
    alice_group
        .merge_pending_commit(provider)
        .expect("error merging pending commit");

    //bob gets the message
    let message = get_latest_message(&client)
        .await?
        .expect("Could not read any message");

    //bob creates the group from the message
    let mut bob_group = expect_welcome(&message, provider)
        .into_group(provider)
        .expect("Error creating the group from the staged join");

    // Alice uploads her first status and stores the dek in the hashmap
    encrypt_upload_send_deks(
        &client,
        &alice.cookie,
        status,
        &mut alice_group,
        &alice.signature_keypair,
        provider,
        &mut alice_deks,
    )
    .await?;

    //bob gets messages again
    let message = get_latest_message(&client)
        .await?
        .expect("Could not read any message");

    //bob decrypts the message using the group keys
    let application_message = expect_application_message(&message, &mut bob_group, provider);

    //bob turns the message into a map of DEKs
    let bob_deks: HashMap<String, String> = deks_from_bytes(application_message);

    //bob fetches statuses
    let statuses: Vec<Status> = get_statuses(&client).await?;

    //decrypt the statuses that bob has DEKs to
    let decrypted_statuses: Vec<Status> = statuses
        .into_iter()
        .filter_map(|s| decrypt_status(&bob_deks, s))
        .collect();

    decrypted_statuses.iter().for_each(|s| println!("{}", s));
    Ok(())
}

//"sid=Fe26.2*1*00efd973ab9e3ab9d0445d0b0c2587a69ca3834fa8b141e59a43c15d987b1977*DDpXm5BStJnP20zX0ghN0g*JmqfOqQeUvEFrOCPvDMQ8QiJlGbLMuXIj2BOvU9kr03nysmSkkKZLSDaEl1eD3Qu*1745609969108*432abe4e677c88e4ce991c4a35f2a506385dd6449516c0789dd92251b1bbf4b8*RkdbKNZc1zSNGycbnX25WAbke8lXmljqMK0Sm2sFLIs~2"

//cargo run -- "sid=Fe26.2*1*7602043493397ac63866af5de8202d795a2e6212e454d735e262d406311bbb0a*9ElJzbyc7XiVljTXiiWmIQ*vYzDs89aAUWl4CaORyCr9yzu4gQN13aCiGhURUJUASZjksD-kwlWYRYB5QUfok-i*1745615837099*0b04515bdfd4bb7e1052067d4e6f8b6dc1eb67b2fb33b093f42850d3c931e0f1*Gnpt2xa7oVxLhsKaKxE-ZAMWruVU9MNOtkTNGuYt54E~2" "sid=Fe26.2*1*4f688cc8559badfeaec7af98e71c1d3712e17c8d5c9647a03e9c7bfe65a96d25*D8TVZ8LoDUX14Q14TU5kPQ*ADE_ZWZT0aqgzM1sUEq2g8_9tko8xdmVlu9Ci4VfyhTjvc_a6DQjo1lvZAOecR10*1745615872281*5cd818f6dd1a482c27800689f33dfddd5406e00189515dd43e2d0fb7cb74fea8*bkXKQFTfa9ojnBJ6Lko1504elNWaV1T7bZUZIkeN8tk~2" "did:plc:2xyjch53vrvt7en6bbshm74t"
// "sid=Fe26.2*1*8368bc94cccb65a3e73e35ef25301bec07fd7c7644d67f6368a0e8c70d63e49c*UAGxMSMs5PNQGvIACgWCIQ*EblN9-esakg5kJNEQapcrExoZegUN8GNFN_vcoG9RJGOiAyXAdvKKM95d5RB0ZLZ*1745611337069*c131d00004461ee89b68a2e9b3c46304a1fe86c1e33f8ae0f9aa7c6ead9168f2*tjbtT1C5VIImlm4AQsqzAdGol1kdIB1O2-qJDod-uuI~2"
// did:plc:7rua64flbgf3vm5qbhga2krc
// "sid=Fe26.2*1*3236c893717cfb2a7ea34fdbb61023de133c111836dff7ebb3b943a26b5d7dda*88AfctOdfQUPFIHxV5X9wA*wqXGCLfO7Do9BtJO44QD8-R-urwz-ESgttjfrkO0prZQLojarNRU6HQsMmZCDH-S*1745615638083*c6d82c3a8bc9eaa38b6851c51ee0e168cb71c5a75690afb70d5c026a2f715da0*JmnH8h1NbygG_3mvwe5GlmyVFFl_Pa0HZgdzLuK5ms0~2"
// did:plc:2xyjch53vrvt7en6bbshm74t
