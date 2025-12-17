// Copyright (c) Silence Laboratories Pte. Ltd. All Rights Reserved.
// This software is licensed under the Silence Laboratories License Agreement.

//! Example demonstrating client-server DKG protocol with encrypted state storage
//!
//! This example shows how 2 parties can run the DKG protocol where:
//! - party0 (Client): Maintains state locally, does NOT encrypt it
//! - party1 (Server-stateless): Stores encrypted state in an untrusted database
//! - Client provides a trusted session_id that server uses for encryption
//! - State is encrypted with ChaCha20-Poly1305 using session_id as AAD

use std::sync::Arc;

use curve25519_dalek::EdwardsPoint;
use rand::RngCore;

use multi_party_schnorr::{
    common::{storage::InMemoryDB, traits::Round},
    group::GroupEncoding,
    keygen::{client::DkgClient, server::DkgServer, utils::setup_keygen, KeygenParty, R0},
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 2 parties: party0 (client), party1 (server)
    const T: u8 = 2;
    const N: u8 = 2;

    // Setup: Create encryption keys for all parties (simulating PKI setup)
    let parties = setup_keygen::<EdwardsPoint>(T, N);
    let mut party_list: Vec<KeygenParty<R0, EdwardsPoint>> = parties.collect();

    // Extract party0 (client) and party1 (server)
    let party0_r0 = party_list.remove(0); // Client - will maintain state locally
    let party1_r0 = party_list.remove(0); // Server - will use encrypted storage

    // Client generates session_id for server to use
    let session_id = DkgClient::generate_session_id();
    println!(
        "Client (party0) generated session_id for server: {:02x?}",
        session_id
    );

    // Server setup: Create server with encryption key and database
    let mut encryption_key = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut encryption_key);
    let db = Arc::new(InMemoryDB::new());
    let server = Arc::new(DkgServer::<EdwardsPoint, _>::new(
        encryption_key,
        db.clone(),
    ));

    // round 0: Initialize DKG
    println!("=== Round 0: Starting DKG ===");

    // Client (party0): Process locally, maintain state
    let (party0_r1, msg1_client) = party0_r0
        .process(())
        .map_err(|e| format!("Client round 0 failed: {:?}", e))?;
    println!("Client (party0): Generated KeygenMsg1 (state kept locally)");

    // Server (party1): Use server to process and store encrypted state
    let msg1_server = server.start_round_0(session_id, party1_r0)?;
    println!("Server (party1): Generated KeygenMsg1 (state encrypted and stored in DB)");

    let all_msg1 = vec![msg1_client.clone(), msg1_server.clone()];

    // round 1: Process KeygenMsg1 messages
    println!("=== Round 1: Processing KeygenMsg1 ===");

    // Client (party0): Process locally, maintain state
    let (party0_r2, msg2_client) = party0_r1
        .process(all_msg1.clone())
        .map_err(|e| format!("Client round 1 failed: {:?}", e))?;

    // Server (party1): Use server to retrieve encrypted state, process, and store
    let msg2_server = server.process_round_1(session_id, all_msg1.clone())?;

    let all_msg2 = vec![msg2_client.clone(), msg2_server.clone()];

    // round 2: Process KeygenMsg2 messages and get Keyshares
    println!("=== Round 2: Processing KeygenMsg2 ===");

    // Client (party0): Process locally, get keyshare
    let keyshare_client = party0_r2
        .process(all_msg2.clone())
        .map_err(|e| format!("Client round 2 failed: {:?}", e))?;

    // Server (party1): Use server to retrieve encrypted state, process, get keyshare
    // Extract final_session_id from msg2_server (KeygenMsg2.session_id is the final_session_id)
    let final_session_id = msg2_server.session_id;
    let keyshare_server = server.process_round_2(session_id, final_session_id, all_msg2.clone())?;

    let public_key_client = keyshare_client.public_key();
    let public_key_server = keyshare_server.public_key();

    println!(
        "Client (party0) Public Key: {}",
        bs58::encode(public_key_client.to_bytes()).into_string()
    );
    println!(
        "Server Public Key:{}",
        bs58::encode(public_key_server.to_bytes()).into_string()
    );

    // Verify both parties have the same public key
    if public_key_client == public_key_server {
        println!("Both parties have the same public key!");
    } else {
        return Err("Public keys do not match".into());
    }

    Ok(())
}
