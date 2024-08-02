# Multiparty EdDSA

This is a pure Rust implementation of the paper [Simple Three-Round Multiparty Schnorr Signing with Full Simulatability](https://eprint.iacr.org/2022/374.pdf).

Additionally, this crate provides a way to perform Hierarchical Key generation and signing using ranks for each party. If you don't need this functionality please set rank to 0 for all.

## Crate structure
We provide two state machines `KeygenParty` and `SignParty`.  

### Round trait
Each state machine implements the `Round` trait. This trait defines the state transition for any round based protocol and does not allow invalid transitions.

```rust
/// Trait that defines a state transition for any round based protocol.
pub trait Round {
    /// Output of the state transition.
    type Output;
    /// Input of the state transition.
    type Input;
    /// Transition to the next state.
    fn process(self, messages: Self::Input) -> Self::Output;
}
```
Based on the paper, message communication is done via broadcast each round. We provide a basic `Coordinator` struct that handles this communication locally. 

We recommend implementing your own coordinator if you want to communicate over the network.

### Examples
Please find the examples in the `examples` folder.





