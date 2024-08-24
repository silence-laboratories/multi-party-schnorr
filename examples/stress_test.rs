use bytemuck::{AnyBitPattern, NoUninit, Pod, Zeroable};
use rand::Rng;
use serde::{Deserialize, Serialize};
use std::time::Instant;

const NUM_ITERATIONS: usize = 1_000_000;
const NUM_PARTIES: usize = 10;

type PointBytes = [u8; 32];
type ScalarBytes = [u8; 32];

#[derive(Clone, Copy, AnyBitPattern, NoUninit, Serialize, Deserialize)]
#[repr(C)]
struct EachParty {
    rank: u8,
    big_s: PointBytes,
    x_i: ScalarBytes,
    zeta_seed: [u8; 32],
}

#[derive(Serialize, Deserialize)]
struct SerdeStruct {
    id: u32,
    name: String,
    parties: Vec<EachParty>,
}

#[repr(C)]
#[derive(Clone, Copy, Pod, Zeroable)]
struct FixedSizeData {
    id: u32,
    name_len: u32,
    parties_len: u32,
}

struct CustomStruct {
    buffer: Vec<u8>,
}

impl CustomStruct {
    fn new(id: u32, name: &str, parties: &[EachParty]) -> Self {
        let fixed = FixedSizeData {
            id,
            name_len: name.len() as u32,
            parties_len: parties.len() as u32,
        };
        let mut buffer = bytemuck::bytes_of(&fixed).to_vec();
        buffer.extend_from_slice(name.as_bytes());
        buffer.extend_from_slice(bytemuck::cast_slice(parties));
        Self { buffer }
    }

    fn id(&self) -> u32 {
        let fixed: &FixedSizeData =
            bytemuck::from_bytes(&self.buffer[..std::mem::size_of::<FixedSizeData>()]);
        fixed.id
    }

    fn name(&self) -> &str {
        let fixed: &FixedSizeData =
            bytemuck::from_bytes(&self.buffer[..std::mem::size_of::<FixedSizeData>()]);
        let start = std::mem::size_of::<FixedSizeData>();
        let end = start + fixed.name_len as usize;
        std::str::from_utf8(&self.buffer[start..end]).unwrap()
    }

    fn parties(&self) -> &[EachParty] {
        let fixed: &FixedSizeData =
            bytemuck::from_bytes(&self.buffer[..std::mem::size_of::<FixedSizeData>()]);
        let start = std::mem::size_of::<FixedSizeData>() + fixed.name_len as usize;
        let end = start + (fixed.parties_len as usize * std::mem::size_of::<EachParty>());
        bytemuck::cast_slice(&self.buffer[start..end])
    }
}

fn generate_random_data() -> (SerdeStruct, CustomStruct) {
    let mut rng = rand::thread_rng();
    let id = rng.gen();
    let name = (0..rng.gen_range(5..20))
        .map(|_| rng.gen_range(b'a'..=b'z') as char)
        .collect::<String>();
    let parties = (0..NUM_PARTIES)
        .map(|_| EachParty {
            rank: rng.gen(),
            big_s: rng.gen(),
            x_i: rng.gen(),
            zeta_seed: rng.gen(),
        })
        .collect::<Vec<_>>();

    let serde_struct = SerdeStruct {
        id,
        name: name.clone(),
        parties: parties.clone(),
    };
    let custom_struct = CustomStruct::new(id, &name, &parties);

    (serde_struct, custom_struct)
}

fn main() {
    let mut serde_structs = Vec::new();
    let mut custom_structs = Vec::new();

    for _ in 0..NUM_ITERATIONS {
        let (serde_struct, custom_struct) = generate_random_data();
        serde_structs.push(serde_struct);
        custom_structs.push(custom_struct);
    }

    // Serialization benchmark
    let serde_start = Instant::now();
    for serde_struct in &serde_structs {
        let _ = bincode::serialize(serde_struct).unwrap();
    }
    let serde_serialize_time = serde_start.elapsed();

    let custom_start = Instant::now();
    for custom_struct in &custom_structs {
        let _ = custom_struct.buffer.clone();
    }
    let custom_serialize_time = custom_start.elapsed();

    // Deserialization benchmark
    let serialized_serde: Vec<_> = serde_structs
        .iter()
        .map(|s| bincode::serialize(s).unwrap())
        .collect();
    let serde_start = Instant::now();
    for bytes in &serialized_serde {
        let _: SerdeStruct = bincode::deserialize(bytes).unwrap();
    }
    let serde_deserialize_time = serde_start.elapsed();

    let custom_start = Instant::now();
    for custom_struct in &custom_structs {
        let _ = custom_struct.buffer.as_slice();
    }
    let custom_deserialize_time = custom_start.elapsed();

    // Field access benchmark
    let serde_start = Instant::now();
    for serde_struct in &serde_structs {
        let _ = serde_struct.id;
        let _ = serde_struct.name.len();
        let _sum: u64 = serde_struct.parties.iter().map(|p| p.rank as u64).sum();
    }
    let serde_access_time = serde_start.elapsed();

    let custom_start = Instant::now();
    for custom_struct in &custom_structs {
        let _ = custom_struct.id();
        let _ = custom_struct.name().len();
        let _sum: u64 = custom_struct.parties().iter().map(|p| p.rank as u64).sum();
    }
    let custom_access_time = custom_start.elapsed();

    println!("Serialization:");
    println!("  Serde:   {:?}", serde_serialize_time);
    println!("  Custom:  {:?}", custom_serialize_time);
    println!("Deserialization:");
    println!("  Serde:   {:?}", serde_deserialize_time);
    println!("  Custom:  {:?}", custom_deserialize_time);
    println!("Field Access:");
    println!("  Serde:   {:?}", serde_access_time);
    println!("  Custom:  {:?}", custom_access_time);
}
