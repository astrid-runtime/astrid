//! Regression coverage for the BLAKE3 public contract.

use blake3::Hasher;

const KEY: [u8; 32] = *b"whats the Elvish word for friend";
const CONTEXT: &str = "BLAKE3 2019-12-27 16:29:52 test vectors context";
const EXTENDED_LEN: usize = 2 * blake3::BLOCK_LEN + 3;

struct Vector {
    input_len: usize,
    hash: &'static str,
    keyed_hash: &'static str,
    derive_key: &'static str,
}

const VECTORS: &[Vector] = &[
    Vector {
        input_len: 0,
        hash: "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262e00f03e7b69af26b7faaf09fcd333050338ddfe085b8cc869ca98b206c08243a26f5487789e8f660afe6c99ef9e0c52b92e7393024a80459cf91f476f9ffdbda7001c22e159b402631f277ca96f2defdf1078282314e763699a31c5363165421cce14d",
        keyed_hash: "92b2b75604ed3c761f9d6f62392c8a9227ad0ea3f09573e783f1498a4ed60d26b18171a2f22a4b94822c701f107153dba24918c4bae4d2945c20ece13387627d3b73cbf97b797d5e59948c7ef788f54372df45e45e4293c7dc18c1d41144a9758be58960856be1eabbe22c2653190de560ca3b2ac4aa692a9210694254c371e851bc8f",
        derive_key: "2cc39783c223154fea8dfb7c1b1660f2ac2dcbd1c1de8277b0b0dd39b7e50d7d905630c8be290dfcf3e6842f13bddd573c098c3f17361f1f206b8cad9d088aa4a3f746752c6b0ce6a83b0da81d59649257cdf8eb3e9f7d4998e41021fac119deefb896224ac99f860011f73609e6e0e4540f93b273e56547dfd3aa1a035ba6689d89a0",
    },
    Vector {
        input_len: 64,
        hash: "4eed7141ea4a5cd4b788606bd23f46e212af9cacebacdc7d1f4c6dc7f2511b98fc9cc56cb831ffe33ea8e7e1d1df09b26efd2767670066aa82d023b1dfe8ab1b2b7fbb5b97592d46ffe3e05a6a9b592e2949c74160e4674301bc3f97e04903f8c6cf95b863174c33228924cdef7ae47559b10b294acd660666c4538833582b43f82d74",
        keyed_hash: "ba8ced36f327700d213f120b1a207a3b8c04330528586f414d09f2f7d9ccb7e68244c26010afc3f762615bbac552a1ca909e67c83e2fd5478cf46b9e811efccc93f77a21b17a152ebaca1695733fdb086e23cd0eb48c41c034d52523fc21236e5d8c9255306e48d52ba40b4dac24256460d56573d1312319afcf3ed39d72d0bfc69acb",
        derive_key: "a5c4a7053fa86b64746d4bb688d06ad1f02a18fce9afd3e818fefaa7126bf73e9b9493a9befebe0bf0c9509fb3105cfa0e262cde141aa8e3f2c2f77890bb64a4cca96922a21ead111f6338ad5244f2c15c44cb595443ac2ac294231e31be4a4307d0a91e874d36fc9852aeb1265c09b6e0cda7c37ef686fbbcab97e8ff66718be048bb",
    },
];

fn painted_input(len: usize) -> Vec<u8> {
    (0..len)
        .map(|index| u8::try_from(index % 251).expect("modulo 251 fits in u8"))
        .collect()
}

fn assert_extended(actual: &[u8], expected_hex: &str, mode: &str) {
    let expected = hex::decode(expected_hex).expect("valid official vector");
    assert_eq!(actual.len(), EXTENDED_LEN);
    assert_eq!(actual, expected, "{mode} extended output changed");
}

#[test]
fn representative_official_vectors_remain_stable() {
    for vector in VECTORS {
        let input = painted_input(vector.input_len);

        let mut extended = [0u8; EXTENDED_LEN];
        Hasher::new()
            .update(&input)
            .finalize_xof()
            .fill(&mut extended);
        assert_extended(&extended, vector.hash, "hash");
        assert_eq!(extended[..32], *blake3::hash(&input).as_bytes());

        let mut keyed_extended = [0u8; EXTENDED_LEN];
        Hasher::new_keyed(&KEY)
            .update(&input)
            .finalize_xof()
            .fill(&mut keyed_extended);
        assert_extended(&keyed_extended, vector.keyed_hash, "keyed hash");
        assert_eq!(
            keyed_extended[..32],
            *blake3::keyed_hash(&KEY, &input).as_bytes()
        );

        let mut derived_extended = [0u8; EXTENDED_LEN];
        Hasher::new_derive_key(CONTEXT)
            .update(&input)
            .finalize_xof()
            .fill(&mut derived_extended);
        assert_extended(&derived_extended, vector.derive_key, "derive key");
        assert_eq!(derived_extended[..32], blake3::derive_key(CONTEXT, &input));
    }
}
