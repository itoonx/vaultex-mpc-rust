//! Stable smoke run of the `tron_decode` fuzz target's invariants (the fuzz campaign itself is not
//! run here): the committed seed corpus, plus deterministic truncations, byte flips, insertions
//! and deletions of every seed.

#[path = "../fuzz/tron_invariants.rs"]
mod tron_invariants;

use std::path::Path;

use tron_invariants::check;

fn seeds() -> Vec<Vec<u8>> {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("fuzz/corpus/tron_decode");
    let mut paths: Vec<_> = std::fs::read_dir(dir)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .collect();
    paths.sort();
    paths.iter().map(|p| std::fs::read(p).unwrap()).collect()
}

#[test]
fn seed_corpus_is_accepted() {
    let seeds = seeds();
    assert_eq!(seeds.len(), 3);
    for seed in &seeds {
        assert_eq!(
            check(seed),
            1,
            "each seed fits exactly one permission context"
        );
    }
}

#[test]
fn mutated_seeds_keep_the_invariants() {
    let (mut runs, mut accepted) = (0usize, 0usize);
    let mut run = |input: &[u8]| {
        runs += 1;
        accepted += check(input);
    };
    for seed in seeds() {
        for cut in 0..seed.len() {
            run(&seed[..cut]);
        }
        for i in 0..seed.len() {
            for mask in [0x01, 0x02, 0x40, 0x80, 0xff] {
                let mut m = seed.clone();
                m[i] ^= mask;
                run(&m);
            }
            let mut m = seed.clone();
            m.remove(i);
            run(&m);
        }
        for i in 0..=seed.len() {
            for byte in [0x00, 0x08, 0x80, 0xff] {
                let mut m = seed.clone();
                m.insert(i, byte);
                run(&m);
            }
        }
    }
    assert!(runs > 5_000, "{runs} inputs");
    // Not vacuous: flips inside the reference-block hash, amounts and addresses that keep the
    // shape valid are accepted, and the invariants held for them too.
    assert!(accepted > 0, "no mutant was accepted");
}
