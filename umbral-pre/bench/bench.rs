use criterion::measurement::Measurement;
use criterion::{criterion_group, criterion_main, BenchmarkGroup, Criterion};

#[cfg(feature = "bench-internals")]
use umbral_pre::bench::{
    capsule_derive_key, capsule_derive_key_reencrypted, capsule_from_public_key,
};

use umbral_pre::{
    decrypt, decrypt_reencrypted, delegate, encrypt, reencrypt, SecretKey, Signer,
    VerifiedCapsuleFrag,
};

#[cfg(feature = "bench-internals")]
fn bench_capsule_from_public_key<'a, M: Measurement>(group: &mut BenchmarkGroup<'a, M>) {
    let delegator_sk = SecretKey::random();
    let delegator_pk = delegator_sk.public_key();
    group.bench_function("Capsule::from_public_key", |b| {
        b.iter(|| capsule_from_public_key(&delegator_pk))
    });
}

#[cfg(feature = "bench-internals")]
fn bench_capsule_derive_key<'a, M: Measurement>(group: &mut BenchmarkGroup<'a, M>) {
    let delegator_sk = SecretKey::random();
    let delegator_pk = delegator_sk.public_key();
    let plaintext = b"peace at dawn";
    let (capsule, _ciphertext) = encrypt(&delegator_pk, plaintext).unwrap();
    group.bench_function("Capsule::derive_key", |b| {
        b.iter(|| capsule_derive_key(&capsule, &delegator_sk))
    });
}

#[cfg(feature = "bench-internals")]
fn bench_capsule_derive_key_reencrypted<'a, M: Measurement>(group: &mut BenchmarkGroup<'a, M>) {
    let delegator_sk = SecretKey::random();
    let delegator_pk = delegating_sk.public_key();

    let signer = Signer::new(SecretKey::random());

    let reader_sk = SecretKey::random();
    let reader_pk = reader_sk.public_key();

    let (capsule, _key_seed) = capsule_from_public_key(&delegator_pk);

    let threshold: u32 = 2;
    let num_frags: u32 = threshold + 1;

    let proxy_sks: Vec<_> = (0..num_frags as usize)
        .map(|_| SecretKey::random())
        .collect();
    let proxy_pks: Vec<_> = proxy_sks.iter().map(|sk| sk.public_key()).collect();
    let proxy_pks_ref: Vec<_> = proxy_pks.iter().map(|pk| pk).collect();

    let delegation = delegate(&delegator_sk, threshold, num_frags, &proxy_pks_ref).unwrap();

    let verified_kfrags: Vec<_> = delegation
        .encrypted_kfrags
        .iter()
        .zip(proxy_sks.iter())
        .map(|(ek, sk)| ek.decrypt(sk).unwrap().verify().unwrap())
        .collect();

    let cfrags: Vec<_> = verified_kfrags
        .into_iter()
        .map(|vkfrag| reencrypt(&reader_pk, &capsule, vkfrag))
        .collect();

    let cfrags_ref: Vec<_> = cfrags[0..threshold as usize].iter().map(|c| c).collect();

    group.bench_function("Capsule::derive_key_reencrypted", |b| {
        b.iter(|| {
            capsule_derive_key_reencrypted(&capsule, &receiving_sk, &delegating_pk, &cfrags_ref)
        })
    });
}

fn bench_pre<'a, M: Measurement>(group: &mut BenchmarkGroup<'a, M>) {
    let delegator_sk = SecretKey::random();
    let delegator_pk = delegator_sk.public_key();
    let plaintext = b"peace at dawn";

    // Encryption

    group.bench_function("encrypt", |b| {
        b.iter(|| encrypt(&delegator_pk, &plaintext[..]))
    });

    // Decryption with the original key

    let (capsule, ciphertext) = encrypt(&delegator_pk, plaintext).unwrap();
    group.bench_function("decrypt", |b| {
        b.iter(|| decrypt(&delegator_sk, &capsule, &ciphertext[..]))
    });

    // Kfrag generation

    let threshold: u32 = 2;
    let num_frags: u32 = threshold + 1;

    let signer = Signer::new(SecretKey::random());

    let reader_sk = SecretKey::random();
    let reader_pk = reader_sk.public_key();

    let proxy_sks: Vec<_> = (0..num_frags as usize)
        .map(|_| SecretKey::random())
        .collect();
    let proxy_pks: Vec<_> = proxy_sks.iter().map(|sk| sk.public_key()).collect();
    let proxy_pks_ref: Vec<_> = proxy_pks.iter().map(|pk| pk).collect();

    group.bench_function("delegate", |b| {
        b.iter(|| {
            delegate(&delegator_sk, threshold, num_frags, &proxy_pks_ref).unwrap();
        })
    });

    // Reencryption

    let delegation = delegate(&delegator_sk, threshold, num_frags, &proxy_pks_ref).unwrap();

    let vkfrag = delegation.encrypted_kfrags[0]
        .decrypt(&proxy_sks[0])
        .unwrap()
        .verify()
        .unwrap();

    group.bench_function("reencrypt", |b| {
        b.iter(|| reencrypt(&reader_pk, &capsule, vkfrag.clone()))
    });

    // Decryption of the reencrypted data

    let verified_kfrags: Vec<_> = delegation
        .encrypted_kfrags
        .iter()
        .zip(proxy_sks.iter())
        .map(|(ek, sk)| ek.decrypt(sk).unwrap().verify().unwrap())
        .collect();

    // Bob requests re-encryption to some set of `threshold` proxies
    // Proxy reencrypts capsule
    let cfrags: Vec<_> = verified_kfrags
        .into_iter()
        .map(|vkfrag| reencrypt(&reader_pk, &capsule, vkfrag))
        .collect();

    group.bench_function("verify cfrag", |b| {
        b.iter(|| {
            cfrags[0]
                .clone()
                .verify(&capsule, &delegation.encrypted_kfrags[0], &reader_pk)
                .unwrap()
        })
    });

    let verified_cfrags: Vec<_> = cfrags
        .into_iter()
        .zip(delegation.encrypted_kfrags.iter())
        .map(|(cfrag, ek)| cfrag.verify(&capsule, ek, &reader_pk).unwrap())
        .collect();

    let verified_cfrags_ref: Vec<_> = verified_cfrags[0..threshold as usize]
        .iter()
        .map(|vc| vc)
        .collect();

    group.bench_function("decrypt_reencrypted", |b| {
        b.iter(|| {
            decrypt_reencrypted(
                &reader_sk,
                &delegator_pk,
                &verified_cfrags_ref,
                &capsule,
                &ciphertext,
            )
        })
    });
}

#[cfg(feature = "bench-internals")]
fn group_internals(c: &mut Criterion) {
    let mut group = c.benchmark_group("internals");
    bench_capsule_from_public_key(&mut group);
    bench_capsule_derive_key(&mut group);
    bench_capsule_derive_key_reencrypted(&mut group);
    group.finish();
}

fn group_pre(c: &mut Criterion) {
    let mut group = c.benchmark_group("PRE API");
    bench_pre(&mut group);
    group.finish();
}

#[cfg(feature = "bench-internals")]
criterion_group!(benches, group_internals, group_pre);

#[cfg(not(feature = "bench-internals"))]
criterion_group!(benches, group_pre);

criterion_main!(benches);
