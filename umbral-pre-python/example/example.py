import umbral_pre

# As in any public-key cryptosystem, users need a pair
# of public and private keys.
# Additionally, users that delegate access to their data
# (like Alice, in this example) need a signing keypair.

# Key Generation (on Alice's side)
alice_sk = umbral_pre.SecretKey.random()
alice_pk = alice_sk.public_key()

signer_sk = umbral_pre.SecretKey.random()
signer = umbral_pre.Signer(signer_sk)
signer_pk = signer_sk.public_key()

# Key Generation (on Bob's side)
bob_sk = umbral_pre.SecretKey.random()
bob_pk = bob_sk.public_key()

# Now let's encrypt data with Alice's public key.
# Invocation of `encrypt()` returns both the ciphertext
# and the encapsulated symmetric key use to encrypt it.
# Note that anyone with Alice's public key
# can perform this operation.

plaintext = b"peace at dawn"
capsule, ciphertext = umbral_pre.encrypt(alice_pk, plaintext)

# Sign the ciphertext to indicate the data source
# this could be Alice if Alice performs the encryption; it could also be other users if they create ciphertext
capsule_bytes = bytes(capsule)
cipher_digest = umbral_pre.get_digest(ciphertext)
signature = signer.sign_with_aux(capsule_bytes, cipher_digest)

# Simulate network transfer
signature_back = umbral_pre.Signature.from_bytes(bytes(signature))
capsule_back = umbral_pre.Capsule.from_bytes(bytes(capsule))

assert signature_back == signature
assert capsule_back == capsule

# Verify signature
assert signature_back.verify_with_aux(signer_pk, capsule_bytes, cipher_digest)

# Verify capsule
capsule.verify()

# Since data was encrypted with Alice's public key,
# Alice can open the capsule and decrypt the ciphertext
# with her private key.

plaintext_alice = umbral_pre.decrypt(
    alice_sk, capsule, ciphertext);
assert plaintext_alice == plaintext

# When Alice wants to grant Bob access to open her encrypted
# messages, she creates re-encryption key fragments,
# or "kfrags", which are then sent to `shares` proxies or Ursulas.

num_shares = 3 # how many fragments to create
threshold = 2 # how many should be enough to decrypt

proxy_sks = []
proxy_pks = []

for i in range(num_shares):
    proxy_sk = umbral_pre.SecretKey.random()
    proxy_pk = proxy_sk.public_key()
    proxy_sks.append(proxy_sk)
    proxy_pks.append(proxy_pk)

# Split Re-Encryption Key Generation (aka Delegation)
delegation = umbral_pre.delegate(
    alice_sk, threshold, num_shares, proxy_pks
)

# Sign the delegation to indicate data source; this is optional, for example, if delegation is
# sent onchain in a transaction which is already signed
delegation_bytes = bytes(delegation)
signature_del = signer.sign(delegation_bytes)

# Simulate network transfer
delegation_back = umbral_pre.Delegation.from_bytes(delegation_bytes)
signature_del_back = umbral_pre.Signature.from_bytes(bytes(signature_del))
assert delegation_back == delegation
assert signature_del_back == signature_del

# Verify signature
assert signature_del.verify(signer_pk, delegation_bytes)

# Verify public parameters in delegation
delegation.verify_public(threshold, num_shares)

# Verify public parameters in delegation with a specific index
# this function is optional and can be used to report verification failure with a specific index onchain
delegation.verify_public_with_index(threshold, num_shares, 0)
delegation.verify_public_with_index(threshold, num_shares, 1)
delegation.verify_public_with_index(threshold, num_shares, 2)

# Proxies decrypt and verify the key fragments
encrypted_kfrags = delegation.get_encrypted_kfrags()
verified_kfrags = []
for i in range(num_shares):
    kf = encrypted_kfrags[i].decrypt(proxy_sks[i])
    vk = kf.verify()
    verified_kfrags.append(vk)


# Bob asks several proxies to re-encrypt the capsule
# so he can open it.
# Each proxy performs re-encryption on the capsule
# using the kfrag provided by Alice, thus obtaining
# a "capsule fragment", or cfrag.

cfrags = []
for vk in verified_kfrags:
    cf = umbral_pre.reencrypt(bob_pk, capsule, vk)
    cfrags.append(cf)

# Bob collects the resulting cfrags from several proxies.
# Bob must gather at least `threshold` cfrags
# in order to open the capsule.

# Simulate network transfer
cfrag0 = umbral_pre.CapsuleFrag.from_bytes(bytes(cfrags[0]))
cfrag1 = umbral_pre.CapsuleFrag.from_bytes(bytes(cfrags[1]))

# Bob must check that cfrags are valid
verified_cfrag0 = cfrag0.verify(capsule, encrypted_kfrags[0], bob_pk)
verified_cfrag1 = cfrag1.verify(capsule, encrypted_kfrags[1], bob_pk)

# Finally, Bob opens the capsule by using at least `threshold` cfrags,
# and then decrypts the re-encrypted ciphertext.

# Decryption by Bob
plaintext_bob = umbral_pre.decrypt_reencrypted(
    bob_sk, alice_pk, capsule, [verified_cfrag0, verified_cfrag1], ciphertext)
assert plaintext_bob == plaintext
