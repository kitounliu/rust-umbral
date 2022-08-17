from typing import Optional, Tuple, List, Sequence


class SecretKey:

    @staticmethod
    def random() -> SecretKey:
        ...

    def public_key(self) -> PublicKey:
        ...

    def to_secret_bytes(self) -> bytes:
        ...

    @staticmethod
    def from_bytes() -> SecretKey:
        ...

    @staticmethod
    def serialized_size() -> int:
        ...


class SecretKeyFactory:

    @staticmethod
    def random() -> SecretKeyFactory:
        ...

    @staticmethod
    def seed_size() -> int:
        ...

    @staticmethod
    def from_secure_randomness(seed: bytes) -> SecretKeyFactory:
        ...

    def make_key(self, label: bytes) -> SecretKey:
        ...

    def make_factory(self, label: bytes) -> SecretKeyFactory:
        ...

    def to_secret_bytes(self) -> bytes:
        ...

    @staticmethod
    def from_bytes() -> SecretKeyFactory:
        ...

    @staticmethod
    def serialized_size() -> int:
        ...


class PublicKey:

    @staticmethod
    def from_bytes() -> PublicKey:
        ...

    @staticmethod
    def serialized_size() -> int:
        ...


class Signer:

    def __init__(secret_key: SecretKey):
        ...

    def sign(self, message: bytes) -> Signature:
        ...

    def sign_with_aux(self, message: bytes, aux: bytes) _> Signature:
        ...

    def verifying_key() -> PublicKey:
        ...


class Signature:

    def verify(self, verifying_pk: PublicKey, message: bytes) -> bool:
        ...

    def verify_with_aux(self, verifying_pk: PublicKey, message: bytes, aux: bytes) -> bool:
        ...

    @staticmethod
    def from_bytes() -> Signature:
        ...

    @staticmethod
    def serialized_size() -> int:
        ...

class Delegation:

    def verify_public(self, threshold: int, num_shares: int):
        ...

    def verify_public_with_index(self, threshold: int, num_shares: int, index: int):
        ...

class Capsule:

    def verify(self) -> bool:
        ...

    @staticmethod
    def serialized_size() -> int:
        ...


def encrypt(delegating_pk: PublicKey, plaintext: bytes) -> Tuple[Capsule, bytes]:
    ...


def decrypt(delegating_sk: SecretKey, capsule: Capsule, ciphertext: bytes) -> bytes:
    ...

def get_digest(message: bytes) -> bytes:
    ...

class KeyFrag:

    def verify(
            self,
            ) -> VerifiedKeyFrag:
        ...

    def skip_verification(self) -> VerifiedKeyFrag:
        ...

    @staticmethod
    def from_bytes() -> KeyFrag:
        ...

    @staticmethod
    def serialized_size() -> int:
        ...


class EncryptedKeyFrag:

    def decrypt(
            self,
            proxy_sk: SecretKey,
    ) -> KeyFrag:
        ...

    @staticmethod
    def to_bytes(self) -> bytes:
        ...

    @staticmethod
    def from_bytes(data: bytes) -> EncryptedKeyFrag:
        ...



class VerifiedKeyFrag:

    def from_verified_bytes(data: bytes) -> VerifiedKeyFrag:
        ...

    def unverify(self) -> KeyFrag:
        ...

    @staticmethod
    def serialized_size() -> int:
        ...


def delegate(
        delegator_sk: SecretKey,
        threshold: int,
        num_shares: int,
        proxy_pks: Sequence[PublicKey],
        ) -> Delegation:
    ...


class CapsuleFrag:

    def verify(
            self,
            capsule: Capsule,
            encrypted_kfrag: EncryptedKeyFrag,
            reader_pk: PublicKey,
            ) -> VerifiedCapsuleFrag:
        ...

    def skip_verification(self) -> VerifiedCapsuleFrag:
        ...

    @staticmethod
    def from_bytes() -> CapsuleFrag:
        ...

    @staticmethod
    def serialized_size() -> int:
        ...


class VerifiedCapsuleFrag:

    def from_verified_bytes(data: bytes) -> VerifiedCapsuleFrag:
        ...

    def unverify(self) -> CapsuleFrag:
        ...

    @staticmethod
    def serialized_size() -> int:
        ...


def reencrypt(reader_pk: PublicKey, capsule: Capsule, vkfrag: VerifiedKeyFrag) -> CapsuleFrag:
    ...


def decrypt_reencrypted(
        reader_sk: SecretKey,
        delegator_pk: PublicKey,
        capsule: Capsule,
        verified_cfrags: Sequence[VerifiedCapsuleFrag],
        ciphertext: bytes,
        ) -> Optional[bytes]:
    ...
