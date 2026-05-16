import random
import secrets
from typing import Sequence

from .field import PRIME, evaluate_polynomial, field_byte_length, mod_inverse

Share = tuple[int, int]


def _randbelow(upper_bound: int, rng: random.Random | None = None) -> int:
    if rng is None:
        return secrets.randbelow(upper_bound)
    return rng.randrange(0, upper_bound)

def build_random_polynomial(
    secret: int,
    threshold: int,
    prime: int = PRIME,
    rng: random.Random | None = None,
) -> list[int]:
    if threshold < 2:
        raise ValueError("threshold must be at least 2")
    if not 0 <= secret < prime:
        raise ValueError("secret must fit in the finite field")

    coefficients = [secret]
    coefficients.extend(_randbelow(prime, rng) for _ in range(threshold - 1))
    return coefficients

def split_secret(
    secret: int,
    threshold: int,
    share_count: int,
    prime: int = PRIME,
    rng: random.Random | None = None,
) -> list[Share]:
    if share_count < threshold:
        raise ValueError("share_count must be at least threshold")
    coefficients = build_random_polynomial(secret, threshold, prime, rng)
    return [
        (index, evaluate_polynomial(coefficients, index, prime))
        for index in range(1, share_count + 1)
    ]

def recover_secret(shares: Sequence[Share], threshold: int, prime: int = PRIME) -> int:
    if len(shares) < threshold:
        raise ValueError("not enough shares to reconstruct the secret")

    usable_shares = list(shares[:threshold])
    x_values = [share[0] for share in usable_shares]
    if len(set(x_values)) != len(x_values):
        raise ValueError("share x-coordinates must be unique")

    secret = 0
    for index, (x_i, y_i) in enumerate(usable_shares):
        numerator = 1
        denominator = 1
        for other_index, (x_j, _) in enumerate(usable_shares):
            if index == other_index:
                continue
            numerator = (numerator * (-x_j % prime)) % prime
            denominator = (denominator * (x_i - x_j)) % prime
        lagrange_basis = numerator * mod_inverse(denominator, prime)
        secret = (secret + y_i * lagrange_basis) % prime
    return secret

def pick_available_shares(
    shares: Sequence[Share],
    available_count: int,
    rng: random.Random,
) -> list[Share]:
    if available_count > len(shares):
        raise ValueError("available_count cannot exceed the total share count")
    return list(rng.sample(list(shares), available_count))

def corrupt_shares(
    shares: Sequence[Share],
    corruption_count: int,
    prime: int = PRIME,
    rng: random.Random | None = None,
) -> tuple[list[Share], list[int]]:
    if corruption_count > len(shares):
        raise ValueError("corruption_count cannot exceed the number of available shares")

    rng = rng or random.Random()
    corrupted = list(shares)
    indices = sorted(rng.sample(range(len(corrupted)), corruption_count))
    for index in indices:
        x_value, y_value = corrupted[index]
        delta = _randbelow(prime - 1, rng) + 1
        corrupted[index] = (x_value, (y_value + delta) % prime)
    return corrupted, indices

def serialized_share_size_bytes(prime: int = PRIME) -> int:
    field_bytes = field_byte_length(prime)
    return field_bytes * 2