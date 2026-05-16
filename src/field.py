from typing import Iterable, Sequence

# NIST P-384 prime
PRIME = int(
    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFE"
    "FFFFFFFF0000000000000000FFFFFFFF",
    16,
)

def mod_inverse(value: int, prime: int = PRIME) -> int:
    value %= prime
    if value == 0:
        raise ZeroDivisionError("zero has no multiplicative inverse")
    return pow(value, -1, prime)

def evaluate_polynomial(coefficients: Sequence[int], x_value: int, prime: int = PRIME) -> int:
    result = 0
    for coefficient in reversed(coefficients):
        result = (result * x_value + coefficient) % prime
    return result

def trim_polynomial(coefficients: Sequence[int]) -> list[int]:
    trimmed = list(coefficients)
    while len(trimmed) > 1 and trimmed[-1] == 0:
        trimmed.pop()
    return trimmed or [0]

def polynomial_add(left: Sequence[int], right: Sequence[int], prime: int = PRIME) -> list[int]:
    length = max(len(left), len(right))
    result = []
    for index in range(length):
        left_value = left[index] if index < len(left) else 0
        right_value = right[index] if index < len(right) else 0
        result.append((left_value + right_value) % prime)
    return trim_polynomial(result)

def polynomial_subtract(left: Sequence[int], right: Sequence[int], prime: int = PRIME) -> list[int]:
    length = max(len(left), len(right))
    result = []
    for index in range(length):
        left_value = left[index] if index < len(left) else 0
        right_value = right[index] if index < len(right) else 0
        result.append((left_value - right_value) % prime)
    return trim_polynomial(result)
def polynomial_scale(coefficients: Sequence[int], scalar: int, prime: int = PRIME) -> list[int]: return trim_polynomial([(scalar * coefficient) % prime for coefficient in coefficients])

def polynomial_multiply(left: Sequence[int], right: Sequence[int], prime: int = PRIME) -> list[int]:
    result = [0] * (len(left) + len(right) - 1)
    for left_index, left_value in enumerate(left):
        for right_index, right_value in enumerate(right):
            result[left_index + right_index] = (
                result[left_index + right_index] + left_value * right_value
            ) % prime
    return trim_polynomial(result)

def polynomial_divmod(
    dividend: Sequence[int],
    divisor: Sequence[int],
    prime: int = PRIME,
) -> tuple[list[int], list[int]]:
    divisor = trim_polynomial(divisor)
    if divisor == [0]:
        raise ZeroDivisionError("polynomial division by zero")

    remainder = trim_polynomial(dividend)
    quotient = [0] * max(1, len(remainder) - len(divisor) + 1)
    divisor_lead_inverse = mod_inverse(divisor[-1], prime)

    while len(remainder) >= len(divisor) and remainder != [0]:
        degree_gap = len(remainder) - len(divisor)
        lead_factor = (remainder[-1] * divisor_lead_inverse) % prime
        quotient[degree_gap] = lead_factor

        subtraction = [0] * degree_gap + polynomial_scale(divisor, lead_factor, prime)
        remainder = polynomial_subtract(remainder, subtraction, prime)

    return trim_polynomial(quotient), trim_polynomial(remainder)

def field_byte_length(prime: int = PRIME) -> int: return (prime.bit_length() + 7) // 8
def powers(base: int, count: int, prime: int = PRIME) -> Iterable[int]:
    value = 1
    for _ in range(count):
        yield value
        value = (value * base) % prime