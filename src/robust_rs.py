from dataclasses import dataclass
from typing import Sequence

from .field import (
    PRIME,
    evaluate_polynomial,
    mod_inverse,
    polynomial_divmod,
    trim_polynomial,
)
from .shamir import Share


class DecodingFailure(RuntimeError):
    """Raised when robust decoding cannot recover a consistent polynomial."""


@dataclass(frozen=True)
class DecodingResult:
    polynomial: list[int]
    corrected_error_count: int
    mismatched_share_indices: list[int]


def solve_linear_system_mod(
    matrix: Sequence[Sequence[int]],
    vector: Sequence[int],
    prime: int = PRIME,
) -> list[int]:
    if not matrix:
        raise ValueError("matrix must not be empty")
    row_count = len(matrix)
    column_count = len(matrix[0])

    augmented = [
        [entry % prime for entry in row] + [vector[row_index] % prime]
        for row_index, row in enumerate(matrix)
    ]

    pivot_columns: list[int] = []
    pivot_row = 0
    for column in range(column_count):
        pivot = None
        for row_index in range(pivot_row, row_count):
            if augmented[row_index][column] % prime != 0:
                pivot = row_index
                break
        if pivot is None:
            continue

        augmented[pivot_row], augmented[pivot] = augmented[pivot], augmented[pivot_row]
        inverse = mod_inverse(augmented[pivot_row][column], prime)
        augmented[pivot_row] = [(value * inverse) % prime for value in augmented[pivot_row]]

        for row_index in range(row_count):
            if row_index == pivot_row:
                continue
            factor = augmented[row_index][column] % prime
            if factor == 0:
                continue
            augmented[row_index] = [
                (current - factor * pivot_value) % prime
                for current, pivot_value in zip(augmented[row_index], augmented[pivot_row])
            ]

        pivot_columns.append(column)
        pivot_row += 1
        if pivot_row == row_count:
            break

    for row in augmented:
        if all(value % prime == 0 for value in row[:-1]) and row[-1] % prime != 0:
            raise DecodingFailure("linear system is inconsistent")

    if len(pivot_columns) < column_count:
        raise DecodingFailure("linear system is underdetermined")

    solution = [0] * column_count
    for row_index, column in enumerate(pivot_columns):
        solution[column] = augmented[row_index][-1] % prime
    return solution

def berlekamp_welch_decode(
    shares: Sequence[Share],
    threshold: int,
    max_errors: int | None = None,
    prime: int = PRIME,
) -> DecodingResult:
    if len(shares) < threshold:
        raise DecodingFailure("not enough shares to decode")

    normalized_shares = sorted(shares, key=lambda item: item[0])
    x_values = [share[0] for share in normalized_shares]
    if len(set(x_values)) != len(x_values):
        raise DecodingFailure("share x-coordinates must be unique")

    feasible_errors = (len(normalized_shares) - threshold) // 2
    if max_errors is None:
        max_errors = feasible_errors
    else:
        max_errors = min(max_errors, feasible_errors)

    for error_count in range(max_errors, -1, -1):
        try:
            result = _solve_for_error_count(normalized_shares, threshold, error_count, prime)
            return result
        except DecodingFailure:
            continue

    raise DecodingFailure("no valid Berlekamp-Welch solution found")

def _solve_for_error_count(
    shares: Sequence[Share],
    threshold: int,
    error_count: int,
    prime: int,
) -> DecodingResult:
    q_degree = threshold + error_count - 1
    unknown_count = (q_degree + 1) + error_count
    equation_matrix: list[list[int]] = []
    equation_vector: list[int] = []

    for x_value, y_value in shares:
        x_powers = [1]
        for _ in range(1, q_degree + 1):
            x_powers.append((x_powers[-1] * x_value) % prime)

        row = list(x_powers)
        for degree in range(error_count):
            row.append((-y_value * x_powers[degree]) % prime)

        equation_matrix.append(row)
        equation_vector.append((y_value * x_powers[error_count]) % prime)

    if len(equation_matrix) < unknown_count:
        raise DecodingFailure("insufficient equations for requested error count")

    solution = solve_linear_system_mod(equation_matrix, equation_vector, prime)
    q_coefficients = solution[: q_degree + 1]
    e_coefficients = solution[q_degree + 1 :] + [1]

    quotient, remainder = polynomial_divmod(q_coefficients, e_coefficients, prime)
    quotient = trim_polynomial(quotient)
    remainder = trim_polynomial(remainder)

    if remainder != [0]:
        raise DecodingFailure("decoded quotient has a non-zero remainder")
    if len(quotient) > threshold:
        raise DecodingFailure("decoded polynomial exceeds threshold degree")

    mismatches = [
        index
        for index, (x_value, y_value) in enumerate(shares)
        if evaluate_polynomial(quotient, x_value, prime) != y_value % prime
    ]
    if len(mismatches) > error_count:
        raise DecodingFailure("too many mismatches for requested error budget")

    return DecodingResult(
        polynomial=quotient,
        corrected_error_count=error_count,
        mismatched_share_indices=mismatches,
    )

def recover_secret_rs(
    shares: Sequence[Share],
    threshold: int,
    max_errors: int | None = None,
    prime: int = PRIME,
) -> int:
    result = berlekamp_welch_decode(shares, threshold, max_errors=max_errors, prime=prime)
    return result.polynomial[0] % prime