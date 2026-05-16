import argparse
import csv
import random
import statistics
import time

from dataclasses import asdict, dataclass
from pathlib import Path

from cryptography.exceptions import InvalidTag

from .aes_utils import (
    decrypt_aes_gcm,
    encrypt_aes_gcm,
    generate_aes256_key,
    int_to_key_bytes,
    key_bytes_to_int,
)
from .field import PRIME
from .robust_rs import DecodingFailure, recover_secret_rs
from .shamir import corrupt_shares, pick_available_shares, serialized_share_size_bytes, split_secret


@dataclass(frozen=True)
class Scenario:
    name: str
    threshold: int
    share_count: int
    available_count: int
    corrupted_count: int
    expected_result: str


@dataclass(frozen=True)
class TrialResult:
    scenario: str
    trial: int
    threshold: int
    share_count: int
    available_count: int
    corrupted_count: int
    expected_result: str
    recovery_succeeded: bool
    key_matches: bool
    decryption_succeeded: bool
    failure_reason: str
    share_generation_ms: float
    recovery_ms: float
    corrected_error_count: int
    storage_overhead_ratio: float

SCENARIOS: tuple[Scenario, ...] = (
    Scenario("Normal recovery", 3, 5, 5, 0, "Success"),
    Scenario("Minimum valid recovery", 3, 5, 3, 0, "Success"),
    Scenario("Insufficient shares", 3, 5, 2, 0, "Failure"),
    Scenario("One corrupted share, enough redundancy", 3, 5, 5, 1, "Success"),
    Scenario("One corrupted share, not enough redundancy", 3, 5, 4, 1, "Failure"),
    Scenario("Larger normal recovery", 4, 7, 7, 0, "Success"),
    Scenario("Larger minimum recovery", 4, 7, 4, 0, "Success"),
    Scenario("Larger insufficient shares", 4, 7, 3, 0, "Failure"),
    Scenario("Correct one corrupted share", 4, 7, 6, 1, "Success"),
    Scenario("Correct two corrupted shares", 4, 8, 8, 2, "Success"),
    Scenario("Large threshold normal", 5, 10, 10, 0, "Success"),
    Scenario("Large threshold minimum", 5, 10, 5, 0, "Success"),
    Scenario("Large threshold insufficient", 5, 10, 4, 0, "Failure"),
    Scenario("Large threshold, one corrupted", 5, 10, 7, 1, "Success"),
    Scenario("Large threshold, two corrupted", 5, 10, 9, 2, "Success"),
)

def run_trial(scenario: Scenario, trial_index: int, rng: random.Random) -> TrialResult:
    plaintext = (
        f"Robust key recovery benchmark::{scenario.name}::trial::{trial_index}".encode("utf-8")
    )
    key = generate_aes256_key()
    package = encrypt_aes_gcm(plaintext, key)
    secret = key_bytes_to_int(key)

    start = time.perf_counter()
    shares = split_secret(secret, scenario.threshold, scenario.share_count, prime=PRIME, rng=rng)
    share_generation_ms = (time.perf_counter() - start) * 1000.0

    available = pick_available_shares(shares, scenario.available_count, rng)
    available, _ = corrupt_shares(
        available,
        scenario.corrupted_count,
        prime=PRIME,
        rng=rng if scenario.corrupted_count else None,
    )

    storage_ratio = (
        scenario.share_count * serialized_share_size_bytes(PRIME) / len(key)
    )

    start = time.perf_counter()
    try:
        recovered_secret = recover_secret_rs(available, scenario.threshold, prime=PRIME)
        recovery_ms = (time.perf_counter() - start) * 1000.0
        recovered_key = int_to_key_bytes(recovered_secret)
        recovered_plaintext = decrypt_aes_gcm(package, recovered_key)

        key_matches = recovered_key == key
        decryption_succeeded = recovered_plaintext == plaintext
        recovery_succeeded = key_matches and decryption_succeeded
        failure_reason = ""
        corrected_error_count = scenario.corrupted_count if recovery_succeeded else 0
    except (DecodingFailure, ValueError) as error:
        recovery_ms = (time.perf_counter() - start) * 1000.0
        recovery_succeeded = False
        key_matches = False
        decryption_succeeded = False
        failure_reason = type(error).__name__
        corrected_error_count = 0
    except InvalidTag:
        recovery_ms = (time.perf_counter() - start) * 1000.0
        recovery_succeeded = False
        key_matches = False
        decryption_succeeded = False
        failure_reason = "InvalidTag"
        corrected_error_count = 0

    return TrialResult(
        scenario=scenario.name,
        trial=trial_index,
        threshold=scenario.threshold,
        share_count=scenario.share_count,
        available_count=scenario.available_count,
        corrupted_count=scenario.corrupted_count,
        expected_result=scenario.expected_result,
        recovery_succeeded=recovery_succeeded,
        key_matches=key_matches,
        decryption_succeeded=decryption_succeeded,
        failure_reason=failure_reason,
        share_generation_ms=share_generation_ms,
        recovery_ms=recovery_ms,
        corrected_error_count=corrected_error_count,
        storage_overhead_ratio=storage_ratio,
    )

def run_experiments(trials_per_scenario: int = 25, seed: int = 20260516) -> list[TrialResult]:
    rng = random.Random(seed)
    results: list[TrialResult] = []
    for scenario in SCENARIOS:
        for trial_index in range(1, trials_per_scenario + 1):
            results.append(run_trial(scenario, trial_index, rng))
    return results

def summarise_results(results: list[TrialResult]) -> list[dict[str, object]]:
    grouped: dict[str, list[TrialResult]] = {}
    for result in results:
        grouped.setdefault(result.scenario, []).append(result)

    summary_rows: list[dict[str, object]] = []
    for scenario in SCENARIOS:
        scenario_results = grouped[scenario.name]
        success_rate = 100.0 * sum(result.recovery_succeeded for result in scenario_results) / len(
            scenario_results
        )
        key_match_rate = 100.0 * sum(result.key_matches for result in scenario_results) / len(
            scenario_results
        )
        decrypt_rate = 100.0 * sum(
            result.decryption_succeeded for result in scenario_results
        ) / len(scenario_results)
        summary_rows.append(
            {
                "scenario": scenario.name,
                "t": scenario.threshold,
                "n": scenario.share_count,
                "m": scenario.available_count,
                "e": scenario.corrupted_count,
                "expected": scenario.expected_result,
                "success_rate_pct": round(success_rate, 2),
                "key_match_rate_pct": round(key_match_rate, 2),
                "decrypt_rate_pct": round(decrypt_rate, 2),
                "mean_share_generation_ms": round(
                    statistics.mean(result.share_generation_ms for result in scenario_results), 4
                ),
                "mean_recovery_ms": round(
                    statistics.mean(result.recovery_ms for result in scenario_results), 4
                ),
                "mean_storage_overhead_ratio": round(
                    statistics.mean(result.storage_overhead_ratio for result in scenario_results), 2
                ),
            }
        )
    return summary_rows

def write_csv(path: Path, rows: list[dict[str, object]]) -> None:
    if not rows:
        raise ValueError("rows must not be empty")
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)

def main() -> None:
    parser = argparse.ArgumentParser(description="Run robust key recovery experiments.")
    parser.add_argument("--trials", type=int, default=25, help="Trials per scenario.")
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path("paper") / "data",
        help="Directory for CSV outputs.",
    )
    parser.add_argument("--seed", type=int, default=20260516, help="Deterministic RNG seed.")
    args = parser.parse_args()

    results = run_experiments(trials_per_scenario=args.trials, seed=args.seed)
    detail_rows = [asdict(result) for result in results]
    summary_rows = summarise_results(results)

    write_csv(args.output_dir / "experiment_results_detailed.csv", detail_rows)
    write_csv(args.output_dir / "experiment_results_summary.csv", summary_rows)

    successful_trials = sum(result.recovery_succeeded for result in results)
    print(
        f"Completed {len(results)} trials across {len(SCENARIOS)} scenarios; "
        f"{successful_trials} trials ended in successful recovery."
    )
    print(f"CSV outputs written to {args.output_dir}")

if __name__ == "__main__":
    main()