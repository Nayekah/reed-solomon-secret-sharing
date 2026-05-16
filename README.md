# Reed-Solomon Secret Sharing

Implementation for the paper:

**A Fault-Tolerant Cryptographic Key Recovery Framework Using Reed-Solomon-Decoded Threshold Secret Sharing**

## Requirements

- Python 3.11 or newer is recommended

Python dependency:

```text
cryptography>=43.0.0
```

## Setup

From the repository root:

```powershell
py -3 -m pip install -r src/requirements.txt
```

## Running the Experiments

Run the experiment suite:

```powershell
py -3 -m src.experiments
```

Useful options:

```powershell
py -3 -m src.experiments --trials 25 --seed 20260516 --output-dir paper/data
```

Outputs:
- `paper/data/experiment_results_detailed.csv`
- `paper/data/experiment_results_summary.csv`

## Citation

If you use this repository, please cite the accompanying paper.

Suggested BibTeX entry:

```bibtex
@misc{subrata2026reedsolomonsecretsharing,
  author       = {Nayaka Ghana Subrata},
  title        = {A Fault-Tolerant Cryptographic Key Recovery Framework Using Reed-Solomon-Decoded Threshold Secret Sharing},
  year         = {2026},
  howpublished = {\url{https://github.com/Nayekah/reed-solomon-secret-sharing}},
  note         = {Cryptography paper, Institut Teknologi Bandung}
}
```

## Contact

If you have any questions related to this implementation, please contact:

- Nayaka Ghana Subrata — `13523090@std.stei.itb.ac.id`
- Nayaka Ghana Subrata — `nayakaghana39@gmail.com`

## Notes

- The key-recovery prototype is intended for study and experimentation.
- The recovery success condition in the robust setting follows the redundancy bound used by the implementation.
