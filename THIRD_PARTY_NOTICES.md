# Third-party material

zscan has no licence of its own yet (the choice is the owner's). The following material from other
projects is used under its own licence.

## EMBER2024 feature extractor (Apache License 2.0)

`zscan/ml/features.py` is derived from `src/thrember/features.py` of
[EMBER2024](https://github.com/FutureComputing4AI/EMBER2024) by Robert J. Joyce, Gideon Miller,
Phil Roth, Richard Zak, Elliott Zaresky-Williams, Hyrum Anderson, Edward Raff and James Holt,
licensed under the Apache License, Version 2.0 (text in `LICENSES/Apache-2.0.txt`).

What was taken: the list of 77 text patterns and their order, the layout and normalisation of the
four feature groups used for ELF, PDF and APK files, and the byte-entropy histogram arithmetic.
What was changed: the code was rewritten for zscan (no scikit-learn, pefile or signify
dependency, since only the groups that need nothing but the file's bytes are used), and the
text patterns are applied once over all of a file's strings instead of once per string, which is
about four times faster and gives identical results (checked on real files, see the README).

## EMBER2024 models and data (Apache License 2.0)

zscan does not contain or redistribute these. `zscan --update-ml` downloads the LightGBM models
from <https://huggingface.co/joyce8/EMBER2024-benchmark-models>, and `python -m zscan.ml.evaluate fetch`
downloads test data from <https://huggingface.co/datasets/joyce8/EMBER2024>. Both are published
under the Apache License 2.0. If you use them in research, cite:

> Robert J. Joyce, Gideon Miller, Phil Roth, Richard Zak, Elliott Zaresky-Williams, Hyrum Anderson,
> Edward Raff, James Holt. *EMBER2024 - A Benchmark Dataset for Holistic Evaluation of Malware
> Classifiers.* KDD 2025. <https://arxiv.org/abs/2506.05074>

The dataset holds feature values and labels only, no executable files. zscan never downloads or
stores malware samples.

## YARA-Forge rules

Downloaded by `zscan --update`, not stored in this repository; each rule keeps its author's licence.
