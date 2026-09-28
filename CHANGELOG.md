# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Added

- Unicode normalisation before detection (per-character NFKC, stripping of
  format / Cf and non-spacing mark / Mn characters), with an offset table so
  findings and masking stay on the original text.

### Changed

- Masking strategies now receive the normalised value. **`hash` tokens and
  `partial` output for values written with fullwidth digits change** (those
  values were already detected via Unicode `\d`). Nothing changes for an
  ASCII value.
