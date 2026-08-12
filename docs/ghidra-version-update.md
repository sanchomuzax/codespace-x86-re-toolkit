# Updating the pinned Ghidra release

The toolkit treats the Ghidra archive name, URL, and SHA-256 digest as one
reviewed supply-chain pin. Update them together; never copy a checksum from an
issue, pull request, mirror, or search result.

## 1. Review the official release

Open the release in the official
[`NationalSecurityAgency/ghidra`](https://github.com/NationalSecurityAgency/ghidra/releases)
repository. Read its security notes, supported Java version, upgrade notes, and
headless-analysis changes before updating.

The prebuilt archive must be the `ghidra_<version>_PUBLIC_<date>.zip` release
asset, not GitHub's automatically generated source archive.

## 2. Cross-check release metadata

Set the candidate tag, then inspect GitHub's authenticated API response:

```bash
TAG=Ghidra_12.1.2_build
gh api "repos/NationalSecurityAgency/ghidra/releases/tags/$TAG" \
  --jq '{body, assets: [.assets[] | {name, digest, browser_download_url}]}'
```

Confirm that all of these identify the same archive and SHA-256 value:

1. the checksum printed in the official release body;
2. the matching asset's `digest` field;
3. a local digest calculated from the downloaded asset.

Download into a disposable directory and calculate the third value:

```bash
CHECK_DIR=$(mktemp -d)
ASSET=ghidra_12.1.2_PUBLIC_20260605.zip
URL="https://github.com/NationalSecurityAgency/ghidra/releases/download/$TAG/$ASSET"
curl --fail --location "$URL" --output "$CHECK_DIR/$ASSET"
sha256sum "$CHECK_DIR/$ASSET"
```

Remove the disposable directory after recording the verified values. If any of
the three sources disagree, stop the update and investigate upstream.

## 3. Update the pin atomically

Change `GHIDRA_VERSION`, `GHIDRA_ZIP`, and `GHIDRA_SHA256` together in:

```text
skills/codespace-x86-re/scripts/codespace_re.py
```

`GHIDRA_URL` and `GHIDRA_DIR` are derived from those constants. Update the
pinned version mentioned in `README.md` as well.

## 4. Validate before release

Run the local suite:

```bash
python3 -m unittest discover -s tests -v
python3 scripts/validate_skill.py
python3 -m py_compile \
  skills/codespace-x86-re/scripts/codespace_re.py \
  scripts/install_skill.py scripts/validate_skill.py
```

Then open a pull request and require the Python matrix and official Agent
Skills validation to pass. Finally, manually dispatch the cost-bounded
`Codespace integration smoke` workflow. It verifies download, installation,
x86 upload, analysis, isolated Java GhidraScript execution, evidence download,
and cleanup against the new release.

Do not publish a version tag until both CI and that integration smoke pass.
