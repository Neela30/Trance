## Which file do I download?

| Your computer | Download |
|---|---|
| Windows 10 or 11 | `TRANCE-…-windows-x64.zip` |
| Linux, 64-bit (Ubuntu 22.04 or newer, or similar) | `TRANCE-…-linux-x64.tar.gz` |
| macOS | Not packaged yet; run TRANCE from source (see the README). |

You do **not** need to download anything separately for the suspect machine: open TRANCE, go to
the **Build tool** tab and click **Save trance-acquire.exe** to put the acquisition tool (and,
if you pick one, WinPMEM) on your tools drive. `trance-acquire.exe` is also attached below for
anyone who wants it on its own.

## Getting started

1. Unzip the download anywhere. No installer and no administrator rights are needed.
2. Run `TRANCE\TRANCE.exe` (Windows) or `TRANCE/TRANCE` (Linux).
3. Windows shows "Windows protected your PC" because the app is not code-signed: click
   **More info**, then **Run anyway**.

Cases are saved in `TRANCE/cases` in your home folder.

## Check the download

Compare the file's SHA-256 with the line for it in `SHA256SUMS`:

- Linux: `sha256sum -c SHA256SUMS --ignore-missing`
- Windows (PowerShell): `Get-FileHash .\TRANCE-…-windows-x64.zip`

More detail (Linux libraries, Volatility symbols, antivirus notes):
[Install (release download)](https://github.com/Neela30/Trance#install-release-download).
