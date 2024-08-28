# Get Started

This guide presents a quick primer to using gittuf. Note that gittuf is
currently in alpha, and it is not intended for use in a production repository.

## Install gittuf

> [!NOTE]
> Please use release v0.1.0 or higher, as prior releases were created to
> test the release workflow.

**Pre-built binaries.** This repository provides pre-built binaries that are
signed and published using [GoReleaser]. The signature for these binaries are
generated using [Sigstore], using the release workflow's identity. Make sure you
have [cosign] installed on your system, then you will be able to securely
download and verify the gittuf release:

> [!NOTE]
> For `windows`, the `.exe` extension needs to be included for the binary 
> (as `filename.exe`), signature (as `filename.exe.sig`) and certificate 
> (as `filename.exe.pem`) files.

### Unix-based operating systems

```sh
# Modify these values as necessary.
# One of: amd64, arm64
ARCH=amd64
# One of: linux, darwin, freebsd
OS=linux
# See https://github.com/gittuf/gittuf/releases for the latest version
VERSION=0.5.2
cd $(mktemp -d)

curl -LO https://github.com/gittuf/gittuf/releases/download/v${VERSION}/gittuf_${VERSION}_${OS}_${ARCH}
curl -LO https://github.com/gittuf/gittuf/releases/download/v${VERSION}/gittuf_${VERSION}_${OS}_${ARCH}.sig
curl -LO https://github.com/gittuf/gittuf/releases/download/v${VERSION}/gittuf_${VERSION}_${OS}_${ARCH}.pem

cosign verify-blob \
    --certificate gittuf_${VERSION}_${OS}_${ARCH}.pem \
    --signature gittuf_${VERSION}_${OS}_${ARCH}.sig \
    --certificate-identity https://github.com/gittuf/gittuf/.github/workflows/release.yml@refs/tags/v${VERSION} \
    --certificate-oidc-issuer https://token.actions.githubusercontent.com \
    gittuf_${VERSION}_${OS}_${ARCH}
   
sudo install gittuf_${VERSION}_${OS}_${ARCH} /usr/local/bin/gittuf
cd -
gittuf version
```

### Windows

Run this script as a `.ps1` file (PowerShell script).

```powershell
# Modify these values as necessary.
# One of: amd64, arm64
ARCH="amd64"
OS="windows"
# See https://github.com/gittuf/gittuf/releases for the latest version
VERSION="0.5.2"

curl "https://github.com/gittuf/gittuf/releases/download/v$VERSION/gittuf_${VERSION}_${OS}_${ARCH}.exe" -O "gittuf_${VERSION}_${OS}_${ARCH}.exe"
curl "https://github.com/gittuf/gittuf/releases/download/v$VERSION/gittuf_${VERSION}_${OS}_${ARCH}.exe.sig" -O "gittuf_${VERSION}_${OS}_${ARCH}.exe.sig"
curl "https://github.com/gittuf/gittuf/releases/download/v$VERSION/gittuf_${VERSION}_${OS}_${ARCH}.exe.pem" -O "gittuf_${VERSION}_${OS}_${ARCH}.exe.pem"

cosign verify-blob --certificate gittuf_${VERSION}_${OS}_${ARCH}.exe.pem --signature gittuf_${VERSION}_${OS}_${ARCH}.exe.sig --certificate-identity https://github.com/gittuf/gittuf/.github/workflows/release.yml@refs/tags/v${VERSION} --certificate-oidc-issuer https://token.actions.githubusercontent.com gittuf_${VERSION}_${OS}_${ARCH}.exe
```

The gittuf binary is now verified on your system. You can run it from the terminal
as `gittuf.exe`. If Go is installed on your system (see our [Go for Windows 
document] for details), you can further run the following commands to add gittuf to `PATH` and
let it be accessible from across the system as a recognized command:

```powershell
cp .\gittuf_${VERSION}_windows_${ARCH}.exe $env:GOPATH\bin\gittuf.exe
gittuf version
```

> [!NOTE]
> This Windows installation guideline assumes that Go has been properly installed
> on the system (including setting proper environment variables). To install Go
> properly on Windows, please refer to our [Go for Windows document]. 

### Building from source

> [!NOTE] 
> `make` needs to be installed manually on Windows as it is not packaged with 
> the OS. The easiest way to install `make` on Windows is to use the 
> `ezwinports.make` package: Simply type `winget install ezwinports.make` 
> in PowerShell.
> You can also install it from the [GNU website] or the [chocolatey] package manager.

#### Unix-based operating systems

To build from source, clone the repository and run
`make`. This will also run the test suite prior to installing gittuf. Note that
git clone https://github.com/gittuf/gittuf
Go 1.22 or higher is necessary to build gittuf.

```sh
git clone https://github.com/gittuf/gittuf
cd gittuf
make
```

#### Windows

The best way to build from source is to clone the repository and run 
`go install`. This command will run only if Go has been properly installed on 
your system (see the [Go for Windows document] for more information)

```powershell
git clone https://github.com/gittuf/gittuf
cd gittuf
go install
```

This will automatically put `gittuf.exe` in your `GOPATH` as configured.

## Create keys

First, create some keys that are used for the gittuf root of trust, policies, as
well as for commits created while following this guide.

> [!NOTE]
> If running on Windows, do not use the `-N ""` flag in the `ssh-keygen` commands.
> Instead, enter an empty passphrase when prompted.

```bash
mkdir gittuf-get-started && cd gittuf-get-started
mkdir keys && cd keys
ssh-keygen -q -t ecdsa -N "" -f root
ssh-keygen -q -t ecdsa -N "" -f policy
ssh-keygen -q -t ecdsa -N "" -f developer
```

## Create a Git repository

gittuf can be used with either a brand new repository or with an existing
repository. Here, we assume gittuf is being deployed with a fresh repository.
Initialize the repository and gittuf's root of trust metadata using the
key.

```bash
cd .. && mkdir repo && cd repo
git init -q -b main
git config --local gpg.format ssh
git config --local user.signingkey ../keys/developer
```

## Initialize gittuf

Initialize gittuf's root of trust metadata.

```bash
gittuf trust init -k ../keys/root
```

After that, add a key for the primary policy. gittuf allows users to specify
rules in one or more policy files. The primary policy file (called `targets`,
from TUF) must be signed by keys specified in the root of trust.

```bash
gittuf trust add-policy-key -k ../keys/root --policy-key ../keys/policy.pub
gittuf policy init -k ../keys/policy --policy-name targets
```
Then, use the policy key to initialize a policy and add a rule protecting the
`main` branch.

```bash
gittuf policy add-rule -k ../keys/policy --rule-name protect-main --rule-pattern git:refs/heads/main --authorize-key ../keys/developer.pub
```

Note that `--authorize-key` can also be used to specify a GPG key or a
[Sigstore] identity for use with [gitsign]. However, we're using SSH keys
throughout in this guide, as gittuf policy metadata currently cannot be signed
using GPG and Sigstore (see [#229]).

After adding the required policies, _apply_ them from the policy-staging area.
This means the policy will be applicable henceforth.

```bash
gittuf policy apply
```

## Making repository changes

You can make changes in the repository using standard Git workflows. However,
changes to Git references (i.e., branches and tags) must be recorded in gittuf's
reference state log (RSL). Currently, this must be executed manually or using a
pre-push hook (see `gittuf add-hook -h` for more information about adding the
hook and [#220] for planned gittuf and Git command compatibility).

```bash
echo "Hello, world!" > README.md
git add . && git commit -q -S -m "Initial commit"
gittuf rsl record main
```

## Verifying policy

gittuf allows for verifying rules for Git references and files.

```sh
gittuf verify-ref --verbose main
```

## Communicating with a remote

gittuf includes helpers to push and fetch the policy and RSL references.
However, there are some known issues (see [#328]) with these commands. In the
meantime, Git can be used to keep gittuf's references updated.

```sh
git push <remote> refs/gittuf/*
git fetch <remote> refs/gittuf/*:refs/gittuf/*
```

## Verify gittuf itself

You can also verify the state of the gittuf source code repository with gittuf
itself. For more information on verifying gittuf with gittuf, visit the
[dogfooding] document.

## Conclusion

This is a very quick primer to gittuf! Please take a look at gittuf's [CLI docs]
to learn more about using gittuf. If you find a bug, please [open an issue] on
the gittuf repository.

[Sigstore]: https://www.sigstore.dev/
[cosign]: https://github.com/sigstore/cosign
[gitsign]: https://github.com/sigstore/gitsign
[GoReleaser]: https://goreleaser.com/
[#276]: https://github.com/gittuf/gittuf/issues/276
[#229]: https://github.com/gittuf/gittuf/issues/229
[#220]: https://github.com/gittuf/gittuf/issues/220
[#328]: https://github.com/gittuf/gittuf/issues/328
[CLI docs]: /docs/cli/gittuf.md
[open an issue]: https://github.com/gittuf/gittuf/issues/new/choose
[dogfooding]: /docs/dogfood.md
[GNU website]: https://gnuwin32.sourceforge.net/packages/make.htm
[chocolatey]: https://community.chocolatey.org/packages/make
[Go for Windows document]: windows/goconfig_win.md
