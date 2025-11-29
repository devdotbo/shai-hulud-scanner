Short version first:

* To check if you might be hit:

  * Cross check your `pnpm-lock.yaml` against the public lists of compromised packages from Tenable, Wiz, and Datadog.
  * Search your projects and home folder for Shai Hulud specific files and GitHub repos (for example repos with description `Sha1-Hulud: The Second Coming.`). ([Tenable®][1])
* To reduce the chance of infection going forward on macOS:

  * Stay on pnpm v10+, **do not** enable `dangerouslyAllowAllBuilds`, and only use `pnpm approve-builds` for a small allowlist of trusted packages.
  * Add pnpm’s `minimumReleaseAge` and `trustPolicy` settings so you do not install freshly published versions automatically. ([pnpm.io][2])
  * Run risky installs and scripts in a sandbox: either a macOS sandbox wrapper (macos-dev-sandbox or node-safe) or a lightweight container (Docker, Colima, or Apple’s `container` CLI). ([GitHub][3])

Below is a more concrete, step by step playbook for you.

---

## 1. What Sha1 Hulud 2.0 actually does (in dev terms)

The new Shai Hulud 2.0 worm works roughly like this:

1. Attackers compromise maintainer accounts and publish trojanized versions of legitimate npm packages (no typosquatting, same names). ([wiz.io][4])
2. Those versions add a `preinstall` script to `package.json` that runs `setup_bun.js`, which downloads Bun and then runs `bun_environment.js`. ([Datadog Security Labs][5])
3. During install, the payload:

   * Steals tokens and secrets from your machine and CI (npm tokens, GitHub tokens, cloud creds, .env files).
   * Creates a public GitHub repo with description `Sha1-Hulud: The Second Coming.` and uploads stolen data as files like `contents.json`, `environment.json`, `cloud.json`, `truffleSecrets.json`. ([Datadog Security Labs][5])
   * If it finds npm credentials, it backdoors packages that you maintain by adding the same preinstall + payload files and republishing them. ([Datadog Security Labs][5])
   * If it cannot get any valid GitHub or npm credentials, it has a fallback that tries to shred all writable files in your home directory. ([Datadog Security Labs][5])

So there are two big goals for you:

1. Detect if this stuff ever ran on your Mac.
2. Make it hard for any future npm malware to touch your real home directory and secrets.

---

## 2. How to check if you are affected

### 2.1 Check your dependencies against the known bad lists

There are public lists of compromised packages and versions:

* Tenable list of affected npm packages (JSON and Markdown) ([Tenable®][1])
* Wiz CSV and IoC repo ([wiz.io][4])
* Datadog IoC repo for Shai Hulud 2.0 ([Datadog Security Labs][5])

Minimal CLI way to check against Tenable’s list:

```bash
# 1) Fetch list of bad packages
curl -sSL \
  https://raw.githubusercontent.com/tenable/shai-hulud-second-coming-affected-packages/main/list.json \
  -o /tmp/shai-hulud-list.json

# 2) Extract just the package names (requires jq; `brew install jq` if needed)
jq -r '.[].name' /tmp/shai-hulud-list.json > /tmp/shai-hulud-packages.txt

# 3) Search your pnpm lockfile(s)
rg -n -f /tmp/shai-hulud-packages.txt pnpm-lock.yaml
```

If `rg` is not installed, you can use plain `grep`:

```bash
while read -r name; do
  grep -n "$name" pnpm-lock.yaml || true
done < /tmp/shai-hulud-packages.txt
```

If you see lines matching both a bad package *and* one of the compromised versions listed in Tenable or Wiz/Datadog lists, you should assume that install was at risk and continue with the rest of the checks and some credential rotation.

If you never had any of the compromised versions in your lockfile, risk is lower but I would still do a quick IoC scan (below) because the lists are not guaranteed complete.

---

### 2.2 Search for Shai Hulud artifact files on your Mac

Shai Hulud 2.0 consistently uses some specific file names both for payload and for exfiltrated data: `setup_bun.js`, `bun_environment.js`, `cloud.json`, `contents.json`, `environment.json`, `truffleSecrets.json`, and a workflow file often named `.github/workflows/discussion.yaml`. ([wiz.io][4])

From your home directory:

```bash
cd ~

# Payload code
find . \
  \( -name 'setup_bun.js' -o -name 'bun_environment.js' \) \
  -type f 2>/dev/null

# Exfiltrated secrets (can have false positives, especially environment.json)
find . \
  \( -name 'cloud.json' -o -name 'contents.json' -o -name 'truffleSecrets.json' \) \
  -type f 2>/dev/null

# Suspicious GitHub Actions workflow
find . -path '*\.github/workflows/discussion.yaml' -type f 2>/dev/null
```

Important notes:

* If those file names appear only inside `node_modules` of a project that you know depends on a compromised version, treat that project as suspect even if the rest of the machine looks OK.
* If you see them under random directories you never created, that is a strong indicator that something executed.

---

### 2.3 Check your GitHub account

The worm creates public repos with description literally set to:

> `Sha1-Hulud: The Second Coming.` ([Datadog Security Labs][5])

Check:

1. On GitHub, search under **your own account** for that description or for `"Shai-Hulud"` generally.
2. Look for any repos you do not recognize and inspect them for those JSON files mentioned above.

If such a repo exists under your account, you almost certainly had secrets exfiltrated and should rotate anything that could realistically be in your dev environment (GitHub PATs, SSH keys, cloud keys, npm tokens).

Note: the worm can also exfiltrate your data into a repo owned by some other random victim, so the absence of repos under your account is not a clean bill of health, but their presence is a very loud red flag. ([Datadog Security Labs][5])

---

### 2.4 If you publish npm packages

If you maintain npm packages:

1. Look at versions published between 2025-11-21 and 2025-11-24 (UTC) and check their `package.json` on npm or in your git tags.
2. If you see an unexpected `preinstall` running `node setup_bun.js` and extra files `setup_bun.js` and `bun_environment.js`, that package was backdoored and republished through your account. ([Datadog Security Labs][5])

If anything smells off, you should:

* Revoke your npm tokens.
* Force release clean versions.
* Put a loud security notice in the README.

---

## 3. Hardening your pnpm setup

You already made a good choice by using pnpm. Version 10 and later are explicitly designed to mitigate npm supply chain attacks by blocking dependency lifecycle scripts and giving you tools to slow down dependency updates. ([pnpm.io][2])

Assuming you are on pnpm 10+:

### 3.1 Keep lifecycle scripts locked down

Key pnpm settings and commands:

1. **Leave the default script blocking in place**

   * pnpm v10 blocks lifecycle scripts in *dependencies* by default, and asks you to approve them via `pnpm approve-builds` or allowlists like `onlyBuiltDependencies`. ([GitHub][6])
   * Do **not** set `dangerouslyAllowAllBuilds` to true, and do not pass `--dangerously-allow-all-builds` on the CLI.

   Check that you did not accidentally flip this on:

   ```bash
   pnpm config get dangerouslyAllowAllBuilds
   # should show nothing or 'false'
   ```

   Also check in `pnpm-workspace.yaml` for a `dangerouslyAllowAllBuilds: true` line and remove it if present. ([pnpm.io][7])

2. **Use `pnpm approve-builds` very sparingly**

   This command whitelists specific packages that are allowed to run build scripts. It writes to `onlyBuiltDependencies` and `ignoredBuiltDependencies` in `pnpm-workspace.yaml`. ([pnpm.io][8])

   Strategy for you as a solo dev:

   * Run your usual `pnpm install`.

   * If pnpm warns that some dependency’s script was blocked and you *know* it is a legit one that really needs to compile stuff (for example `@swc/core`, `bcrypt`, `sharp`, Prisma), run:

     ```bash
     pnpm approve-builds
     ```

   * Then let pnpm add only those to the allowlist.

   * Do not blanket approve everything, and definitely do not try to mimic npm’s old behavior.

3. **Optional extra paranoia for installs**

   For a particularly sketchy project, you can also do:

   ```bash
   pnpm install --ignore-scripts
   ```

   That turns off all lifecycle scripts (including your top level project). It may break native modules or codegen, so this is more of an emergency lever during incidents.

### 3.2 Delay dependency updates with `minimumReleaseAge`

pnpm has a built in “cooldown” for new versions:

```yaml
# pnpm-workspace.yaml
minimumReleaseAge: 1440   # minutes -> 1 day
# or 10080 for one week
```

This makes pnpm refuse to install any version that was published more recently than the threshold. Since compromised versions are usually detected and unpublished within hours, this is a very effective low effort mitigation. ([pnpm.io][2])

Given the Shai Hulud timeline, setting this to at least 24 hours is reasonable for personal dev work.

### 3.3 Use `trustPolicy` if you want extra checks

pnpm’s `trustPolicy` can be set to `no-downgrade` to block installing versions whose trust level (provenance, publisher identity) is lower than earlier versions you used. That helps avoid newly compromised or re homed packages. ([pnpm.io][2])

In `pnpm-workspace.yaml`:

```yaml
trustPolicy: no-downgrade
```

### 3.4 General hygiene with pnpm

* Always commit your `pnpm-lock.yaml`.
* Avoid `pnpm update` on autopilot. Use `pnpm update <package>` intentionally and read changelogs for anything that touches auth, crypto, or networking.
* Do not use `npm` or `yarn` in the same repo unless you have to. Pick pnpm and stick to it so you do not accidentally bypass its protections.

---

## 4. Sandboxing npm and Node on macOS

You asked explicitly about sandboxing that does not feel like heavy VMs. On macOS you have three realistic layers, from light to heavy:

### 4.1 macOS native sandbox wrappers (good fit for pnpm)

**macos-dev-sandbox**

This is a small tool that wraps your dev commands using macOS’s built in sandbox mechanism (`sandbox-exec`). It blocks access to sensitive paths like `~/.ssh`, `~/.aws`, Desktop, Documents, etc, and allows only your sandbox workspace and toolchain. ([GitHub][3])

The workflow:

1. Install and set up:

   ```bash
   git clone https://github.com/Norskes/macos-dev-sandbox.git
   cd macos-dev-sandbox
   ./sandbox-setup.sh
   ```

   Then add an alias suggested by the script, for example:

   ```bash
   alias sandbox="$HOME/macos-dev-sandbox/sandbox.sh"
   export SANDBOX_BASE_DIR="$HOME/Sandbox"
   ```

2. Use it:

   ```bash
   cd "$SANDBOX_BASE_DIR/my-project"

   sandbox pnpm install
   sandbox pnpm run dev
   sandbox node some-script.js
   ```

Within that sandbox:

* Critical files like `~/.ssh`, `~/.aws`, Desktop, Documents are blocked from read access.
* Your dev tools, npm cache, pnpm store, and the sandbox workspace remain usable. ([GitHub][3])

For your use case (pnpm plus Node), this is probably the most ergonomic “just wrap my commands” solution that still uses macOS’s native sandboxing.

### 4.2 Node focused sandbox: node-safe

`node-safe` is a wrapper around your existing `node` binary that uses the macOS sandbox under the hood. It gives you Deno style permissions for file system, network, and process spawning, and provides `npm-safe` / `npx-safe` / `yarn-safe` binaries. ([GitHub][9])

Typical install:

```bash
npm install --global @berstend/node-safe

# Then:
node-safe script.js
npm-safe install   # sandboxed install
npm-safe run build
```

You can allow specific paths:

```bash
npm-safe --allow-read="./src/**" --allow-write="./dist/**" run build
```

Right now the project explicitly supports npm and yarn as package managers. For pnpm, you would still benefit from using `node-safe` for running Node scripts and tools that you do not fully trust, but pnpm itself would be better sandboxed with macos-dev-sandbox or containers.

This is a nice layer for:

* Random CLIs installed via npm.
* Project build scripts that you do not completely trust.
* Node based tools that manage secrets or connect to external services.

### 4.3 Containers that do not feel like “big VMs”

If you are ok with a CLI based VM, then containers are a great compromise: the “VM” is hidden under a simple command and can be disposable.

You have a few options:

1. **Docker / Colima / Rancher Desktop style**

   The “npm in a box” pattern is literally: run npm/pnpm inside a container and mount your project folder. ([SuperGeekery][10])

   Example with Docker:

   ```bash
   docker run --rm -it \
     -v "$PWD":/app \
     -w /app \
     node:22-bullseye \
     bash

   # inside the container:
   corepack enable pnpm
   pnpm install
   pnpm test
   ```

   You can alias this to something like `safe-pnpm` so your workflow is:

   ```bash
   safe-pnpm install
   safe-pnpm test
   ```

   If malware wipes `$HOME` inside that container, it only wipes the container’s home, not your macOS home. Worst case it trashes the project directory you mounted, not your SSH keys or cloud config.

2. **Apple’s new `container` tool**

   On Apple silicon with recent macOS you can use Apple’s own container runtime (`apple/container`), which runs Linux containers as lightweight VMs, with strong isolation via the Virtualization framework. ([GitHub][11])

   This behaves a lot like Docker but uses Apple’s hypervisor isolation model, which gives you VM level safety by default. The usage pattern is similar: you pull or build an OCI image and run `container run` with a bind mount to your project.

   It is newer and less polished than Docker, but it is worth a look if you like Apple native tooling.

3. **VS Code Dev Containers / Remote Containers**

   If you already use VS Code, Dev Containers basically do the above for you, plus isolate your `.env` and secrets, which is explicitly recommended in newer npm security guidance. ([GitHub][6])

As a solo dev who is ok with CLI VMs, I would seriously consider:

* Regular everyday work: pnpm with supply chain settings plus macos-dev-sandbox.
* Trying unknown code or weird repos: run them only inside a container or sandbox.

---

## 5. What to do if you find something suspicious

If any of the checks above suggest you might have been hit:

1. **Rotate credentials**

   At minimum:

   * GitHub PATs and fine grained tokens.
   * SSH keys used for GitHub or infra.
   * npm tokens in `~/.npmrc` or in CI.
   * Cloud creds stored in `~/.aws`, `gcloud`, `az` directories, or .env files. ([wiz.io][4])

2. **Clear caches and reinstall dependencies from a known good state**

   In each project that had bad versions:

   ```bash
   rm -rf node_modules
   pnpm store prune  # optional
   pnpm install
   ```

3. **Harden going forward**

   * Lock down pnpm as described above.
   * Move plaintext secrets out of local `.env` where possible (use password manager CLI, local keychain, or environment specific secrets management). ([GitHub][6])
   * Adopt a sandbox workflow for anything that touches external code.

---

## 6. Recommended setup for you specifically

Given what you described (macOS, pnpm, willing to use CLI and maybe a VM):

1. Verify you are on pnpm 10+ and configure:

   * `minimumReleaseAge: 1440` in `pnpm-workspace.yaml`.
   * `trustPolicy: no-downgrade`.
   * Keep `dangerouslyAllowAllBuilds` off.
   * Use `pnpm approve-builds` only for very specific packages.

2. Install **macos-dev-sandbox** and run all `pnpm install` / `pnpm update` / suspicious Node scripts through `sandbox ...`.

3. Optionally, for extra isolation or when running random cloned repos:

   * Use a Docker or Apple `container` based “safe pnpm” alias and do those installs in containers.

4. Run the detection steps once now:

   * Check your lockfile against Tenable / Datadog lists.
   * Run the file system searches.
   * Check GitHub for suspicious repos.

If you want, I can help you write a small Node or shell script that automatically pulls the Datadog and Tenable IoC lists, parses your `pnpm-lock.yaml`, and prints a simple “might be affected here” summary.

---

* [wiz.io](https://www.wiz.io/blog/shai-hulud-2-0-ongoing-supply-chain-attack?utm_source=chatgpt.com)
* [Cyber Kendra](https://www.cyberkendra.com/2025/11/sha1-hulud-20-destructive-worm-hijacks.html?utm_source=chatgpt.com)
* [IT Pro](https://www.itpro.com/security/cyber-attacks/shai-hulud-malware-is-back-with-a-vengeance-and-hit-more-than-19-000-github-repositories-so-far-heres-what-developers-need-to-know?utm_source=chatgpt.com)
* [securityboulevard.com](https://securityboulevard.com/2025/09/shai-hulud-npm-attack-what-you-need-to-know/?utm_source=chatgpt.com)

[1]: https://www.tenable.com/blog/faq-about-sha1-hulud-2-0-the-second-coming-of-the-npm-supply-chain-campaign "Sha1-Hulud 2.0: npm Supply-Chain Attack FAQ | Tenable®"
[2]: https://pnpm.io/supply-chain-security "Mitigating supply chain attacks | pnpm"
[3]: https://github.com/Norskes/macos-dev-sandbox "GitHub - Norskes/macos-dev-sandbox: A utility for isolating potentially dangerous code during development on macOS using the built-in `sandbox-exec` mechanism."
[4]: https://www.wiz.io/blog/shai-hulud-2-0-ongoing-supply-chain-attack "Sha1-Hulud 2.0 Supply Chain Attack: 25K+ Repos Exposed | Wiz Blog"
[5]: https://securitylabs.datadoghq.com/articles/shai-hulud-2.0-npm-worm/ "
  The Shai-Hulud 2.0 npm worm: analysis, and what you need to know | Datadog Security Labs
"
[6]: https://github.com/lirantal/npm-security-best-practices "GitHub - lirantal/npm-security-best-practices: Collection of npm package manager Security Best Practices"
[7]: https://pnpm.io/it/next/settings?utm_source=chatgpt.com "Settings (pnpm-workspace.yaml)"
[8]: https://pnpm.io/next/cli/approve-builds?utm_source=chatgpt.com "pnpm approve-builds"
[9]: https://github.com/berstend/node-safe "GitHub - berstend/node-safe:  Make using Node.js safe again with Deno-like permissions"
[10]: https://supergeekery.com/blog/containerizing-npm-and-package-managers-for-security?utm_source=chatgpt.com "npm in a box: Containerizing package managers for security."
[11]: https://github.com/apple/containerization?utm_source=chatgpt.com "Containerization is a Swift package for running Linux ..."

