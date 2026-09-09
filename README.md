# Password Strength Auditor

A command line tool that scores password strength using entropy and pattern
detection, estimates how long different kinds of attackers would need to crack
it, and audits whole files of passwords at once.

Built by [Syanne Voxland](https://skyprimini.github.io/) for CSCI 713,
Software Development Processes, at North Dakota State University.

## Reference project

This project is modelled on **zxcvbn** by Dropbox:

- https://github.com/dropbox/zxcvbn

zxcvbn is the well known open-source password strength estimator. Its core idea
is that the usual rules ("must contain a symbol") measure the wrong thing, and
that a better estimate comes from finding the *patterns* in a password and
working out how many guesses an attacker would actually need.

This project borrows that idea, not its code. The scoring maths, the pattern
detectors, the crack-time scenarios, and the word list here are all written from
scratch. zxcvbn ships a large frequency corpus drawn from real breaches; this
uses a much smaller hand-written list, so it is less accurate on obscure
passwords and is meant as a learning exercise rather than a replacement.

## AI tools used

Developed with **Claude Opus 5** via **Claude Code** (Anthropic's CLI), used for
implementing the scoring engine, the pattern detectors, the crack-time
estimates, and the test suite. Development was iterative: the assistant proposed
implementations, and the design decisions, scope, and review were mine.

One example of that loop is worth recording. The test
`test_common_word_with_suffix_is_flagged` failed on the first run because leet
substitutions were being applied *before* the trailing digits were stripped, so
`dragon123` became `dragonl2e` and the suffix could no longer be removed. The
order of those two steps was swapped and the detector now catches it.

## What it does

**1. Entropy scoring.** Works out the size of the character pool a password
draws from and computes `length * log2(pool)` as a best case, then discounts
that by whatever weaknesses are found. Reports a 0 to 4 score.

**2. Pattern detection.** Flags passwords that look strong but aren't:

- common passwords, including with leet substitutions (`p@ssw0rd`) and
  appended characters (`dragon123`)
- sequential runs (`abcd`, `4321`)
- repeated characters and repeated blocks (`aaaa`, `abcabc`)
- keyboard walks (`qwerty`)
- years and dates

**3. Crack-time estimation.** Converts entropy into estimated time to crack
under four attacker models, from a rate-limited login form through to offline
GPU cracking of a fast hash.

**4. Batch auditing.** Reads a file of passwords and produces either a summary
table or a JSON report, so you can see which credentials to rotate first.

## Setup

Python 3.10 or newer. There are no third-party dependencies, so there is
nothing to install beyond Python itself.

```bash
git clone https://github.com/skyprimini/password-strength-auditor.git
cd password-strength-auditor
python3 --version   # expect 3.10 or newer
python3 -m pwaudit --help
```

Run the commands below from the repository root. The tool is invoked as a
module (`python3 -m pwaudit`) rather than an installed command, so Python needs
to find the `pwaudit` package in the current directory. Installing it as a
standalone `pwaudit` command is tracked as future work.

On Windows, use `python` in place of `python3`.

<details>
<summary>Optional: run inside a virtual environment</summary>

Not required, since there are no dependencies, but harmless if you prefer to
keep things isolated:

```bash
python3 -m venv .venv
source .venv/bin/activate      # Windows: .venv\Scripts\activate
python -m pwaudit --help
```

</details>

## Usage

Check a single password, prompted so it stays out of your shell history:

```bash
python -m pwaudit
```

Or pass it directly:

```bash
python -m pwaudit 'correct horse battery staple'
```

```
  Strength   [####################]  very strong (4/4)
  Entropy    105.1 bits  (before penalties: 105.1)
  Length     16  |  character sets: lowercase, uppercase, digits, symbols

  Estimated time to crack
    Online attack, rate limited            longer than recorded history
    Online attack, no rate limit           longer than recorded history
    Offline attack, slow hash (bcrypt)     longer than recorded history
    Offline attack, fast hash (SHA-1)      longer than recorded history

  Suggestions
    - This password looks solid. Store it in a password manager.
```

Audit a file. Lines may be `password` or `label:password`; blank lines and
lines starting with `#` are ignored:

```bash
python -m pwaudit --file passwords.txt
```

```
identifier  score          bits  offline fast hash
----------  ------------ ------  ----------------------
email       very weak       1.9  instantly
banking     very strong    72.3  90 centuries
laptop      very weak       4.4  instantly
work-vpn    very strong   105.1  longer than recorded history
old-forum   very weak      11.6  instantly

5 passwords: 3 very weak, 2 very strong
```

Machine-readable output, for piping into another tool:

```bash
python -m pwaudit --file passwords.txt --json
```

Exit code is `0` when everything scores 3 or better and `1` otherwise, so it can
gate a CI check.

## Running the tests

```bash
python -m unittest discover -s tests -t .
```

30 tests covering the character-pool maths, each pattern detector, end-to-end
scoring of known-weak and known-strong passwords, and the crack-time boundaries.

## Project layout

```
pwaudit/
  __main__.py    command line interface
  scoring.py     entropy and the 0-4 score
  patterns.py    weakness detectors
  crack_time.py  attacker models and time estimates
  batch.py       file auditing and reports
  data/          common password list
tests/
  test_pwaudit.py
```

## A caution

This is coursework. Don't paste real passwords into a tool you found on GitHub,
including this one. The single-password mode prompts with hidden input and never
writes the password anywhere, but the habit is still a bad one.

## Planned work

Tracked as issues on this repository: breach checking through the Have I Been
Pwned range API using k-anonymity, richer leet handling, a larger frequency
list, and an installable console entry point.
