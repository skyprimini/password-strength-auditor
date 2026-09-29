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

**6. HTML reporting.** Turns a batch audit into a standalone HTML file that can
be shared with someone deciding what to rotate first, without handing them the
credentials.

**5. Breach checking.** Optionally looks the password up in the Have I Been
Pwned corpus. A password can be long, random, and high-entropy and still be
compromised if it has appeared in a breach, and entropy alone will never tell
you that.

The lookup uses k-anonymity: the password is hashed with SHA-1 and only the
**first five characters of that hash** are sent. The server returns every
suffix sharing that prefix and the match happens on your machine, so it never
learns which password was asked about and never sees the password itself. It is
behind the `--check-breaches` flag because it is the only part of the tool that
touches the network, and it degrades quietly to "not checked" when offline.

## Setup

Python 3.10 or newer. There are no third-party dependencies, so there is
nothing to install beyond Python itself.

```bash
git clone https://github.com/skyprimini/password-strength-auditor.git
cd password-strength-auditor
python3 --version   # expect 3.10 or newer
python3 -m pwaudit --help
```

### Install it as a command

```bash
pip install -e .
pwaudit --help
```

That registers a `pwaudit` command that works from any directory. The `-e` makes
it an editable install, so edits to the source take effect immediately; drop it
for a normal install.

### Or run it without installing

```bash
python3 -m pwaudit --help
```

This works straight from a clone with nothing installed, but must be run from
the repository root so Python can find the `pwaudit` package.

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
pwaudit
```

Or pass it directly:

```bash
pwaudit 'correct horse battery staple'
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
pwaudit --file passwords.txt
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

Check whether a password has turned up in a breach:

```bash
pwaudit 'password' --check-breaches
```

```
  Breach check
    found 52,372,427 times in the breach corpus
    Treat this password as compromised and change it everywhere.
```

Write a shareable HTML report of a batch audit:

```bash
pwaudit --file passwords.txt --html report.html
```

The report is a single self-contained file with no external assets, so it
survives being emailed around. It shows summary counts, a sortable table of
every entry, and colour-coded strengths. **It never contains the passwords
themselves**, only their labels and the scores derived from them.

Machine-readable output, for piping into another tool:

```bash
pwaudit --file passwords.txt --json
```

Exit code is `0` when everything scores 3 or better and `1` otherwise, so it can
gate a CI check.

## Running the tests

```bash
python3 -m unittest discover -s tests -t .
```

54 tests covering the character-pool maths, each pattern detector, end-to-end
scoring of known-weak and known-strong passwords, the crack-time boundaries, and
the breach lookup, and the HTML report. The breach tests use a fake HTTP opener,
so the whole suite runs offline and never contacts the network. One test asserts
that no password ever appears in a generated report.

## Project layout

```
pwaudit/
  __main__.py    command line interface
  scoring.py     entropy and the 0-4 score
  patterns.py    weakness detectors
  crack_time.py  attacker models and time estimates
  batch.py       file auditing and reports
  breach.py      Have I Been Pwned lookup, k-anonymity
  report.py      standalone HTML report
  data/          common password list
tests/
  test_pwaudit.py
  test_breach.py
  test_report.py
pyproject.toml   packaging and the pwaudit entry point
```

## A caution

This is coursework. Don't paste real passwords into a tool you found on GitHub,
including this one. The single-password mode prompts with hidden input and never
writes the password anywhere, but the habit is still a bad one.

## Planned work

Tracked as issues on this repository: richer leet handling and a larger
frequency list.
