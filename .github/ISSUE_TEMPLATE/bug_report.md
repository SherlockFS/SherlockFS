---
name: Bug report
about: 'Help us fix SherlockFS: Submit a bug report'
title: "[BUG] "
labels: 'triage,bug'
assignees: ''

---

**Issue Description:**

*Please provide a detailed and clear description of the encountered issue. The more details you provide, the better.*

**Affected Components:**

- [ ] SherlockFS toolchain - gcc
- [ ] SherlockFS toolchain - make
- [ ] SherlockFS library - libssl
- [ ] SherlockFS library - libfuse
- [ ] SherlockFS library - libcriterion
- [ ] SherlockFS utils - shlkfs.mkfs
- [ ] SherlockFS utils - shlkfs.mount
- [ ] SherlockFS utils - shlkfs.useradd
- [ ] SherlockFS utils - shlkfs.userdel
- [ ] Other (please specify): [component name]

**Pre-Execution Checklist:**

- [ ] Operating system confirmed as Linux-based.
- [ ] Confirmed execution of `./dependencies.sh` script without errors.
  - [ ] Verified OpenSSL / libssl correct installation.
  - [ ] Verified OpenSSL / libssl version >= `3.0.10`.
  - [ ] Verified FUSE / libfuse correct installation.
  - [ ] Verified libcriterion correct installation (testing only).
- [ ] Confirmed that the issue still exists after using the Docker image.

**Reproduction Steps:**

1. Navigate to [specific folder/file].
2. Run the command [command].
3. Input [input/data].
4. Encounter the error at [specific moment].

```log
[Output logs goes here]
```

**Expected vs. Actual Behavior:**

*Expected:*
*Describe your expectations in detail.*

*Actual:*
*Detail what actually happened, including exact error messages if applicable.*

**Supporting Information:**

*Include screenshots, code snippets, or sample files if they would assist in diagnosing the problem.*

**System Environment:**

- Operating System: [your OS and its version (`uname -a`)]
- OpenSSL Version: [your OpenSSL / libssl version (`openssl version`)]
- FUSE Version: [your FUSE version (`fusermount -V`)]

**Additional Context:**

*Anything else you think might help us understand the problem better.*

**Possible Solutions:**

*Feel free to suggest what might be causing the issue or how to fix it.*

**Related Issues & Documentation:**

*Mention any related issues or documentation that could be relevant.*

**Issue Submission Checklist:**

- [ ] *Pre-Execution Checklist* has been completed.
- [ ] I have checked the issue tracker for similar issues.
- [ ] I have provided a detailed account of steps to reproduce the issue.
- [ ] I have detailed my environment information.
- [ ] I have included all relevant supporting documents.
