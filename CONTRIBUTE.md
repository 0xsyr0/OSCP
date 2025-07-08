# CONTRIBUTE.md

Thank you for your interest in making this guide better and to keeping it up to date to help other people passing the OffSec Certified Professional (OSCP) exam!
This notes should give you a guideline on how to contribute to the project.

## Table of Contents

- [Resources](#resources)
- [Styleguides](#styleguides)
    - [Hot to make a bug report](#how-to-make-a-bug-report)
    - [How to fix a bug](#how-to-fix-a-bug)
    - [Coding conventions and style guide](#coding-conventions-and-style-guide)

## Resources

Please only contribute techniques and applications according to the official OffSec Exam Guide.

- [OSCP Exam Guide](https://help.offsec.com/hc/en-us/articles/360040165632-OSCP-Exam-Guide#exam-restrictions)

## Styleguides

### How to make a bug report

If you want to submit a bug like for example a typo please use the following structure.

- Description: Add a short description.
- Environment: Environment information like the name of a box on HTB.
- Command: The command which was used.
- Error message: Output or screenshot which shows the issue. Ideally in Markdown.
- Labels: Typo/Bug/Outdated/Improvement

### How to fix a bug

For fixing a bug I highly recommend forking the repository and creating a pull request (PR) with the detailed description mentioned in the section above.
Please notice that your commits need to be signed in ordert to merch your PR.

### Coding conventions and style guide

When it comes to contribution in terms of techniques or applications please use the following example as baseline in your PR.

```c
#### MAIN SECTION LIKE POST EXPLOITATION

##### SUB-SECTION

> URL (ONLY IF ABSOLUTELY NECESSARY)

COMMAND A
COMMAND B

###### PAYLOAD

COMMAND C
```

- For new tools stick to the Kali Linux menu structure.
- Keep spaces between sections and commands.
- Try to avoid prompts like `$`, `C:\>` or `PS C:\>` to keep commands as easy as possible to copy and paste.
- Try to avoid unnecessary explanations.
- Keep values which needed to be replaced in capital letters.
- Enclose the values in `<>`
- Stick to the already available values like `LHOST`, `RHOST`, `LPORT`, `RPORT`, `DOMAIN`, `FILE`, `SHARE`, `URL` etc.
- If you use  for example payloads from other people, please mention them in your PR.
- Keep it as slim as possible

