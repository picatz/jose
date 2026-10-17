# Security policy

## Reporting a vulnerability

Report vulnerabilities privately through GitHub: open the repository's
**Security** tab and choose **Report a vulnerability**. Please do not open a
public issue for a suspected vulnerability.

Include the affected package and version (or commit), what an attacker can
do, and a minimal reproduction if you have one. You will get an
acknowledgement, and fixes are released with an advisory that credits the
reporter unless you ask otherwise.

## Supported versions

Until v1, only the latest release (or, before the first tag, the `main`
branch) receives security fixes.

## Scope

In scope: anything that lets a token, key or proof be accepted when it
should be refused, a secret or private key leak, or unbounded resource use
from attacker-controlled input. The defaults described in each package's
documentation (for example, `jwt.Verifier` never accepting `alg: none`) are
part of the security contract.
