# Publishing

As of right now, publishing to npm is a manual process.

1. Increment the versions as needed.
   You'll likely want to increment the passkeys-sdk version and make all of the other packages use that new version in their `dependencies`.

2. `git tag @teamhanko/passkeys-sdk@<new version of passkeys-sdk package>`

3. `git push && git push --tags`
