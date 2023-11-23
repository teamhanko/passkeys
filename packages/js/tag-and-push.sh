#!/bin/bash

version=$1
if [ -z "$version" ]; then
  echo "Usage: $0 <version>"
  exit 1
fi

git tag @teamhanko/passkeys-sdk@$version
git tag @teamhanko/passkeys-next-auth-provider@$version

git push origin @teamhanko/passkeys-sdk@$version & git push origin @teamhanko/passkeys-next-auth-provider@$version
