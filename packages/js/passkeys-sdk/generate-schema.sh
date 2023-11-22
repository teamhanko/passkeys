#!/bin/bash

dirname=$(dirname "$0")

bunx openapi-typescript "$dirname/../../../spec/passkey-server.yaml" -o "$dirname/src/schema.ts"