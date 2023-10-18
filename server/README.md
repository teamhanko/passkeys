# Starting the server

## Getting started

For a quick start of the Passkey server you can use the config and docker compose file in [deploy](../deploy).
All you have to do to start the server is to add an API key and a secret key in the config file in `secrets.api_keys` like:

```yaml
secrets:
  api_keys:
    - your-super-secret-api-key
  keys:
    - your-super-secret-crypto-key
```
> **Note:** You must at least provide 1 api key and 1 secret key.
> * Each secret key needs to be at least 16 characters long
> * Each api key needs to be at least 32 characters long

After that you can run the following docker compose command to start the passkey server for local usage:

```bash
cd deploy
docker compose -f backend.yaml up -d
```

After running the docker compose command the passkey server will be available at http://localhost:8000

> **Note:** If you want to use a different origin you have to configure CORS and webauthn. Please see the

## Start the passkey server manually

If you do not want to use our deployment or already have a database you want to use you can follow the steps below to get the passkey server up and running:

1. [Run a database](#run-a-database)
2. [Configure database access](#configure-database-access)
3. [Apply database migrations](#apply-database-migrations)
4. [Configure JSON Web Key Set generation](#configure-json-web-key-set-generation)
5. [Configure an API key](#configure-an-api-key)
6. [Configure WebAuthn](#configure-webauthn)
7. [Configure CORS](#configure-cors)
8. [Start the backend](#start-the-backend)

### Run a database

The following databases are currently supported:

- PostgreSQL
- MySQL

#### Postgres

Use Docker to run a container based on the official [Postgres](https://hub.docker.com/_/postgres) image:

```shell
docker run --name=postgres \
-e POSTGRES_USER=<DB_USER> \
-e POSTGRES_PASSWORD=<DB_PASSWORD> \
-e POSTGRES_DB=<DB_DATABASE> \
-p <DB_PORT>:5432 \
-d postgres
```

or use the [official binary packages](https://www.postgresql.org/download/) to install and run
a Postgres instance.

#### MySQL

Use Docker to run a container based on the official [MySQL](https://hub.docker.com/_/mysql) image:

```shell
docker run --name=mysql \
-e MYSQL_USER=<DB_USER> \
-e MYSQL_PASSWORD=<DB_PASSWORD> \
-e MYSQL_DATABASE=<DB_DATABASE> \
-e MYSQL_RANDOM_ROOT_PASSWORD=true \
-p <DB_PORT>:3306 \
-d mysql:latest
```

or follow the official [installation instructions](https://dev.mysql.com/doc/mysql-getting-started/en/#mysql-getting-started-installing) to install and run
a MySQL instance.

### Configure database access

Open the `config.yaml` file in the `server/config` or create your own `*.yaml` file and add the following:

```yaml
database:
  user: <DB_USER>
  password: <DB_PASSWORD>
  host: localhost # change this if the DB is not running on localhost, esp. in a production setting
  port: <DB_PORT>
  database: <DB_DATABASE>
  dialect: <DB_DIALECT> # depending on your choice of DB: postgres, mysql
```

Replace `<DB_USER>`, `<DB_PASSWORD>`, `<DB_PORT>`, `<DB_DATABASE>` with the values used in your running
DB instance (cf. the Docker commands above used for running the DB containers) and replace `<DB_DIALECT>` with
the DB of your choice.

### Apply Database migrations

Before you can start and use the service you need to run the database migrations:

#### Docker

```shell
docker run --mount type=bind,source=<PATH-TO-CONFIG-FILE>,target=/config/config.yaml -p 8000:8000 -it ghcr.io/teamhanko/passkey-server:latest migrate up
```

> **Note** The `<PATH-TO-CONFIG-FILE>` must be an absolute path to your config file created above.

#### From source

First build the Hanko backend. The only prerequisite is to have Go (v1.18+) [installed](https://go.dev/doc/install)
on your computer.

```shell
go generate ./...
go build -a -o passkey-server main.go
```

This command will create an executable with the name `hanko`, which then can be used to apply the database migrations
and start the Hanko backend.

To apply the migrations, run:

```shell
./passkey-server migrate up --config <PATH-TO-CONFIG-FILE>
```

> **Note** The path to the config file can be relative or absolute.

### Configure JSON Web Key Set generation

The API uses [JSON Web Tokens](https://www.rfc-editor.org/rfc/rfc7519.html) (JWTs) for authentication.
JWTs are verified using [JSON Web Keys](https://www.rfc-editor.org/rfc/rfc7517) (JWK).
JWKs are created internally by setting `secrets.keys` options in the
configuration file (`server/config/config.yaml` or your own `*.yaml` file):

```yaml
secrets:
  keys:
    - <CHANGE-ME>
```

> **Note**  at least one `secrets.keys` entry must be provided and each entry must be a random generated string at least 16 characters long.

Keys secrets are used to en- and decrypt the JWKs which get used to sign the JWTs.
For every key a JWK is generated, encrypted with the key and persisted in the database.

The Passkey server API publishes public cryptographic keys as a JWK set through the `.well-known/jwks.json` endpoint to enable
clients to verify token signatures.

### Configure an API key

API keys are used to restrict access to a specific part of the HTTP API (Managing credentials and starting a passkey registration)

```yaml
secrets:
  api_keys:
    - <CHANGE-ME>
```

> **Note**  at least one `secrets.api_keys` entry must be provided and each entry must be a random generated string at least 32 characters long.

The Passkey server API publishes public cryptographic keys as a JWK set through the `.well-known/jwks.json`
endpoint to enable clients to verify token signatures.

### Configure WebAuthn

Passkeys are based on the [Web Authentication API](https://www.w3.org/TR/webauthn-2/#web-authentication-api).
In order to create and login with passkeys, the Hanko backend must be provided information about
the [WebAuthn Relying Party](https://www.w3.org/TR/webauthn-2/#webauthn-relying-party).

For most use cases, you just need the domain of your web application that uses the Hanko backend. Set
`webauthn.relying_party.id` to the domain and set `webauthn.relying_party.origin` to the domain _including_ the
protocol.

> **Important**: If you are hosting your web application on a non-standard HTTP port (i.e. `80`) you also have to
> include this in the origin setting.

#### Local development example

When developing locally, the Passkey server defaults to:

```yaml
webauthn:
  relying_party:
    id: "localhost"
    display_name: "Hanko Passkey Service"
    origins:
      - "http://localhost"
```

so no further configuration changes need to be made to your configuration file.

#### Production Examples

When you have a website hosted at `example.com` and you want to add a login to it that will be available
at `https://example.com/login`, the WebAuthn config would look like this:

```yaml
webauthn:
  relying_party:
    id: "example.com"
    display_name: "Example Project"
    origins:
      - "https://example.com"
```

If the login should be available at `https://login.example.com` instead, then the WebAuthn config would look like this:

```yaml
webauthn:
  relying_party:
    id: "login.example.com"
    display_name: "Example Project"
    origins:
      - "https://login.example.com"
```

Given the above scenario, you still may want to bind your users WebAuthn credentials to `example.com` if you plan to
add other services on other subdomains later that should be able to use existing credentials. Another reason can be if
you want to have the option to move your login from `https://login.example.com` to `https://example.com/login` at some
point. Then the WebAuthn config would look like this:

```yaml
webauthn:
  relying_party:
    id: "example.com"
    display_name: "Example Project"
    origins:
      - "https://login.example.com"

```

### Configure CORS

Because the backend and your application(s) consuming backend API most likely have different origins, i.e.
scheme (protocol), hostname (domain), and port part of the URL are different, you need to configure
Cross-Origin Resource Sharing (CORS) and specify your application(s) as allowed origins:

```yaml
server:
    cors:
    allow_origins:
      - https://example.com
```

When you include a wildcard `*` origin you need to set `unsafe_wildcard_origin_allowed: true`:

```yaml
server:
  cors:
    allow_origins:
      - "*"
    unsafe_wildcard_origin_allowed: true
```

Wildcard `*` origins can lead to cross-site attacks and when you include a `*` wildcard origin,
we want to make sure, that you understand what you are doing, hence this flag.

> **Note** In most cases, the `allow_origins` list here should contain the same entries as the `webauthn.relying_party.origins` list. Only when you have an Android app you will have an extra entry (`android:apk-key-hash:...`) in the `webauthn.relying_party.origins` list.

### Start the backend

The Hanko backend consists of a public and an administrative API (currently providing user management
endpoints). These can be started separately or in a single command.

##### Docker

```shell
docker run --mount type=bind,source=<PATH-TO-CONFIG-FILE>,target=/config/config.yaml -p 8000:8000 -it ghcr.io/teamhanko/passkey-server:latest serve
```

> **Note** The `<PATH-TO-CONFIG-FILE>` must be an absolute path to your config file created above.

The service is now available at `localhost:8000`.

`8000` is the default port for the public API. It can be customized via in the configuration through
the `server.address` option.

```yaml
server:
  address: "<YOUR_URL>:<YOUR_PORT>"
```

##### From source

```shell
go generate ./...
go build -a -o passkey-server main.go
```

Then run:
```shell
./passkey-server serve --config <PATH-TO-CONFIG-FILE>
```

The service is now available at `localhost:8000`.
