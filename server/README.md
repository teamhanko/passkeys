# Starting the server

## Getting started

For a quick start of the passkey server you can use the config and docker compose file in [deploy/docker-compose](../deploy/docker-compose).
All you have to do to start the server is to run the following commands:

```shell
cd ../deploy/docker-compose
docker compose -f backend.yaml up -d
```

After running the Docker compose command the passkey server will be available at http://localhost:8000 and the 
admin API will be available at http://localhost:8001

Now you need to [create a tenant](#create-tenant) to use the service.

## Start the passkey server manually

If you do not want to use our deployment or already have a database you want to use you can follow the steps below to get the passkey server up and running:

1. [Run a database](#run-a-database)
2. [Configure database access](#configure-database-access)
3. [Apply database migrations](#apply-database-migrations)
4. [Create Tenant](#create-tenant)
5. [Start the backend](#start-the-server)

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

### Apply database migrations

Before you can start and use the service you need to run the database migrations:

#### Docker

```shell
docker run --mount type=bind,source=<PATH-TO-CONFIG-FILE>,target=/config/config.yaml -p 8000:8000 -it ghcr.io/teamhanko/passkey-server:latest migrate up
```

> **Note** The `<PATH-TO-CONFIG-FILE>` must be an absolute path to your config file created above.

#### From source

First build the passkey server. The only prerequisite is to have Go (v1.18+) [installed](https://go.dev/doc/install)
on your computer.

```shell
go generate ./...
go build -a -o passkey-server main.go
```

This command will create an executable with the name `passkey-server`, which then can be used to apply the database migrations
and start the passkey server.

To apply the migrations, run:

```shell
./passkey-server migrate up --config <PATH-TO-CONFIG-FILE>
```

> **Note** The path to the config file can be relative or absolute.

### Create Tenant

Now you need to create a tenant. For this you can import our [admin OpenAPI specification](../spec/passkey-server-admin.yaml)
into Postman, Insomnia or use the following curl command:

```shell
curl --location 'http://<YOUR DOMAIN>:8001/tenants' \
--header 'Content-Type: application/json' \
--header 'Accept: application/json' \
--data '{
  "display_name": "<TENANT NAME>",
  "config": {
    "cors": {
      "allowed_origins": [
        "<CORS ORIGINS>"
      ],
      "allow_unsafe_wildcard": false
    },
    "webauthn": {
      "relying_party": {
        "id": "<YOUR DOMAIN>",
        "display_name": "Hanko Passkey Server",
        "origins": [
          "<WEBAUTHN ORIGINS>"
        ]
      },
      "timeout": 60000,
      "user_verification": "preferred",
      "attestation_preference": "none",
      "resident_key_requirement": "required"
    },
    "create_api_key": true
  }
}'
```
> **Note**: The result of the curl command will contain your **tenant id** (Field: `id`) and your **API key** (Field: `api_key.secret`). 
> If you want to skip the api key creation, remove the `create_api_key` parameter from the body. 

Let us dissect the command to show how to configure the tenant for your use case.

#### Name of the Tenant

If you want to maintain multiple tenants and build your own dashboard you can change `<TENANT NAME>` to a more descriptive one.
If you only want to use 1 tenant, just name it like you want.

e.g:

```json
{
  "display_name": "My Test Tenant"
}
```

#### Configure Cors

Because the server and your application(s) consuming the server API most likely have different origins, i.e.
scheme (protocol), hostname (domain), and port part of the URL are different, you need to configure
Cross-Origin Resource Sharing (CORS) and specify your application(s) as allowed origins:

```json
{
  "config": {
    "cors": {
      "allowed_origins": [
        "<CORS ORIGINS>"
      ],
      "allow_unsafe_wildcard": false
    }
  }
}
```

Replace `<CORS ORIGINS>` with the origin of your application.
When you include a wildcard `*` origin you need to set `"allow_unsafe_wildcard": true`:

```json
{
  "config": {
    "cors": {
      "allowed_origins": [
        "*"
      ],
      "allow_unsafe_wildcard": true
    }
  }
}
```

Wildcard `*` origins can lead to cross-site attacks and when you include a `*` wildcard origin,
we want to make sure, that you understand what you are doing, hence this flag.

> **Note** In most cases, the `allowed_origins` list here should contain the same entries as the `webauthn.relying_party.origins` list. Only when you have an Android app you will have an extra entry (`android:apk-key-hash:...`) in the `webauthn.relying_party.origins` list.

#### Configure Webauthn

Passkeys are based on the [Web Authentication API](https://www.w3.org/TR/webauthn-2/#web-authentication-api).
In order to create and login with passkeys, the passkey server must be provided information about
the [WebAuthn Relying Party](https://www.w3.org/TR/webauthn-2/#webauthn-relying-party).

```json
{
  "config": {
    "webauthn": {
      "relying_party": {
        "id": "<YOUR DOMAIN>",
        "display_name": "Hanko Passkey Server",
        "origins": [
          "<WEBAUTHN ORIGINS>"
        ]
      },
      "timeout": 60000,
      "user_verification": "preferred",
      "attestation_preference": "none",
      "resident_key_requirement": "required"
    }
  }
}
```

For most use cases, you just need the domain of your web application that uses the passkey server. Set
`<YOUR DOMAIN>` to the domain and set `<WEBAUTHN ORIGINS>` to the domain _including_ the
protocol.

> **Important**: If you are hosting your web application on a non-standard HTTP port (i.e. `80`) you also have to
> include this in the origin setting.

As an example: If the login should be available at `https://login.example.com` instead, then the WebAuthn config would look like this:

```json
{
  "config": {
    "webauthn": {
      "relying_party": {
        "id": "login.example.com",
        "display_name": "Hanko Passkey Server",
        "origins": [
        "https://login.example.com"
        ]
      },
      "timeout": 60000,
      "user_verification": "preferred",
      "attestation_preference": "none",
      "resident_key_requirement": "required"
    }
  }
}
```

Given the above scenario, you still may want to bind your users WebAuthn credentials to `example.com` if you plan to
add other services on other subdomains later that should be able to use existing credentials. Another reason can be if
you want to have the option to move your login from `https://login.example.com` to `https://example.com/login` at some
point. Then the WebAuthn config would look like this:

```json
{
  "config": {
    "webauthn": {
      "relying_party": {
        "id": "example.com",
        "display_name": "Hanko Passkey Server",
        "origins": [
        "https://login.example.com"
        ]
      },
      "timeout": 60000,
      "user_verification": "preferred",
      "attestation_preference": "none",
      "resident_key_requirement": "required"
    }
  }
}
```

### Start the server

To serve the API with the passkey-server you can use the following command:

##### Docker

```shell
docker run --mount type=bind,source=<PATH-TO-CONFIG-FILE>,target=/config/config.yaml -p 8000:8000 -p 8001:8001 -it ghcr.io/teamhanko/passkey-server:latest serve all
```

> **Note** The `<PATH-TO-CONFIG-FILE>` must be an absolute path to your config file created above.

The service is now available at `localhost:8000` and the admin API at `localhost:8001`

`8000` is the default port for the API. It can be customized via in the configuration through
the `server.address` option.

```yaml
server:
  address: "<YOUR_URL>:<YOUR_PORT>"
```

`8001` is the default port for the admin API. It can be customized via in the configuration through
the `server.admin_address` option.

```yaml
server:
  admin_address: "<YOUR_URL>:<YOUR_PORT>"
```

##### From source

```shell
go generate ./...
go build -a -o passkey-server main.go
```

Then run:
```shell
./passkey-server serve all --config <PATH-TO-CONFIG-FILE>
```

The service is now available at `localhost:8000` and the admin API at `localhost:8001`
