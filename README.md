# Zitadel Bench

Zitadel Bench is a project to replicate certain Zitadel workflows and benchmark their performance to understand limiting factors and find bottlenecks.

It will run Terraform in a docker container to setup the provisioned Zitadel instance with a required organization, company and user.

# Prerequisites


- Go
- Docker (compose)
- make

For [Zitadel k6s load-tests](https://github.com/zitadel/zitadel/tree/main/load-test):

- [npm](https://docs.npmjs.com/downloading-and-installing-node-js-and-npm)
- [k6](https://k6.io/docs/get-started/installation/)

# Scenarios

## 3-Node Cockroach Cluster

Run Zitadel with a clustered cockroach and 1 CLI client authenticating:
```
make benchmark-cockroach
make benchmark-clients
docker logs clients-zitcli-1 -f
```

## Single-Node Postgres Instance

Run Zitadel with a single instance PostgreSQL and 1 CLI client authenticating:
```
make benchmark-postgres
make benchmark-clients
docker logs clients-zitcli-1 -f
```

## Scaling Go CLI clients

Run multiple Go CLI clients, depending on the `USERS` variable:
```
make benchmark-scale
```

## Removing Clients

Remove all Go CLI clients:
```
make benchmark-clients-down
```

## Remove Everything

Removes any Zitadel and database containers as well as all clients:
```
make down
```
