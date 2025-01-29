# Controls how many concurrent authenticate calls each cli client should do
TF_VAR_concurrency=1
USERS?=20
AUTHENTICATION_METHOD="jwt" # pkce

build:
	GOOS=linux GOARCH=amd64 go build -o cmd/cli/zitcli github.com/alfatraining/zitadel-bench/cmd/cli

run:
	go run github.com/alfatraining/zitadel-bench/cmd/cli

benchmark-clients: build
	docker network create zitadel || true
	AUTHENTICATION_METHOD=$(AUTHENTICATION_METHOD) docker compose -f benchmark/clients/docker-compose.yml up --build -d

benchmark-scale: benchmark-clients
	AUTHENTICATION_METHOD=$(AUTHENTICATION_METHOD) docker compose -f benchmark/clients/docker-compose.yml scale zitcli=$(USERS)

benchmark-clients-down:
	AUTHENTICATION_METHOD=$(AUTHENTICATION_METHOD) docker compose -f benchmark/clients/docker-compose.yml down --volumes --remove-orphans

down: benchmark-clients-down benchmark-cockroach-down benchmark-postgres-down
	docker network rm zitadel || true
	rm -f ./benchmark/terraform/terraform.tfstate
	rm -f ./benchmark/terraform/terraform.tfstate.backup

benchmark-cockroach:
	docker network create zitadel || true
	TF_VAR_concurrency=$(TF_VAR_concurrency) docker compose -f benchmark/cockroach/docker-compose.yml up -d
	docker logs cockroach-terraform-1  -f

benchmark-cockroach-down:
	TF_VAR_concurrency=$(TF_VAR_concurrency) docker compose -f benchmark/cockroach/docker-compose.yml down --volumes --remove-orphans

benchmark-postgres:
	docker network create zitadel || true
	TF_VAR_concurrency=$(TF_VAR_concurrency) docker compose -f benchmark/postgres/docker-compose.yml up -d
	docker logs postgres-terraform-1  -f

benchmark-postgres-down:
	TF_VAR_concurrency=$(TF_VAR_concurrency) docker compose -f benchmark/postgres/docker-compose.yml down --volumes --remove-orphans
