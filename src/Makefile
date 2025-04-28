SCRIPT := scripts/generate_env.py

all: up

build:
	docker compose --env-file .env -f docker-compose.yml -f docker-compose.user.postgres.yml build
	# docker compose --env-file .test-env -f docker-compose.test.yml build
	# docker compose --env-file .env -f docker-compose.yml -f docker-compose.user.mongo.yml build

up: postgres

test:
	docker compose --env-file .test-env -f docker-compose.test.yml up -d

mup:
	docker compose --env-file .test-env -f docker-compose.test.yml -f docker-compose.down.yml up user-migrate-postgres auth-migrate-postgres todo-migrate-postgres

mdown:
	docker compose --env-file .test-env -f docker-compose.test.yml -f docker-compose.down.yml up user-migrate-postgres-down auth-migrate-postgres-down todo-migrate-postgres-down --force-recreate

reset:
	make mdown
	make mup

postgres:
	python ${SCRIPT}
	docker compose --env-file .env -f docker-compose.yml -f docker-compose.user.postgres.yml up
	# cat .env | grep -v '^$$' | sed 's/^\(\w\)/export \1/g' | sed 's/$$/;/g' | xargs && docker compose

mongo:
	python ${SCRIPT}
	docker compose --env-file .env -f docker-compose.yml -f docker-compose.user.mongo.yml up

rmv:
	for volume in $$(docker volume ls -q); do docker volume rm $$volume; done

down:
	docker compose --env-file .env -f docker-compose.yml -f docker-compose.user.postgres.yml down
	# docker compose --env-file .test-env -f docker-compose.test.yml down
	# docker compose --env-file .env -f docker-compose.yml -f docker-compose.user.mongo.yml down

boards:
	docker exec -it todo-postgres-test psql -U postgres -d todo_db -c "select * from boards;"

columns:
	docker exec -it todo-postgres-test psql -U postgres -d todo_db -c "select * from columns;"

cards:
	docker exec -it todo-postgres-test psql -U postgres -d todo_db -c "select * from cards;"

users:
	docker exec -it user-postgres-test psql -U postgres -d user_db -c "select * from users;"

tokens:
	docker exec -it auth-postgres-test psql -U postgres -d auth_db -c "select * from tokens;"
