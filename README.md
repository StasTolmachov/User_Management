

## Launching locally:  
Starting DB in Docker:
```shell 
make db-up
```
Starting application locally:
```shell
make run
```
Stop and delete database:
```shell
make db-down
```
## Launching in Docker:  
Starting DB and API in Docker:
```shell
make docker-up
```

Stop and delete containers:
```shell
make docker-down
```
## Options:


Make tests and coverage:
```shell
make cover
```

Install migrations:
```shell
make migrate-up
```

Generate mock:
```shell
make mock
```

Generate Swagger:
```shell
make swag
```

[Open Swagger UI](http://localhost:8080/swagger/index.html)
`http://localhost:8080/swagger/index.html`
