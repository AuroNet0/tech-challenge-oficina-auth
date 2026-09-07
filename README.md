# tech-challenge-oficina-auth

## Objetivo

Este repositorio contem a estrutura inicial do servico de autenticacao de clientes da oficina.
O servico sera uma AWS Lambda responsavel por receber um CPF, validar o CPF, consultar o cliente,
verificar seu status e gerar um JWT em etapas futuras.

## Responsabilidade

A responsabilidade deste projeto e concentrar o fluxo de autenticacao de clientes por CPF.
Nesta etapa inicial, o handler apenas retorna uma resposta temporaria indicando que o fluxo ainda
nao foi implementado.

## Tecnologias

- Java 21
- Maven
- AWS Lambda Java Core
- JUnit 5

## Estrutura

```text
src/
  main/
    java/
      br/com/fiap/oficina/auth/
        handler/AuthHandler.java
        model/AuthRequest.java
        model/AuthResponse.java
  test/
    java/
      br/com/fiap/oficina/auth/
        handler/AuthHandlerTest.java
```

## Execucao local

Para compilar o projeto localmente:

```bash
mvn clean package -DskipTests
```

## Testes

Para executar os testes unitarios:

```bash
mvn test
```

## CI

O workflow `Auth CI` executa testes e build Maven em eventos de `push`, `pull_request` para as
branches `homolog` e `main`, alem de permitir execucao manual via `workflow_dispatch`.

Este projeto ainda nao documenta deploy, criacao de recursos AWS, API Gateway, banco de dados ou JWT.