# Tech Challenge Oficina — Auth Service

AWS Lambda Java 21 com identidade independente, login email/senha, JWT RS256 e JWKS (FIAP Fase 4, Etapas 8.1/8.2).
Sem Spring Boot, JPA ou acesso aos bancos dos demais serviços.

**Login por CPF permanece desativado.** O handler HTTP API v2 oferece `POST /api/v1/auth/login`
e `GET /.well-known/jwks.json`, sem endpoints públicos administrativos.
Login verifica Argon2id, estado e papéis do PostgreSQL Auth antes de emitir RS256 com UUID no subject.
Contrato, configuração, exemplos sanitizados e limitações: [docs/authentication.md](docs/authentication.md).

## Implementação

- Usuario identificado por UUID, email normalizado único, CPF opcional, hash Argon2id e ativação.
- Papéis CLIENTE, ATENDENTE, MECANICO e GERENTE, sem concessão automática.
- Vínculos lógicos autorizados com UUID de cliente do OS, sem FK ou consulta externa.
- Casos de uso internos com porta obrigatória de autorização; nenhuma rota pública administrativa.
- JDBC com pool máximo de duas conexões, transações e bloqueio pessimista.
- Flyway V1, PostgreSQL local, Testcontainers e gate JaCoCo de 80%.
- Rehash condicional sob lock, rate limiting compartilhado via Flyway V2 e JWT de até 15 minutos.
- JWKS público com cache de 60 s e sobreposição de chaves; provider compartilhado com refresh de 30 s.
- Adapter Secrets Manager preparado e provedor de arquivo explicitamente local; nenhuma chave gerada no startup.

Modelo, classes, invariantes, schema, segurança e roteiro completo: [docs/identity.md](docs/identity.md).

## Desenvolvimento local

Requer Java 21, Maven e Docker. Copie `.env.example` para `.env`, preencha uma senha local e inicie:

```bash
docker compose --env-file .env up -d --wait
mvn clean verify
```

Exporte AUTH_DB_HOST, AUTH_DB_PORT, AUTH_DB_NAME, AUTH_DB_USER, AUTH_DB_PASSWORD e, localmente,
AUTH_ENVIRONMENT=local e AUTH_DB_SSLMODE=disable no processo Java.
O Compose lê .env; o Java não o carrega automaticamente. Execute a migração separadamente:

```bash
java -cp target/tech-challenge-oficina-auth.jar br.com.fiap.oficina.auth.infrastructure.config.MigrateIdentity
docker compose down
```

Para usar o handler localmente, configure também AUTH_JWT_ISSUER, AUTH_JWT_AUDIENCE,
AUTH_KEY_PROVIDER=local-file e AUTH_LOCAL_KEY_FILE absoluto em diretório privado ignorado pelo Git.
O comando `java -cp target/tech-challenge-oficina-auth.jar br.com.fiap.oficina.auth.infrastructure.config.GenerateLocalKeys`
gera um arquivo novo apenas com AUTH_ENVIRONMENT=local, fora da Lambda. A chave só assina após a janela
de publicação inicial de 90 s. Não há usuários/senhas padrão. Veja o roteiro completo na documentação de autenticação.

O PostgreSQL fica em 127.0.0.1:5544 (porta configurável). O encerramento preserva o volume exclusivo.
Testcontainers cria seu próprio banco descartável; não depende desse Compose, AWS ou OS Service.
`mvn test` executa os unitários; `mvn clean verify` exige Docker e verifica integração, cobertura e pacote.
Relatório: `target/site/jacoco/index.html`.

## Compatibilidade e implantação

Preservados nome da Lambda, runtime java21, handler e artefato `target/tech-challenge-oficina-auth.jar`.
O código JWT HS256 legado permanece isolado e depreciado para referência de contrato.
Terraform não foi alterado: a futura infraestrutura deverá configurar banco Auth, AUTH_DB_*,
segredos próprios, TLS e execução separada de migração. Não reaproveitar DB_* ou RDS do OS.

**O workflow existente realiza deploy após push/manual em homolog/main.**
Não executar commit, push, merge, deploy ou terraform apply como parte da validação local.
O CI passa a executar clean verify antes do job de deploy existente.

Pendências: implantação AWS e rotação operacional auditada; 8.3 (segurança dos serviços e propriedade de ordens),
8.4 (E2E de segurança). Consulte [limitações e infraestrutura futura](docs/identity.md#próximas-etapas).
