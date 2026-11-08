# Identidade independente — Etapa 8.1

> Registro da entrega 8.1. O estado atual do handler, autenticação RS256/JWKS, rehash e V2
> está documentado em [authentication.md](authentication.md). As descrições de 503 permanente
> e da 8.2 como futura abaixo representam o estado histórico da 8.1.

## Escopo e estado operacional

Java 21, AWS Lambda e JDBC, sem Spring, JPA ou acesso aos bancos de OS, Execution e Billing.
Esta etapa prepara persistência e provisionamento interno. **Não fornece login seguro ainda.**
O handler antigo mantém nome e assinatura, mas retorna HTTP 503 para qualquer evento, inclusive sem configuração.
Não existe flag que habilite CPF em produção ou localmente. A consulta à tabela externa `clientes` foi removida.
`JwtService` permanece depreciado e isolado, sem chamada pelo handler; os testes preservam apenas o contrato
HS256 antigo (inclusive subject CPF) para referência de compatibilidade. CPF é público e nunca comprova identidade.

## Pacotes e classes

```text
br.com.fiap.oficina.auth
├── domain
│   ├── model: Usuario, UsuarioCliente
│   ├── enums: Papel
│   └── exception: IdentityException
├── application
│   ├── port/in: UsuarioView
│   ├── port/out: UsuarioRepository, IdentityTransaction, PasswordHasher, ProvisioningAuthorization
│   └── usecase: CadastrarUsuarioUseCase, BuscarUsuarioUseCase,
│               AtribuirPapelUseCase, VincularClienteUseCase, DesativarUsuarioUseCase
├── infrastructure
│   ├── persistence/jdbc: JdbcIdentityTransaction, JdbcUsuarioRepository
│   ├── config: AuthDatabase, MigrateIdentity
│   └── security: Argon2idPasswordHasher
├── handler: AuthHandler (legado, desativado)
├── service: JwtService (legado), CpfValidator (validação legada), ConfigurationException
└── model: ClienteAuth, AuthResponse (contrato legado)
```

O domínio depende apenas da biblioteca padrão Java. A porta de repositório trabalha com o agregado completo,
permitindo consultar e persistir usuário, credencial, papéis e vínculos na mesma transação.
`UsuarioView` é a saída dos casos de uso: não contém CPF nem hash.
Não serializar o agregado `Usuario`; o hash é acessível apenas internamente para persistência/verificação.
O `toString` do agregado contém somente UUID e estado de ativação.

## Modelo e invariantes

- UUID aleatório é a identidade principal. Email é login único; CPF é metadado opcional.
- Email: strip nas extremidades e lowercase com Locale.ROOT em todo o endereço. Apenas ASCII, formato
  local@dominio.sufixo, até 254 caracteres; pontos e aliases com + são preservados. Não há equivalência
  especial para provedores, remoção de pontos, Unicode ou IDN. A política torna a parte local insensível
  a maiúsculas por decisão explícita do Auth.
- CPF: aceita onze dígitos, pontos, hífen e espaços; persiste onze dígitos. Ausência é null.
  A política desta etapa verifica formato, não titularidade nem dígitos verificadores. CPF informado é único
  no banco Auth; múltiplos null são permitidos. Nunca usar CPF como segredo ou chave de relacionamento.
- Nome obrigatório, sem espaços nas extremidades, até 200 caracteres. Hash Argon2id obrigatório.
- Timestamps UTC (`Instant` / `TIMESTAMPTZ`), atualização não anterior à criação.
- Cadastro começa ativo e sem papéis ou vínculos. Ausência de papel não concede privilégios.
- Papéis fechados: CLIENTE, ATENDENTE, MECANICO, GERENTE. Valores desconhecidos são rejeitados pelo enum
  e pelo CHECK SQL; duplicatas são recusadas pelo domínio e PK composta.
- Usuário inativo não tem privilégios, não pode receber novos papéis ou vínculos, nem poderá receber
  autenticação válida na Etapa 8.2. A futura autenticação deverá verificar estado antes de emitir token.
- Vínculos exigem CLIENTE. Acesso lógico exige usuário ativo, papel CLIENTE e vínculo efetivamente atribuído.
  A autorização dos recursos nos outros serviços ainda será implementada na Etapa 8.3.

## Provisionamento e autorização

Todos os casos de uso exigem uma implementação injetada de `ProvisioningAuthorization`.
A porta deve lançar exceção se o chamador não puder executar a operação no usuário/cliente alvo.
Ela não recebe papéis declarados pelo cliente HTTP como prova de autorização.
Não há implementação permissiva, binding de produção ou endpoint público nesta etapa.
Os autorizadores permissivos dos testes são fixtures exclusivamente em `src/test`.

Antes de expor handlers administrativos, implementar autorização baseada em identidade autenticada e papéis
consultados no Auth, incluindo autorização do alvo, auditoria e proteção contra elevação de privilégios.
O primeiro GERENTE deverá ser provisionado futuramente por operador de segurança autorizado, via ferramenta
administrativa separada e auditada, após comprovação de identidade e criação de credencial individual.
Não existe bootstrap automático, conta padrão, senha fixa ou migração com usuários.
As classes de caso de uso são operações internas, não mecanismos de login ou de autorização HTTP.

O vínculo `UsuarioCliente(usuarioId, clienteId, criadoEm)` é lógico. Não existe FK externa nem consulta ao OS.
A FK composta interna garante que o usuário tenha CLIENTE. Um UUID no Auth não comprova existência no OS.
A integração posterior deverá validar a existência do cliente e a autorização de seu titular por canal confiável,
antes de chamar VincularClienteUseCase. Não aceitar clienteId arbitrário de requisição pública.

## Credenciais

`Argon2idPasswordHasher` usa Argon2id v19 via Bouncy Castle em Java puro, sem JNI ou bibliotecas nativas:
compatível com Java 21 e empacotamento Lambda. Parâmetros atuais: **19.456 KiB (~19 MiB), 2 iterações,
paralelismo 1, salt aleatório SecureRandom de 16 bytes por hash e saída de 32 bytes**.
Formato PHC inclui algoritmo, versão e parâmetros. Comparação do resultado com MessageDigest.isEqual.
A referência da implementação é a [API Bouncy Castle](https://github.com/bcgit/bc-java/blob/main/core/src/main/java/org/bouncycastle/crypto/generators/Argon2BytesGenerator.java).

Senhas de cadastro: 12 a 1.024 caracteres Java; não são normalizadas ou truncadas.
Usar char[] nas chamadas internas e apagar o buffer no chamador em bloco finally.
Não há senha em DTO, log, exception ou banco. Somente o hash sai do componente.
Verificação rejeita hash inválido, senha incorreta, algoritmo/versão desconhecidos e parâmetros fora dos limites
antes de alocar memória (8.192–65.536 KiB, 1–5 iterações, paralelismo 1–4).
`parametros()` identifica a política, e `precisaRehash()` permite atualização futura após verificação bem-sucedida.
Não regravar um hash antes de verificar a senha. Hash malformado falha fechado.

A configuração reduz uso de memória em instâncias Lambda de 512 MB, mas latência/custo e concorrência devem
ser medidos no runtime AWS real na Etapa 8.2. Login futuro exigirá rate limiting e proteção contra abuso.

## PostgreSQL e Flyway V1

Arquivo: `src/main/resources/db/migration/V1__create_identity_schema.sql`.

| Tabela | Chaves e constraints |
| --- | --- |
| usuarios | UUID PK, email único normalizado, CPF opcional único, hash obrigatório no formato Argon2id, ativo, criado_em, atualizado_em |
| usuario_papeis | PK (usuario_id, papel), FK usuarios, CHECK com os quatro papéis |
| usuario_clientes | PK (usuario_id, cliente_id), papel fixo CLIENTE, FK composta para usuario_papeis, criado_em |

Índices únicos de UUID/email/CPF, PKs compostas, índice papel/usuario e índice cliente/usuario.
Todas as FKs permanecem dentro do Auth. Nenhuma conta é inserida.
Flyway Core e módulo PostgreSQL têm a mesma versão. O suporte PostgreSQL é um módulo separado,
conforme a [documentação Flyway](https://documentation.red-gate.com/fd/postgresql-database-277579325.html).

Migração é explícita, executada por `MigrateIdentity.main` em processo separado.
Nunca é chamada pelo handler, construtor da Lambda ou por invocação.
Em implantação futura, executar job controlado antes da atualização da Lambda, com credencial de migração
separada da credencial de runtime. Flyway clean está desabilitado.

## JDBC e transações

`JdbcIdentityTransaction.executar` obtém uma conexão do datasource, desabilita autocommit,
executa o callback com um `JdbcUsuarioRepository` associado à mesma conexão, faz commit ou rollback
e fecha/devolve a conexão. UsuarioRepository não deve escapar do callback.

Leituras usam SELECT FOR UPDATE para bloquear a linha raiz até commit, carregando papéis/vínculos
consistentemente e serializando mutações de um mesmo usuário em READ COMMITTED.
Salvar exige que a raiz tenha sido lida e bloqueada nessa transação; não se usa version.
A estratégia é pessimista, evitando perda de atribuições concorrentes.
Associações são adicionadas via batches idempotentes (ON CONFLICT DO NOTHING), sem remoção implícita.
Não há operação de revogar papel/desvincular nesta etapa.

Todos os valores externos usam PreparedStatement. SQL fixo, sem concatenação de entrada.
Usuário/hash/papéis/vínculos são persistidos atomicamente; erro em qualquer parte desfaz o agregado.
Unicidade é protegida por constraints, inclusive sob concorrência de cadastro.
SQLState 23505 vira DUPLICADO; 40001/40P01/55P03 viram CONCORRENCIA; outros viram PERSISTENCIA.
Mensagens e causas de SQLException não são propagadas em IdentityException.
Handlers futuros deverão mapear erros sem revelar existência de contas ou informações SQL.

Pool HikariCP por contexto de execução: máximo 2, mínimo ocioso 0, espera 3 s,
validação 1 s, inatividade 60 s, vida 5 min, connectTimeout 3 s, socketTimeout 5 s,
statement_timeout 4 s, lock_timeout 2 s e idle_in_transaction_session_timeout 10 s.
Criar datasource uma vez por instância Lambda e reutilizar entre invocações; não criar um pool por consulta.
Fechar datasource no encerramento de processos CLI/testes. A reserva de concorrência da Lambda deverá
considerar 2 conexões por instância; considerar RDS Proxy na infraestrutura futura.

## Configuração local

Pré-requisitos: JDK 21, Maven 3.9+ e Docker com engine ativo.

1. Copiar `.env.example` para `.env` e preencher AUTH_DB_PASSWORD com senha **local** escolhida por você.
2. Iniciar somente o PostgreSQL do Auth: `docker compose --env-file .env up -d --wait`.
3. Exportar as variáveis AUTH_* no shell; Docker Compose lê .env, Java **não lê automaticamente**.
4. Executar `mvn clean verify` e depois a migração explícita abaixo.
5. Consultar o schema e encerrar o ambiente quando necessário.

| Variável | Política |
| --- | --- |
| AUTH_DB_HOST | Obrigatória; sem fallback para DB_HOST |
| AUTH_DB_PORT | Padrão 5432; exemplo local 5544, configurável |
| AUTH_DB_NAME | Obrigatória; banco exclusivo oficina_auth no exemplo |
| AUTH_DB_USER | Obrigatória; usuário exclusivo do Auth |
| AUTH_DB_PASSWORD | Obrigatória, sem valor padrão |
| AUTH_DB_SSLMODE | Padrão verify-full; disable permitido somente com host 127.0.0.1 e AUTH_ENVIRONMENT=local |
| AUTH_ENVIRONMENT | local apenas para desenvolvimento; não altera o handler |

Host/nome/porta são validados para evitar injeção de propriedades no JDBC URL.
Em AWS, usar TLS verify-full e configurar a confiança na CA do banco.
Não reutilizar credenciais, tabelas ou schema do OS.
Compose fixa o bind em 127.0.0.1; volume exclusivo oficina-auth-local_auth-data.
Não versionar .env ou segredos. O exemplo não tem senha preenchida.

Exemplo PowerShell para carregar **somente o .env local controlado por você**, sem avaliar código:

```powershell
Get-Content .env | ForEach-Object {
    if ($_ -match '^([A-Z][A-Z0-9_]*)=(.*)$') {
        [Environment]::SetEnvironmentVariable($matches[1], $matches[2], 'Process')
    }
}
java -cp target/tech-challenge-oficina-auth.jar br.com.fiap.oficina.auth.infrastructure.config.MigrateIdentity
```

O processo migra e valida. Para inspecionar:

```bash
docker compose exec auth-postgres sh -c 'psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" -c "\\dt" -c "\\d usuarios" -c "\\d usuario_papeis" -c "\\d usuario_clientes" -c "SELECT version, success FROM flyway_schema_history"'
docker compose down
```

`down` preserva o volume e afeta apenas este projeto Compose. Não usar comandos globais de prune.
Não é necessário iniciar a Lambda ou conectar à AWS para esta etapa.

## Testes e qualidade

`mvn test`: testes unitários de domínio, casos de uso internos, autorização negada, hash, config,
falhas JDBC e handler fechado, além dos testes legados de contrato compatíveis.

`mvn clean verify`: unitários + integração Failsafe (`*IT`) com Testcontainers PostgreSQL 16,
Flyway migrate/validate, constraints/índices, mapeamento completo, hash persistido,
isolamento, inativação, rollback e concorrência de cadastro/papéis/vínculos.
Docker é obrigatório para verify: falta de engine falha o build, não pula integração.
O banco Testcontainers é descartável e não usa AUTH_DB_* ou DB_* do ambiente.
Não usa AWS, CPF real ou banco do OS.

JaCoCo: gate mínimo de 80% de linhas em **todo o código de produção**, sem excluir domínio,
casos de uso ou adapters. Relatórios `target/site/jacoco/index.html` e `jacoco.xml`.
Unitários em `target/surefire-reports`; integração em `target/failsafe-reports`.
O CI executa clean verify antes de publicar o artefato para o job de deploy.
Nenhum comando local de teste executa Terraform ou deploy.

## AWS Lambda, Shade e compatibilidade

Artefato preservado: `target/tech-challenge-oficina-auth.jar`.
Nome: tech-challenge-oficina-auth; runtime java21;
handler: br.com.fiap.oficina.auth.handler.AuthHandler::handleRequest.
Shade conserva providers via ServicesResourceTransformer: JDBC, Flyway e JJWT continuam descobertos.
Bouncy Castle Argon2 não requer registro de provider criptográfico ou biblioteca nativa.
A assinatura e o código do JWT legado não foram substituídos.

**Mudança intencional:** o endpoint antigo retorna 503 permanentemente. Consumidores que dependam de CPF
deixarão de obter token após implantação; esta é a alternativa segura ao requisito incompatível de manter
login por CPF operacional. Não houve implantação ou alteração de recursos de produção nesta etapa.
Nenhuma variável legada DB_* é lida pelo novo código.

Terraform permanece sem alterações. Atualmente aponta ao RDS legado e injeta DB_*/JWT_SECRET;
isso não inicializa banco nem reativa o handler fechado. Não aplicar esta infraestrutura como preparação
do novo banco. Nenhum apply, push ou deploy é necessário para testar.

Antes de implantação futura:
- Provisionar PostgreSQL exclusivo e credenciais distintas (migration/runtime), com grants mínimos.
- Ajustar data sources, security groups, rede e secret management (Secrets Manager ou equivalente)
  para AUTH_DB_* e CA TLS; remover DB_* e a dependência do RDS OS.
- Definir execução única de migração antes do deploy e política de recuperação.
- Dimensionar memória/timeout, conexões/concurrency e avaliar RDS Proxy.
- Implementar autorização administrativa e procedimento auditado para a primeira conta GERENTE.

**Atenção:** o workflow existente faz deploy e terraform apply em push/workflow_dispatch nas branches
homolog/main. Nenhum push/merge deve ser feito sem revisão e autorização de implantação.

## Próximas etapas

- 8.2: autenticação real email/senha, checagem de inatividade, proteção contra abuso, JWT assimétrico,
  UUID no sub, rotação de chaves e JWKS. Não reaproveitar CPF como subject.
- 8.3: validação JWT e autorização nos microsserviços, integração confiável de vínculos e propriedade das OS.
- 8.4: E2E de segurança incluindo elevação indevida, isolamento entre clientes e usuários inativos.

## Evidência desta entrega

Validação local em 22/10/2026, branch homolog, Microsoft JDK 21 e Docker Desktop:

- `mvn clean verify`: BUILD SUCCESS; 24 testes unitários e 5 de integração, sem falhas ou skips.
- Flyway V1 aplicado e validado em PostgreSQL 16.6 Testcontainers; segunda migração sem alterações.
- Constraints, índices, rollback completo e concorrência de cadastro, papel e vínculo verificados.
- JAR Shade executado em processo Java separado: handler 503, hash/verificação Argon2id e migração
  explícita com datasource Hikari; providers JDBC/Flyway presentes no pacote final.
- JaCoCo: 354 de 389 linhas cobertas (91,00%), gate 80% aprovado, sem exclusões configuradas.
- Docker Compose validado com `config --quiet`; `git diff --check` sem erros.
- Busca por padrões de chaves privadas e access keys AWS não encontrou ocorrências nos arquivos da entrega;
  `.env` ignorado e `.env.example` sem senha preenchida. Essa busca não substitui secret scanning no CI.
- Sem commit, push, merge, deploy, terraform apply ou alteração de Terraform/RDS de produção.

Além das novas classes listadas no mapa de pacotes, foram modificados AuthHandler (desativado),
JwtService (depreciado), AuthHandlerTest (agora exige recusa), pom.xml (dependências, Java 21,
Failsafe, Shade e JaCoCo), CI (clean verify), README e .gitignore.
Foram removidos JdbcClienteRepository, ClienteRepository, DatabaseException e AuthRequest, eliminando
o caminho de consulta/autenticação por CPF no banco externo. Novos testes ficam em domain, application
e infrastructure; PackagedRuntimeProbe existe apenas em src/test para validar o artefato empacotado.
