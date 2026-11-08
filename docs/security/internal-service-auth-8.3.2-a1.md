# Etapa 8.3.2-A.1 — Preparação do canal técnico Auth–OS

Data: 24/10/2026. **Entrega parcial segura: assinatura, transporte HTTPS, parser de envelope e verificação JWT testáveis; rota interna continua fechada.**

## 1. Estado inicial, escopo e versões

| Repositório | Branch | HEAD inicial | Estado inicial |
| --- | --- | --- | --- |
| AuroNet0/tech-challenge-oficina-auth | homolog | `41bed205bd489c8931dbf4030b706426dd87422f` | Limpo |
| AuroNet0/tech-challenge-oficina-os-service | homolog | `665aea6bffc92d2d2d6183a56d20393745d208b4` | Limpo |

Referências preservadas: `docs/authentication.md`, `docs/security/authorization-8.3.1.md`, `docs/security/internal-identity-8.3.2-a.md`. Não foram editadas para reescrever resultados históricos. Casos de uso/portas da 8.3.2-A e login/JWKS permanecem intactos.

Auth: Java 21, JJWT 0.12.6, Jackson 2.17.2, aws-lambda-java-events 3.15.0, AWS SDK 2.31.78 e JAR Shade, sem Spring. OS: Java 21, Boot 4.1.1, Security 7.1.1/Jackson 3.1.5 gerenciados pelo BOM; adicionados módulos AWS SDK `auth` e `regions` 2.31.78 para assinatura. `Aws4Signer` é do SDK oficial existente, não uma implementação criptográfica de produção do projeto. JJWT 0.12.6 não permite esvaziar o registry de algoritmos com clear(); a allowlist RS256 usa remoção explícita dos demais algoritmos, seguindo a abordagem já testada na 8.2.

Foram revistos AuthHandler/AuthBootstrap/AuthServices, emissor/JWKS/KeyProvider, VerificarAcessoClienteUseCase, ClientAccessAuthentication, IdentidadeAcessoCliente, AcessoClienteView, Terraform Lambda/IAM/rede e SecurityConfig/application.yml do OS. SecurityConfig OS continua Basic temporário; esta etapa não aplica JWT/RBAC aos controllers de negócio.

## 2. Resultado arquitetural e motivo de manter HTTP fechado

O ambiente não possui API Gateway HTTP API AWS_IAM implantado/testável autorizado para esta tarefa. O Terraform atual não declara esse canal e continua com configurações legadas. Não foram feitos deploy, Terraform ou chamadas AWS reais. Assim, **não foi comprovado o comportamento do produto AWS quanto a integridade do corpo, principal entregue, permissões efetivas ou impossibilidade de bypass por InvokeFunction**.

Foi possível comprovar localmente que o assinador SDK produz uma assinatura SigV4 que inclui o hash do corpo e que um verificador independente do algoritmo detecta adulterações. Isso não comprova que uma configuração futura do HTTP API rejeitará todo caminho de payload não assinado, nem que uma identidade IAM terá somente o escopo pretendido.

Por essa razão:

- `AuthHandler` não foi alterado e continua retornando **404** para a rota interna antes de inicializar serviços, inclusive em evento direto com authorizer IAM forjado e JWT real.
- Não há implementação produtiva da porta `ClientAccessAuthentication` baseada apenas em campos de evento. Parser e verificador JWT são componentes separados, ainda não ligados à exposição HTTP.
- Não existe flag de desenvolvimento/produção que habilite a rota nesta entrega.
- OS tem adapter HTTP/assinador e porta para obter JWT do contexto autenticado, sem registro automático de bean, default permissivo ou chamada pelos controllers.
- A extração real de token de uma autenticação JWT do OS pertence ao adapter de segurança da 8.3.2-B. A porta não lê headers arbitrários nem oferece argumento de token na operação de negócio.

Não foi criado protocolo próprio, chave compartilhada entre serviços, Authorization Service ou acesso cruzado aos bancos.

## 3. O que a documentação AWS permite concluir

A [documentação de IAM para HTTP APIs](https://docs.aws.amazon.com/apigateway/latest/developerguide/http-api-access-control-iam.html) descreve AWS_IAM por rota, uso de SigV4 e exigência de execute-api:Invoke. HTTP APIs não suportam resource policies; não planejar esse recurso como controle disponível nessa modalidade.

O [algoritmo SigV4 oficial](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_sigv-create-signed-request.html) incorpora HashedPayload ao canonical request. Essa é a propriedade matemática exercitada pelo teste local do SDK. A aceitação/rejeição de formas alternativas pelo Gateway real não foi medida nesta etapa. Não usar documentação do algoritmo genérico ou de S3 como prova do comportamento específico do HTTP API.

O [formato HTTP API v2](https://docs.aws.amazon.com/apigateway/latest/developerguide/http-api-develop-integrations-lambda.html) utiliza rawPath, requestContext.http.method, body/isBase64Encoded e normalização de headers. aws-lambda-java-events 3.15.0 possui representação de authorizer.iam, inclusive userArn. Um evento JSON pode ser construído por qualquer chamador com InvokeFunction: a presença de apiId, userArn, accountId, signature ou sourceIp **não autentica sua origem**.

O principal técnico futuro deverá vir do contexto IAM criado pelo Gateway autenticado e de mapeamento explícito para role/workload permitido, nunca de X-Service-Id ou do payload. Capturar e validar fixtures reais do contexto HTTP v2 da modalidade adotada antes de implementar esse adapter; logs de `$context.identity.*` não são automaticamente o schema do evento `authorizer.iam`. Referência complementar: [variáveis IAM de access logs HTTP API](https://docs.aws.amazon.com/apigateway/latest/developerguide/http-api-logging-variables.html).

A [permissão Gateway→Lambda](https://docs.aws.amazon.com/lambda/latest/dg/services-apigateway.html) deverá restringir SourceArn/SourceAccount e a função/alias apropriados. Isso não remove automaticamente permissões IAM identity-based de InvokeFunction concedidas a consumidores do mesmo account: revisá-las e impedir esse bypass também. Function URL, rotas $default/ANY e integrações alternativas precisam estar ausentes ou igualmente restritas.

## 4. Componentes implementados

### Auth

Caminhos relativos a `src/main/java/br/com/fiap/oficina/auth/`:

| Componente novo | Comportamento |
| --- | --- |
| `infrastructure/security/InternalClientAccessRequest.java` | Parser estrito do envelope, limites, UUIDs canônicos, instante e checagem de frescor; toString redigido |
| `infrastructure/security/InternalUserTokenVerifier.java` | Assinatura RS256 real com chave pública confiável, schema/claims/tempo e resultado mínimo interno (usuarioId, expiraEm) |

Nenhum desses componentes autentica o serviço por conta própria. Não são handlers, não fazem bind em AuthBootstrap e não podem fornecer um servicoId ao caso de uso. O adapter IAM da porta permanece ausente, evitando transformar campos de contexto forjáveis em prova.

`VerificarAcessoClienteUseCase` continua exigindo contexto de ClientAccessAuthentication vinculado ao alvo/validade e allowlist técnica antes do banco. Usa identidade derivada da autenticação, não usuarioId fornecido ao executar. Leitura atual de usuário ativo, CLIENTE e vínculo continua em transação com SELECT FOR UPDATE. Inexistência/inatividade/sem papel/sem vínculo → decisão negativa; indisponibilidade/lock/commit → erro, nunca false.

### OS

Caminhos relativos a `src/main/java/com/oficina/os/`:

| Componente novo | Comportamento |
| --- | --- |
| `application/port/out/ClientAccessPort.java` | `boolean verificar(UUID clienteId)`; sem parâmetro de usuário/token/roles |
| `application/port/out/AuthenticatedUserToken.java` | Porta para JWT original da invocação HTTP autenticada; sem implementação permissiva |
| `application/exception/ClientAccessException.java` | Falhas sanitizadas separando autenticação, autorização técnica, indisponibilidade e resposta inválida |
| `infrastructure/identity/SigV4ClientAccessSigner.java` | AWS SDK assina POST execute-api, corpo e headers com credencial de sessão não expirada |
| `infrastructure/identity/ClientAccessHttpAdapter.java` | Obtém token pela porta, monta envelope e requestId por chamada, assina, usa HTTPS e valida resposta mínima |

O assinador recebe AwsCredentialsProvider e resolve a credencial em cada operação. Recusa AwsBasicCredentials, sessão sem prazo, sessão expirada ou token de sessão vazio. Não há credencial permanente/default no código. Futuro wiring deve usar provider de workload com atualização automática e prazos explícitos, por exemplo ContainerCredentialsProvider para Pod Identity; IRSA requer provider WebIdentity/STS e dependências/configuração próprias a validar. Os dois módulos SDK adicionados não representam instalação/configuração automática de IRSA.

O adapter recebe HttpClient com connect timeout presente, redirects NEVER e deadline total configurado maior que zero e até 10 s. A chamada assíncrona tem espera limitada, cancelamento em timeout e subscriber que limita resposta a 1.024 bytes. Não redireciona credenciais para outro host, não repete POST automaticamente nem mantém cache positivo. Falhas são sanitizadas sem cause contendo token/body.

Endpoint é configuração confiável HTTPS com caminho exato `/internal/v1/identity/client-access/check`, sem userinfo, query ou fragmento. Isso exige futuro stage `$default` ou domínio/mapping com URL externa compatível. Stage nomeado/prefixo externo não é aceito por este contrato: não remover prefixos arbitrariamente para fazer assinatura coincidir.

Não foram alterados controllers, SecurityConfig, contratos REST públicos, domínio OS, Saga, Inbox, Outbox ou RabbitMQ.

## 5. Contrato HTTP e propagação de identidade

Rota **prevista, não ativada**: POST `/internal/v1/identity/client-access/check`.

Authorization contém SigV4 do workload. Corpo JSON UTF-8 assinado:

```json
{
  "clienteId": "00000000-0000-0000-0000-000000000001",
  "userAccessToken": "<JWT RS256 original>",
  "requestId": "00000000-0000-0000-0000-000000000002",
  "issuedAt": "2026-10-24T12:00:00Z"
}
```

Não contém usuarioId, roles, ativo, lista de clientes ou dados de OS. O OS obtém token exclusivamente de AuthenticatedUserToken, cuja implementação futura deve exigir autenticação JWT já validada e ser vinculada à requisição atual. Não extrair simplesmente Authorization em controller sem autenticação. Nenhum estado de usuário é guardado entre invocações.

Parser Auth: quatro campos exatos, todos strings; JSON sem duplicatas/trailing content; UTF-8 válido; máximo 12 KiB decodificados e token até 8 KiB; clienteId/requestId UUID canônico minúsculo e issuedAt Instant válido. Falha de parsing é INVALIDO sanitizado. Ainda falta adapter para checar limite bruto/Base64 do evento, método/routeKey/content-type, origem de Gateway e autenticação técnica antes do caso de uso. O parser não atribui autenticidade ao que lê.

O JWT é verificado em componente próprio com RS256, kid conhecido/único/publicado no KeyProvider, issuer/audience configurados e claims temporais obrigatórias. Não segue jku/x5u, não aceita alg alternativo, none ou header extra fora de typ/alg/kid do contrato atual. Exige aud array textual, roles array com nomes do enum, sub/jti UUID canônicos, iat/nbf/exp inteiros, nbf=iat, iat não futuro, exp estritamente posterior ao agora/iat e TTL até 900 s. Esta versão usa skew zero; relógios precisam estar sincronizados. Sem CLIENTE no banco atual não há acesso, independentemente do conteúdo do JWT. Roles vazias podem ser verificadas criptograficamente, sem privilégio automático.

KeyProvider de Auth é fonte pública local confiável, não URL fornecida pelo token. Falha de fonte de chaves conserva erro de infraestrutura; JWT malformado/incorreto gera CREDENCIAIS_INVALIDAS, sem registrar token completo.

Resposta futura somente `{"autorizado":true}` ou `{"autorizado":false}`, HTTP 200, Content-Type application/json e Cache-Control no-store. O cliente OS exige esse schema exato, boolean e no-store; campos extras, respostas ambíguas/oversized ou erro de rede não se tornam true/false. 401 → AUTENTICACAO, 403 → SERVICO_NAO_AUTORIZADO, demais status não 200 (inclusive 404 da rota atual) → INDISPONIVEL. Erro estrutural detectado explicitamente é RESPOSTA_INVALIDA; exceção de parser/transporte é indisponibilidade sanitizada. Não devolver corpo remoto ao frontend.

O Auth não prova propriedade da OS: OS ainda precisa resolver seu cliente contratante e autorizar sua ação. O vínculo permanece N:N, sem operação de desvinculação implementada. Não há atomicidade distribuída entre decisão Auth e efeito OS.

## 6. Assinatura, integridade e replay

Produção OS usa AWS4-HMAC-SHA256 do SDK para execute-api/us-east-1 ou Region configurada, com credenciais temporárias. São incluídos `X-Amz-Date`, `X-Amz-Security-Token`, Content-Type e `X-Amz-Content-Sha256` com SHA-256 real do corpo. O corpo usado para transportar o token é exatamente o enviado ao HttpClient; o assinador também mantém cópia para impedir mutação do array original. Não se usa UNSIGNED-PAYLOAD, query presigned ou token em URL.

Os testes incluem uma implementação **exclusivamente em src/test** do algoritmo SigV4 documentado, limitada ao path/service/region usados na suíte e credenciais sintéticas. Ela recalcula canonical request, hash e HMAC e compara assinatura, sem retornar identidade fixa antes de verificar criptografia. Essa escolha fornece um oracle independente do assinador oficial; não cria protocolo novo e não é verificador de produção ou emulador completo de IAM.

Resultado local comprovado: troca de clienteId, JWT ou corpo depois da assinatura falha; segredo incorreto/credencial desconhecida/ausente/header inválido e requisição temporalmente expirada falham no verificador local. Isso **não comprova autorização IAM real de uma role**, nem substitui teste de integração AWS.

Parser Auth oferece janela de 60 s exclusiva no limite superior e tolerância de futuro de até 5 s para issuedAt. Essa checagem só será confiável após autenticação/integridade do envelope. RequestId serve à correlação; não existe tabela distribuída de nonce. Repetição idêntica dentro da janela é permitida no teste, explicitamente, e deverá refazer leitura atual do banco. SigV4 não é apresentado como proteção de uso único. Se rejeição de replay único for requisito de ativação, definir armazenamento atômico por principal/requestId/TTL em projeto aprovado, sem cache por pod/Lambda.

## 7. Evidências e classificação dos testes

### Local implementado

| Categoria | Arquivo | O que comprova |
| --- | --- | --- |
| Unitário/contrato Auth | `src/test/.../infrastructure/security/InternalIdentityComponentsTest.java` | Envelope estrito, limites, frescor, falhas sanitizadas, UUID e formato real de aud do emissor |
| Criptográfico Auth | Mesmo arquivo, JJWT e chaves RSA efêmeras | Token real do Rs256TokenIssuer, assinatura errada, RS384/none, exp/nbf/iat, emissor/audiência/sub/jti/roles inválidos, kid desconhecido e fonte de chaves indisponível |
| Não exposição Lambda | Mesmo arquivo + testes/probe existentes | Evento direto com IAM forjado e JWT válido recebe 404; handler público não inicializa canal interno |
| Unitário/criptográfico OS | `src/test/.../infrastructure/identity/{ClientAccessAdapterTest,SigV4TestVerifier}.java` | SDK assina e oracle HMAC verifica, detectando adulteração e credenciais sintéticas inválidas; sessão permanente/expirada recusada |
| Integração HTTPS local OS | ClientAccessAdapterTest, HttpsServer e certificado efêmero keytool | TLS com confiança/hostname normais, recebimento real de request assinado, duas chamadas sem cache, requestIds novos, respostas/erros/status/limites e timeout |
| Estado/persistência Auth | Suítes preservadas VerificarAcessoClienteUseCaseTest/ClientAccessPostgresIT | Usuário inativo, sem CLIENTE, sem vínculo, N:N, PostgreSQL indisponível, locks/concorrência e commit sem decisão positiva |

O servidor HTTPS local verifica criptografia SigV4; não é a Lambda Auth nem API Gateway. O token textual da suíte OS é marcador de transporte, não JWT autenticado por esse servidor. A prova JWT real está na suíte Auth. Não chamar esses testes separados de E2E distribuído ou de validação IAM implantada.

O certificado TLS é gerado no diretório temporário de teste com keytool/JDK 21 e truststore restrito à suíte; não existe trust-all, HTTP claro ou flag TLS permissiva em produção. Segredos SDK da suíte são sintéticos e nunca usados fora de src/test. Nenhuma credencial AWS real é necessária.

### Cenários ainda pendentes

- Role OS permitida versus role IAM desconhecida/sem execute-api:Invoke, sessão STS inválida/expirada e revogação de credenciais no **Gateway real**.
- Captura do principal HTTP v2 real e mapeamento exato de role/sessão; nenhum header declarativo é prova substituta.
- Adulteração do corpo/token/alvo através do HTTP API real, incluindo hash de conteúdo ausente/alterado, UNSIGNED-PAYLOAD, SignedHeaders reduzido, query signing, transformação/Base64 da integração e eventual rejeição de caminhos alternativos.
- Invocação direta negada por IAM, Function URLs e rotas/integrations de bypass; o teste local 404 comprova não exposição, não policy AWS.
- Adapter produtivo ClientAccessAuthentication, operação HTTP Auth com status 200/401/403/503 e teste cruzado real OS→Gateway→Auth→PostgreSQL. Não há resposta positiva exposta nesta etapa.
- Implementação no OS da porta de token original após JWT autenticado, sem aceitar token do frontend como parâmetro de serviço.

Esses cenários não estão aprovados por stubs ou por testes apenas especificados.

## 8. Critérios de ativação e dependências

Antes de qualquer ativação, apresentar para revisão:

1. HTTP API com route AWS_IAM específica, payloadFormatVersion 2.0, TLS, stage/mapping compatível, limite de corpo/rate e logs sem request/response body, JWT ou assinatura completa.
2. Workload OS com credenciais temporárias renováveis, execute-api:Invoke restrito a account/API/stage/POST/internal/v1/identity/client-access/check, sem wildcard amplo, sem acesso ao banco Auth e sem lambda:InvokeFunction.
3. Fonte de confiança Gateway→Lambda comprovada por permissões de invocação e revisão de identity-based grants; zero bypass por função/alias/URL/rota permissiva.
4. Evidência dos testes adversariais de corpo no produto real. Se não for possível impor integridade integral, **manter fechado** e submeter alternativa padronizada (por exemplo mTLS com identidade verificável e autorização de certificado) à revisão; não inventar assinatura paralela própria ou aceitar somente hash não autenticado.
5. Contrato de contexto IAM real e allowlist técnica; implementar adapter por invocação que valida serviço, envelope/frescor, JWT e alvo, produzindo IdentidadeAcessoCliente com usuarioId derivado exclusivamente do JWT e validade limitada pelas evidências. Nenhuma reutilização de identidade em Lambda aquecida.
6. Binding deliberado no bootstrap/handler, testes de erro e resposta mínima/no-store, transação atual de vínculo preservada, timeouts medidos com os limites JDBC/Lambda existentes e ausência de cache positivo.
7. Adapter de token autenticado no OS com testes de impersonação e uso do JWT original; controllers só passam a depender da porta na 8.3.2-B.
8. Revisão de replay: janela/releitura versus uso único, retenção/auditoria e eventual armazenamento distribuído adicional aprovado.

Não foram criados recursos, alterados Terraform/GitHub Actions ou solicitada ativação sem essas evidências. A próxima decisão é aprovar a validação de infraestrutura em ambiente controlado e seu plano de permissões, em tarefa separada; não publicar a rota como efeito desta entrega local.

## 9. Resultados da execução e arquivos

Execuções finais em 24/10/2026, JDK Microsoft 21.0.12.1, Maven e Docker Desktop locais:

| Repositório | clean verify | Testes | Falhas/erros/ignorados | JaCoCo linhas |
| --- | --- | --- | --- | --- |
| Auth | BUILD SUCCESS | 68 unitários + 16 integração = **84** | **0/0/0** | **764/823 = 92,83%** |
| OS | BUILD SUCCESS | **74**, incluindo integrações HTTP/PostgreSQL/RabbitMQ via Surefire | **0/0/0** | **1.225/1.388 = 88,26%** |

Ambos os gates de 80% passaram, sem adicionar exclusões ou ignorar testes. Testes direcionados novos: 7 cenários Auth e 5 cenários OS. As tentativas iniciais do teste Auth detectaram a incompatibilidade de clear() no registry JJWT; após correção a suíte direcionada e clean verify completo passaram.

JAR Lambda Shade `target/tech-challenge-oficina-auth.jar`: **24.953.346 bytes**. Probe em JVM separada retornou PACKAGED_RUNTIME_OK, preservando login, verificação RS256 com JWKS público, Argon2 e migração explícita. Rota interna continua 404 no probe e no teste de evento IAM forjado. O OS também gerou o JAR Spring Boot repackaged com sucesso.

Logs ignorados pelo Git: Auth `target/auth-a1-verify.log`; OS `target/os-a1-verify.log`. Relatórios Surefire/Failsafe/JaCoCo nos respectivos targets. PostgreSQL e RabbitMQ usados são Testcontainers locais; não houve chamada AWS. Os downloads de dependências Maven não equivalem a chamadas de autenticação AWS.

Migrações originais e documentos anteriores foram comparados ao HEAD e permanecem intactos. `git diff --check` sem erros de whitespace. Estado final: Auth tem quatro arquivos novos não rastreados; OS tem pom.xml modificado e sete arquivos novos não rastreados. Não há alterações locais anteriores sobrescritas, commit ou push.

Auth: dois novos arquivos de produção, um novo teste e este documento; nenhum arquivo de produção preexistente modificado. OS: pom.xml com dois módulos SDK, duas portas, exceção, dois adapters e dois arquivos de teste novos. Todas as entidades, migrações, controllers, configurações de segurança e Saga/mensageria preexistentes permanecem inalteradas.

Antes de wiring/ativação, revisar níveis de logs de SDK/signers e logging HTTP de infraestrutura: proibir wire/canonical debugging que possa capturar credenciais de sessão ou headers assinados. O código novo não registra token, body ou exceção remota, mas isso não substitui a política de logs dos componentes externos. Não registrar o objeto SdkHttpFullRequest assinado, eventos Lambda ou o retorno da porta de token. Essa revisão faz parte do gate de ativação, junto da supressão de body em Gateway/APM.

## 10. Próxima etapa

8.3.2-B: autenticar HTTP do OS por JWT e ligar extração confiável do token/políticas de recurso, depois de resolver o gate de infraestrutura para o canal Auth. Manter ownership real indisponível com falha fechada enquanto a rota Auth estiver fechada; não substituir consulta por autorização positiva local. Escopos filial/atribuições seguem a autoridade do OS definida na 8.3.2-A.

Nenhum commit/push. Não iniciar 8.3.2-B automaticamente.
