# Autenticação — Etapa 8.2

## Arquitetura implementada

AWS Lambda Java 21, eventos API Gateway HTTP API v2, JDBC/PostgreSQL exclusivo do Auth.
Sem Spring, JPA, recursos AWS novos ou consultas aos bancos dos serviços de negócio.
O handler existente mantém nome/assinatura e agora roteia login e JWKS.
Não há endpoints de cadastro administrativo, atribuição de papel ou vínculo.

Fluxo:
```text
HTTP v2 -> AuthHandler -> limite JDBC compartilhado -> AutenticarUsuarioUseCase
          -> UsuarioRepository (SELECT FOR UPDATE) -> Argon2id -> estado/papéis
          -> rehash condicional -> Rs256TokenIssuer -> commit -> resposta sem cache
GET JWKS -> JwksService -> RotatingKeyProvider -> somente n/e e metadados públicos
```

O domínio da 8.1 e o SQL V1 foram preservados. A extensão do repositório
`atualizarHash(id, anterior, novo, agora)` acrescenta compare-and-set de credencial sob lock da raiz;
não exige mudar Usuario ou seu esquema. O V2 cria somente os contadores de login.

Classes novas:
- application: AutenticarUsuarioUseCase, AccessToken, TokenIssuer, LoginRateLimiter.
- infrastructure/config: AuthBootstrap, AuthServices, GenerateLocalKeys.
- infrastructure/security: KeyProvider, SigningKey, KeyDocuments, RotatingKeyProvider,
  LocalKeySource, SecretsManagerKeySource, Rs256TokenIssuer, JwksService.
- infrastructure/persistence/jdbc: JdbcLoginRateLimiter.

Modificados: AuthHandler, UsuarioRepository, JdbcUsuarioRepository, IdentityException, pom.xml,
.env.example, .gitignore e documentação. Os testes da 8.1 permanecem, ajustando somente as expectativas
transitórias de 503 e a quantidade de migrações. JwtService HS256 e seus testes de contrato
continuam depreciados, isolados e fora do caminho de emissão.

## Fluxo de login e credenciais

1. Exigir evento HTTP API v2, rota/método corretos, Content-Type application/json e JSON estrito.
2. Limitar corpo a 8.192 caracteres transportados e 8.192 bytes decodificados, validar UTF-8/Base64,
   rejeitar campos extras, duplicados, tipos inválidos e documentos concatenados.
3. Exigir apenas email/senha; senha de 12 a 1.024 caracteres, sem normalização; email bruto até 320
   caracteres antes da política de normalização da 8.1 (login normalizado até 254).
4. Contabilizar tentativa distribuída usando sourceIp do contexto de API Gateway e email normalizado.
5. Buscar agregado pelo email em transação, com SELECT FOR UPDATE; carregar papéis efetivos.
6. Verificar Argon2id também para usuário ausente, usando hash fictício calculado uma vez por contexto.
   Comparar com MessageDigest.isEqual pela implementação da 8.1.
7. Senha incorreta, email ausente e inativo retornam o mesmo 401. Não há consulta ou prova por CPF.
8. Após sucesso e confirmação de ativo, recalcular hash antigo quando necessário.
   O UPDATE exige id, hash anterior e ativo, além do lock. Uma troca concorrente não é sobrescrita.
9. Emitir token usando UUID e papéis do banco. Commit antes de retornar o resultado ao handler.
   Se assinatura/commit falhar, não há token entregue e o rehash é revertido.

A transação mantém o lock durante verificação/assinatura para linearizar login com desativação,
mudança de credencial e papéis. Isso pode aumentar contenção; timeouts existentes continuam válidos.
Nenhuma transação do rate limiter fica aberta durante o cálculo Argon2id.
O hash fictício evita o caminho rápido comum de conta inexistente; não se promete tempo perfeitamente
constante de banco/rede ou entre hashes com diferentes parâmetros históricos.
Buffers char[] são apagados no handler; Strings produzidas pelo parser JSON não podem ser apagadas
com garantia na JVM. Nunca registrar body, senha, hash, documento secreto ou token completo.
AccessToken tem toString sanitizado.

## Contrato HTTP

### POST /api/v1/auth/login

```json
{"email":"pessoa@example.test","senha":"<senha individual fornecida pelo usuario>"}
```

Sucesso 200:
```json
{"accessToken":"<JWT assinado>","tokenType":"Bearer","expiresIn":900}
```

A resposta contém apenas esses três campos. expiresIn coincide com exp-iat.
Não há refresh token, sessão persistente ou cookie de autenticação nesta etapa.

| Status | Condição |
| --- | --- |
| 200 | Login válido ou JWKS disponível |
| 400 | Evento/JSON/Base64/UTF-8/entrada inválida |
| 401 | Credenciais inválidas ou usuário inativo; mensagem idêntica |
| 404 | Rota desconhecida, inclusive login legado por CPF |
| 405 | Método incorreto; header Allow indica o método esperado |
| 429 | Limite distribuído excedido; Retry-After: 60 |
| 500 | Falha interna inesperada; mensagem genérica |
| 503 | Banco, chaves, concorrência/timeout ou configuração essencial indisponível |

Respostas de login/erro: Cache-Control: no-store, Pragma: no-cache e nosniff.
O handler não registra exceções ou material sensível. Erros não carregam causas SQL/AWS.
O tratamento de 503 fica restrito a configuração/dependências; não é resposta indiscriminada.

### GET /.well-known/jwks.json

Documento público, sem autenticação. Cache-Control: public, max-age=60, must-revalidate.
Pragma no-cache é mantido como política conservadora de clientes legados.
Exemplo **abreviado** (n representa o módulo RSA em base64url, sem padding):
```json
{"keys":[{"kty":"RSA","kid":"2026-rotation-a","use":"sig","alg":"RS256","n":"<modulo-publico-base64url>","e":"AQAB"}]}
```

A resposta real contém o módulo completo e é utilizada pelos testes para reconstruir a chave pública.
Whitelist de campos: kty, kid, use, alg, n, e. Nunca há d, p, q, dp, dq, qi, privateKey ou credenciais.
Ausência de chaves disponíveis falha com 503; nunca produz JWT sem assinatura.

## JWT RS256

Header sanitizado:
```json
{"alg":"RS256","typ":"JWT","kid":"2026-rotation-a"}
```

Payload ilustrativo sanitizado (datas apenas exemplificativas):
```json
{
  "iss":"https://auth.example.test",
  "sub":"00000000-0000-4000-8000-000000000001",
  "aud":["oficina"],
  "iat":1792843200,
  "nbf":1792843200,
  "exp":1792844100,
  "jti":"00000000-0000-4000-8000-000000000002",
  "roles":["CLIENTE","MECANICO"]
}
```

Forma compacta: `<header-base64url>.<payload-base64url>.<assinatura-RS256>`.
Nenhum token completo ou chave privada é incluído nesta documentação.
Sem CPF, email, nome, senha, hash ou vínculos de cliente. Subject é exclusivamente UUID.
Sem papéis resulta em roles: [], sem privilégios implícitos.
Algoritmo fixado pelo servidor em RS256; entrada HTTP não controla alg, kid, roles, iss ou aud.
TTL padrão 900 segundos, permitido entre 60 e 900. iat/nbf/exp usam Clock injetável,
com precisão de segundos; jti é UUID aleatório.
A biblioteca existente [JJWT](https://github.com/jwtk/jjwt) assina RSA com algoritmo explicitamente informado.

Consumidores da 8.3 deverão fixar RS256, emissor e audiência, verificar assinatura, kid, exp/nbf e
estrutura do subject; rejeitar none, HS256, chaves desconhecidas e algoritmos diferentes.
Os testes fazem essas verificações com uma allowlist RS256. Não aceitar apenas decodificação do payload.
JJWT 0.12.6 verifica exp quando o relógio ultrapassa a data; testes negativos usam relógio posterior,
sem sleeps. A política final de skew dos consumidores deverá ser limitada a no máximo 60 segundos.

## Armazenamento de chaves e escolha AWS

Escolha preparada: Secrets Manager com assinatura RSA local, usando AWS SDK Java v2,
cliente HTTP de URLConnection e credenciais da role Lambda (sem chaves AWS fixas).
A chave privada não vai no JAR, banco, source ou variável PEM. A variável contém somente o identificador
do secret; o adapter lê SecretString da versão AWSCURRENT.
O secret é criptografado no serviço; material privado existirá na memória JVM após recuperação.
Isso exige IAM mínimo, acesso restrito ao processo e não registrar dumps/segredos.
KMS Sign manteria a chave privada fora do processo, mas adicionaria chamada remota, latência e custo por
assinatura e exigiria outro adapter de assinatura. Não foi implementado nem validado nesta etapa.

A [AWS recomenda cache por contexto Lambda](https://docs.aws.amazon.com/lambda/latest/dg/with-secrets-manager.html).
O provider atualiza o manifesto a cada 30 segundos e reutiliza a mesma instância por Lambda.
Cliente: conexão/leitura de 2 segundos, tentativa de 2 segundos e chamada total de 4 segundos.
Falha ao atualizar depois do prazo não usa cache indefinidamente: falha fechada.
Custo futuro depende de quantidade de secrets, chamadas por frota/cold starts e eventual chave KMS;
não houve avaliação de custos AWS com recursos reais.
Permissões previstas: secretsmanager:GetSecretValue no ARN específico; kms:Decrypt na CMK quando aplicável.
Sem permissões de escrita/rotação na role de runtime.
[Permissões e cache do SDK](https://docs.aws.amazon.com/java/api/latest/software/amazon/awssdk/services/secretsmanager/SecretsManagerClient.html).

Documento privado do provedor: activeKid e array keys (máximo 8), cada item com:
kid, publicKey (DER X.509 em base64 padrão), privateKey opcional (DER PKCS#8 em base64 padrão),
publishFrom, signFrom, signUntil, publishUntil (UTC ISO-8601).
privateKey é necessário somente para a ativa; pode ser omitido para chaves antigas/futuras.
RSA de 2.048 a 4.096 bits, expoente público 65537; kid até 80 caracteres alfanuméricos, _ ou -.
JSON duplicado/inválido e documentos acima de 64 KiB são rejeitados sem propagar conteúdo.
Não versionar um documento privado de exemplo. GenerateLocalKeys gera um arquivo novo explicitamente.

## Rotação e sobreposição

A origem compartilhada (AWSCURRENT ou arquivo local) define uma única activeKid.
Não se gera chave em invocação nem startup. Instâncias convergem para o manifesto compartilhado
no máximo após o intervalo de atualização de 30 segundos; não há chave exclusiva por JVM.

Política implementada:
- Publicar a nova chave pelo menos 90 s antes de signFrom (60 s de cache JWKS + 30 s de atualização).
- A assinatura só ocorre no intervalo signFrom inclusivo até signUntil exclusivo.
- publishUntil deve ser pelo menos signUntil + 1.050 s:
  900 s de TTL máximo + 60 s de cache JWKS + 30 s de atualização + 60 s de skew máximo.
- Manter antigas no JWKS até publishUntil, inclusive depois que pararem de assinar.
- Provider com manifesto anterior rejeita remoção antecipada, troca de material do mesmo kid
  ou redução do publishUntil enquanto a chave antiga ainda estiver na janela.
- Expirado o prazo, o manifesto pode remover a chave antiga. Não reutilizar kids.
- Falha de leitura/manifesto/ativa impede emissão. JWKS pode continuar publicando chaves válidas
  mesmo quando a ativa já não pode assinar.

Procedimento de operação futuro: distribuir manifesto com antigas + nova pública; aguardar 90 s;
trocar activeKid de forma atômica na origem compartilhada; manter antigas e respectivas datas;
remover somente depois dos prazos. Enquanto instâncias usam cache anterior, podem continuar assinando
com a antiga até seu signUntil. Portanto, retenção é calculada pelo último instante possível de assinatura.
A publicação inicial deve preceder signFrom; campos de data não comprovam que a operação foi executada.

Testes usam duas instâncias e origem compartilhada para validar sobreposição e rejeição de remoção precoce.
**Não há orquestrador AWS de rotação implantado.** Uma instância nova não conhece manifestos anteriores
e depende da correção do histórico/orquestrador compartilhado; o guard local não substitui controle
central auditado, versionamento de publicação e IAM. Rotação em produção não é declarada concluída.
Revogação emergencial de chave comprometida exige procedimento separado e invalidação controlada de caches.

## Limitação distribuída de tentativas

JdbcLoginRateLimiter usa V2 e transação independente, anterior à criptografia, em todas as tentativas
de entrada válida, inclusive sucesso, senha errada e conta ausente:
- 10 tentativas por email normalizado/minuto.
- 20 tentativas por sourceIp/minuto.
- 300 tentativas globais/minuto.

Janelas fixas usam CURRENT_TIMESTAMP do PostgreSQL; INSERT ON CONFLICT condicional impede ultrapassar
o limite entre instâncias. Chaves de escopo são hashes SHA-256, sem senha, email ou IP em texto puro.
Esse hash não é hash de senha nem anonimização irreversível de identificadores previsíveis.
A ordem estável de aquisição evita deadlocks entre escopos; qualquer falha de banco impede login.
Tentativas recusadas não executam Argon2id; as contagens de tentativas admitidas persistem mesmo se login falhar.
Retry-After: 60 é conservador. Janelas fixas permitem até dois limites em torno da fronteira de minuto.
Limite por email pode causar negação de serviço dirigida por até a janela; parâmetros devem ser calibrados.

O IP vem exclusivamente de requestContext.http.sourceIp. X-Forwarded-For não é usado.
Somente API Gateway deve poder invocar a Lambda publicamente; permissão de invocação direta permite
forjar contexto e precisa ser restrita por IAM/resource policy.
Contadores ficam no banco Auth e funcionam entre JVMs. Não há blacklist/contador apenas em memória.

Manutenção necessária: remover janelas antigas por job administrativo separado, por exemplo:
`DELETE FROM login_tentativas WHERE janela < CURRENT_TIMESTAMP - INTERVAL '1 day'`.
Há índice por janela; a limpeza não é feita em cada login. Configurar execução periódica antes de produção
e grants separados. Sem limpeza o armazenamento cresce; não se declara a operação de produção pronta.
O limite global também limita cardinalidade de contadores admitidos por minuto, mas não elimina a limpeza.

Ainda configurar API Gateway throttling, limites de integração, concorrência reservada e WAF
antes de exposição pública. O banco protege a entrada no Argon2id, mas requisições ainda consomem
invocações/conexões e não substituem proteção de borda contra DDoS.
Logs/access logs da infraestrutura não devem armazenar body ou resposta com tokens.

## Lambda/API Gateway e configuração

Handler preservado: br.com.fiap.oficina.auth.handler.AuthHandler::handleRequest.
Artefato: target/tech-challenge-oficina-auth.jar; runtime java21; Shade preserva ServiceLoader.
AuthBootstrap inicializa serviços uma vez por contexto aquecido; pool Hikari máximo 2,
sem pool por requisição e sem Flyway em invocações. AuthServices.close encerra recursos em processos locais.
Falha de configuração não ativa fallback CPF/HS256.

Este repositório Terraform só declara Lambda/rede/IAM, sem API Gateway. O código anterior já usava
APIGatewayV2HTTPEvent. Configurar rotas explícitas POST /api/v1/auth/login e GET /.well-known/jwks.json,
payloadFormatVersion 2.0. Método vem de requestContext.http.method, caminho de rawPath.
Não remover prefixos/stages arbitrariamente; custom domain/base mapping deve produzir essas rawPaths.
Eventos REST v1 ou sem contexto recebem 400. CORS/OPTIONS, se necessários, ficam na configuração
do HTTP API; o handler não permite origens amplas implicitamente.

| Variável | Obrigatoriedade e uso |
| --- | --- |
| AUTH_DB_* | Conforme identity.md; banco independente, sem fallback DB_* |
| AUTH_KEY_PROVIDER | local-file ou secrets-manager, explícito |
| AUTH_LOCAL_KEY_FILE | Caminho absoluto para arquivo privado apenas em modo local |
| AUTH_ENVIRONMENT | local para arquivo/gerador; local-file é proibido se AWS_LAMBDA_FUNCTION_NAME existir |
| AUTH_KEY_SECRET_ID | Identificador/ARN do secret para secrets-manager |
| AWS_REGION | Região explícita para o SDK em secrets-manager |
| AUTH_JWT_ISSUER | Identificador HTTPS explícito, estável e confiável |
| AUTH_JWT_AUDIENCE | Audiência explícita; até 200 caracteres válidos |
| AUTH_JWT_TTL_SECONDS | 60–900; padrão 900 |

## Execução e testes locais sem AWS

Requer JDK 21, Maven e Docker engine ativo.
1. Copiar .env.example para .env, preencher senha local e exportar AUTH_* no shell (Java não lê .env).
2. Executar `docker compose --env-file .env up -d --wait`.
3. Executar `mvn clean verify` (Testcontainers usa bancos próprios descartáveis).
4. Migrar banco local com:
   `java -cp target/tech-challenge-oficina-auth.jar br.com.fiap.oficina.auth.infrastructure.config.MigrateIdentity`.
5. Criar diretório privado .local-secrets e configurar AUTH_LOCAL_KEY_FILE com caminho absoluto.
6. Gerar chaves somente por comando explícito:
   `java -cp target/tech-challenge-oficina-auth.jar br.com.fiap.oficina.auth.infrastructure.config.GenerateLocalKeys`.
   O arquivo não é sobrescrito. Em POSIX usa modo 600; no Windows aplicar ACL exclusiva do usuário no diretório.
7. Publicar a chave antes de usá-la: o gerador marca signFrom para 90 s após geração.
   Antes desse instante JWKS funciona, mas login retorna 503 por chave ainda não ativa.
8. Provisionar usuários somente pelos casos de uso internos com autorização confiável.
   Não há senha/conta administrativa padrão ou endpoint de autoprovisionamento.
9. Encerrar somente este ambiente com `docker compose down`, preservando seu volume.

Não há servidor HTTP local adicionado. Os testes constroem eventos v2 representativos e chamam o handler;
o teste do JAR usa o construtor real e as mesmas variáveis que a Lambda usaria, sem credenciais AWS.
`mvn test`: unitários e negativos.
`mvn clean verify`: inclui integração PostgreSQL e subprocesso usando o JAR Shade.
Sem Docker o build falha, não ignora integração. Clock injetado controla tempos sem sleeps.
V1 é preservado e validado junto a V2.
Testes cobrem assinatura pública/JWKS, rejeição none/HS256/assinatura errada/expiração/nbf,
papéis, ausência de CPF, inativação, falhas, rotação entre instâncias, rehash, rollback, concorrência
e limites compartilhados. Nenhuma chave de teste é necessária em source ou AWS.
Chaves geradas em testes/gerador são descartáveis e não devem ser usadas em produção.
Relatórios: target/surefire-reports, target/failsafe-reports, target/site/jacoco/index.html.

## Inativação, revogação e Etapa 8.3

Inativo não recebe novos tokens. Token já emitido pode continuar válido até exp, mesmo após desativação,
mudança de senha ou papel. Não há revogação distribuída imediata nesta etapa.
Avaliar sessão/versionamento, introspecção para operações sensíveis ou lista compartilhada de revogação.
Não usar blacklist local. Refresh tokens exigirão etapa própria com armazenamento, rotação,
detecção de reutilização e revogação de sessões; não há refresh token improvisado.

Auth autentica e emite papéis; OS/Execution/Billing devem autorizar suas operações na 8.3.
CLIENTE não comprova propriedade de qualquer OS. Vínculos autorizados e propriedade das ordens
continuam necessários; UUID de cliente não é exposto como prova no token.
Nenhum desses serviços foi alterado.

## Pendências AWS e implantação

Não houve deploy, Terraform, criação AWS, alteração de workflow/proteção de branches ou push.
O workflow existente contém deploy em push/manual; não foi acionado ou reativado.
Terraform ainda referencia o banco legado e não deve ser aplicado como implantação do novo fluxo.

Antes de produção: PostgreSQL Auth e grants; migrations V1/V2 como etapa separada; contadores/limpeza;
Secrets Manager, IAM mínimo, rede VPC/NAT ou endpoint e proteção dos secrets;
orquestrador auditado de rotação e publicação prévia; API Gateway v2 e throttling/WAF;
memória/timeout/concurrency/pool; TLS e observabilidade sanitizada.
O adapter Secrets Manager foi testado com cliente simulado; permissões, custos, rede, caches de borda,
rotação real e performance Lambda não foram validados na AWS.

Na infraestrutura atual, a role só tem políticas básicas de logs/VPC e o security group só libera
saída PostgreSQL TCP 5432 na VPC compartilhada. Portanto, ainda faltam explicitamente permissão
Secrets Manager e conectividade HTTPS 443 ao endpoint privado/NAT, além das novas variáveis.

## Evidências locais — 24/10/2026

- `mvn clean verify`: BUILD SUCCESS com Java 21; 42 testes unitários e 12 de integração,
  zero falhas/erros e zero testes ignorados.
- PostgreSQL 16.6 Testcontainers: V1/V2, autenticação Argon2id, papéis, inativação, limites compartilhados
  por email/IP/global, concorrência, compare-and-set, troca de senha concorrente e rollback aprovados.
- Login/JWKS chamados por eventos HTTP v2; token RS256 validado somente com chave pública do JWKS.
- Negativos: none, HS256, RS384, assinatura errada, expiração, nbf, JSON duplicado/extra,
  body inválido/oversized/Base64/UTF-8, senha incorreta, inativo, falhas de banco/chave e headers IP forjados.
- Duas instâncias compartilham manifesto e preservam validação de tokens anteriores na sobreposição.
- JAR Shade de 24.939.815 bytes executado em processo Java separado: bootstrap real, pool,
  migração explícita, login, Argon2id, JWT RS256 e validação pelo JWKS aprovados.
- JaCoCo: 638/697 linhas, 91,54%; gate 80% aprovado sem exclusões. Cobertura da 8.1 preservada.
- V1, Terraform e workflow sem alterações; nenhuma operação Terraform ou AWS executada.
- `git diff --check` e verificação dos arquivos novos sem erros de whitespace.
- Busca por padrões de chaves privadas/access keys sem ocorrências; artefato sem arquivos PEM/key
  ou classes/arquivos de fixtures. Isso não substitui varredura especializada de segredos/dependências.
- Estado Git da entrega: branch homolog, 13 arquivos modificados e 24 novos não rastreados;
  sem commit, push, merge ou deploy. O workspace estava limpo no início desta etapa.
