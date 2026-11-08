# Etapa 8.3.1 — Arquitetura de autorização e matriz de permissões

Data: 24/10/2026. **Proposta para revisão e aprovação; nenhuma segurança nova foi implementada.**

## 1. Escopo, evidências e estado Git

Documento central no Auth, pois este repositório é a fonte dos contratos de identidade, papéis, emissão e JWKS (`docs/identity.md` e `docs/authentication.md`). A autorização de negócio continuará pertencendo a OS, Execution e Billing. Centralizar a especificação evita três matrizes divergentes e não transfere domínio de negócio ao Auth.

Foram examinados os quatro clones locais, todos em `homolog`, inicialmente sem alterações rastreadas ou não rastreadas. HEAD, `homolog` e referência local `origin/homolog` coincidiam. Os HEADs remotos também foram conferidos por GET das branches na API GitHub, através do conector, e coincidem com os abaixo. O `git ls-remote` pelo Git Windows falhou por credenciais Schannel; a verificação pelo conector resolveu essa limitação sem checkout/fetch ou alteração de configuração global. A exceção de `safe.directory` necessária nos clones irmãos foi passada apenas ao comando Git.

| Repositório AuroNet0 | HEAD analisado / homolog remoto | Estado inicial |
| --- | --- | --- |
| tech-challenge-oficina-auth | `eb1809a081d2c7cc6a2c01576807fd248f9f3065` | Limpo |
| tech-challenge-oficina-os-service | `665aea6bffc92d2d2d6183a56d20393745d208b4` | Limpo |
| tech-challenge-oficina-execution-service | `c1769c390825d12f35841e1b0d8f9508afa926a1` | Limpo |
| tech-challenge-oficina-billing-service | `6a53e4c412d666051dea5b8919027db09f70f3ab` | Limpo |

Contagem: endpoint é o par método HTTP + caminho declarado em controller. Query parameters não multiplicam rotas. Não se contam HEAD/OPTIONS implícitos, `/error` do framework nem cada recurso estático Swagger.

| Serviço | Controllers | Rotas de negócio | Webhook | Técnica própria | Total de controllers |
| --- | ---: | ---: | ---: | ---: | ---: |
| OS | 4 | 14 | 0 | 0 | **14** |
| Execution | 4 | 10 | 0 | 1 | **11** |
| Billing | 4 | 8 | 1 | 0 | **9** |
| Total | 12 | 32 | 1 | 1 | **34** |

As rotas técnicas geradas por Actuator/Springdoc são inventariadas separadamente na seção 10. A análise inclui todos os controllers encontrados em `src/main/java`, inclusive `BootstrapStatusController`, fora do subpacote `controller`. Não foram encontrados endpoints de alteração de papéis nos três serviços, confirmação manual de pagamento, início HTTP de reparo ou alteração genérica de status.

### Referências locais e convenções

Os caminhos abaixo são relativos ao respectivo repositório, nos commits fixados acima:

- **A** = Auth: `src/main/java/br/com/fiap/oficina/auth/`.
- **O** = OS: `src/main/java/com/oficina/os/`.
- **E** = Execution: `src/main/java/com/oficina/execution/`.
- **B** = Billing: `src/main/java/com/oficina/billing/`.
- **O-HTTP** = O `infrastructure/web/controller/{Cliente,Veiculo,Filial,OrdemServico}Controller.java`; **O-SEC** = O `infrastructure/config/SecurityConfig.java`.
- **E-HTTP** = E `infrastructure/web/controller/{Diagnostic,Repair,ExecutionHistory}Controller.java` e `infrastructure/web/BootstrapStatusController.java`; **E-SEC** = E `infrastructure/config/SecurityConfig.java`.
- **B-HTTP** = B `infrastructure/web/controller/{Orcamento,Pagamento,Checkout,MercadoPagoWebhook}Controller.java`; **B-SEC** = B `infrastructure/config/SecurityConfig.java`.

Esses arquivos fundamentam diretamente cada linha de inventário. Os casos de uso e agregados adicionais são citados nas seções correspondentes. README foi confrontado com código, não usado como fonte exclusiva.

## 2. Estado atual da autenticação

### 2.1 Auth implementado

`A handler/AuthHandler.java` atende `POST /api/v1/auth/login` e `GET /.well-known/jwks.json` com eventos API Gateway HTTP v2. Login usa email/senha; CPF não autentica. `A application/usecase/AutenticarUsuarioUseCase.java` carrega o usuário via repositório transacional, verifica Argon2id e estado ativo e emite `ativo.id()` e `ativo.papeis()`. `A infrastructure/persistence/jdbc/JdbcUsuarioRepository.java` lê papéis/vínculos do banco próprio. Não há aceitação de papéis fornecidos pelo frontend.

Contrato publicado por `A infrastructure/security/Rs256TokenIssuer.java`:

| Campo | Local e valor efetivo | Consequência para consumidores |
| --- | --- | --- |
| `alg` | Header, `RS256` fixo | Allowlist exclusiva RS256 |
| `typ` | Header, `JWT` | Não é prova isolada de autenticidade |
| `kid` | Header, identificador da chave ativa | Selecionar chave pública no JWKS confiável; **não é claim do payload** |
| `iss` | Payload, `AUTH_JWT_ISSUER`, HTTPS explícito | Igualdade exata com configuração aprovada |
| `sub` | Payload, `usuarioId.toString()` | UUID do usuário Auth, nunca CPF ou clienteId |
| `aud` | Payload, array com `AUTH_JWT_AUDIENCE` | Validar presença da audiência esperada |
| `iat` | Payload, instante UTC da emissão em segundos | Exigir tipo temporal e coerência |
| `nbf` | Payload, igual a iat | Rejeitar uso antecipado, respeitado skew limitado |
| `exp` | Payload, iat + TTL | TTL 60–900 s, padrão 900 s |
| `jti` | Payload, UUID aleatório | Identificador do token; não significa revogação implementada |
| `roles` | Payload, lista ordenada de nomes do enum | `CLIENTE`, `ATENDENTE`, `MECANICO`, `GERENTE`; pode estar vazia |

Issuer e audiência de cada ambiente ainda precisam ser fixados: o código exige configuração, não publica um endereço/valor universal. Não inventar URL operacional a partir dos exemplos locais.

`A infrastructure/security/JwksService.java` publica somente `kty`, `kid`, `use`, `alg`, `n`, `e`, obtidos da chave pública RSA. Não publica `d`, primos, PEM privado ou credenciais. `AuthHandler` retorna JWKS com `Cache-Control: public, max-age=60, must-revalidate`; login usa `no-store`.

`A domain/model/Usuario.java`, `UsuarioCliente.java`, `domain/enums/Papel.java` e Flyway `V1__create_identity_schema.sql` estabelecem UUID como identidade, papéis fechados e vínculo lógico `(usuario_id, cliente_id)` condicionado a CLIENTE. Não existe FK externa. Um usuário pode ter vários clientes e um cliente vários usuários: a PK composta não impõe relação 1:1. O vínculo não comprova por si a existência do cliente no OS.

`V2__create_login_rate_limits.sql` adiciona limitação distribuída de tentativas, não revogação. Não há vínculos, CPF ou filial no JWT. Não há refresh token, introspecção, endpoint interno de resolução de vínculos, remoção de vínculo/papel ou revogação imediata de access token implementados. Inativação impede novas emissões; tokens anteriores podem sobreviver até expiração mais a tolerância de relógio. O `JwtService` legado HS256 e seus testes não definem o contrato atual; não reutilizá-los.

### 2.2 Serviços de negócio implementados

Os três `pom.xml` usam **Java 21 e Spring Boot 4.1.1**, com starter Security; ainda não têm integração OAuth2 Resource Server. Auth é Java 21/Lambda/JDBC, sem Spring.

| Serviço | Autenticação HTTP atual | Autorização atual | CSRF atual |
| --- | --- | --- | --- |
| OS | HTTP Basic temporário; usuário padrão Spring quando não sobrescrito | `authenticated()` nas demais rotas; sem papéis/propriedade | Ignorado em `/api/**` |
| Execution | HTTP Basic temporário | `authenticated()` nas demais rotas; sem papéis/propriedade | Ignorado em `/api/**` e `/internal/**` |
| Billing | HTTP Basic configurado via `spring.security.user` | Checkout POST exige `ROLE_BILLING_OPERATOR`; demais negócios somente autenticados | Habilitado; exceção exata para POST do webhook |

Fontes: O-SEC, E-SEC, B-SEC e `src/main/resources/application.yml` de cada serviço. Billing usa `BILLING_SECURITY_ROLES`, padrão `USER`; **BILLING_OPERATOR não é papel do Auth**. Health e Swagger/OpenAPI são `permitAll()` nos três serviços. Não há verificação de proprietário nas consultas/decisões abaixo. Autenticar com Basic não equivale a autorizar por identidade de negócio.

## 3. Inventário completo e alterações propostas

Legenda de papéis: C=CLIENTE, A=ATENDENTE, M=MECANICO, G=GERENTE. `—` significa nenhum papel humano autorizado. Não há hierarquia G > demais. Todas as permissões são propostas e sujeitas às condições desta seção e à aprovação da seção 12.

Autenticação/autorização atuais indicadas por linha: `Basic/aut` = Basic + apenas authenticated, `Basic/op` = Basic + BILLING_OPERATOR, `HMAC` = permitAll no filtro HTTP + autenticação própria no controller. `S` = exigir escopo operacional autorizado (filial/OS); `P` = provar propriedade; `D` = decisão de negócio pendente, negar até aprovação. Identidade JWT, escopo e vínculo ainda não existem nesses serviços.

### 3.1 OS — 14 rotas (O-HTTP/O-SEC)

| ID | Controller | Método e caminho completo | Operação | Atual: autenticação/autorização | Papéis recomendados | Propriedade/condição adicional | Risco atual | Alteração 8.3.2 |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| O01 | ClienteController | POST `/api/v1/clientes` | Cadastrar cliente | Basic/aut | A | S; cadastro não cria vínculo Auth | Cadastro abusivo/PII | JWT + A + escopo + auditoria |
| O02 | ClienteController | GET `/api/v1/clientes/{id}` | Consultar cadastro | Basic/aut | A | S; C/G/M negados neste DTO integral | Exposição de CPF, contato e cadastro alheio | JWT + A + alvo autorizado |
| O03 | ClienteController | GET `/api/v1/clientes` | Listar clientes | Basic/aut | A | S; filtrar antes de retornar | Enumeração de todos os clientes | JWT + A + filtro de escopo |
| O04 | VeiculoController | POST `/api/v1/veiculos` | Cadastrar veículo | Basic/aut | A | S sobre cliente alvo; ativo | Vincular veículo ao cliente errado | JWT + A + validar cliente/escopo |
| O05 | VeiculoController | GET `/api/v1/veiculos/{id}` | Consultar veículo | Basic/aut | C, A | C: P via veículo.clienteId; A: S | IDOR de veículo | JWT + papel + propriedade/escopo |
| O06 | VeiculoController | GET `/api/v1/veiculos?clienteId={uuid}` | Listar veículos do cliente | Basic/aut | C, A | C: clienteId em vínculos; A: S | Enumeração por parâmetro manipulável | JWT + validar filtro antes da consulta |
| O07 | FilialController | POST `/api/v1/filiais` | Cadastrar filial | Basic/aut | G | S + delegação administrativa explícita D | Alteração da estrutura da oficina | JWT + G + permissão administrativa específica |
| O08 | FilialController | GET `/api/v1/filiais/{id}` | Consultar filial | Basic/aut | A, G | S; não há propriedade pessoal | Reconhecimento da estrutura | JWT + escopo de filial |
| O09 | FilialController | GET `/api/v1/filiais` | Listar filiais | Basic/aut | A, G | S; filtrar filiais autorizadas | Enumeração operacional | JWT + filtro de escopo |
| O10 | OrdemServicoController | POST `/api/v1/ordens-servico` | Abrir OS/iniciar Saga | Basic/aut | A | S; cliente/veículo/filial consistentes e ativos conforme domínio | Abertura indevida e disparo de comandos | JWT + A + escopo antes de mutar/Outbox |
| O11 | OrdemServicoController | GET `/api/v1/ordens-servico/{id}` | Consultar OS | Basic/aut | C, A, M, G | C: P; A/G: S; M: OS atribuída/autorizada D | IDOR e dados operacionais alheios | JWT + política por recurso |
| O12 | OrdemServicoController | GET `/api/v1/ordens-servico` | Pesquisar OS paginadas | Basic/aut | C, A, M, G | Interseção obrigatória com P/S; filtros opcionais não são autorização | Consulta global e contagem de OS alheias | JWT + restrição no repositório antes da paginação |
| O13 | OrdemServicoController | GET `/api/v1/ordens-servico/{id}/historico` | Histórico de status | Basic/aut | C, A, M, G | Mesma política da OS | Vazamento de histórico/correlação | JWT + autorizar OS antes do histórico |
| O14 | OrdemServicoController | GET `/api/v1/ordens-servico/{id}/saga` | Inspecionar Saga | Basic/aut | G | S + necessidade operacional D; C/A/M negados | Exposição de `lastError` e estado interno | JWT + acesso gerencial delimitado + rede |

O02 não concede automaticamente ao cliente seu cadastro integral: não foi requisito de autoatendimento e o DTO contém PII. Se necessário, aprovar finalidade e campos antes de permitir. O05/O06 já atendem consulta dos veículos próprios.

### 3.2 Execution — 11 rotas (E-HTTP/E-SEC)

| ID | Controller | Método e caminho completo | Operação | Atual: autenticação/autorização | Papéis recomendados | Propriedade/condição adicional | Risco atual | Alteração 8.3.3 |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| E01 | DiagnosticController | GET `/api/v1/diagnosticos/{id}` | Consultar diagnóstico | Basic/aut | M | S da OS resolvida pelo agregado | Diagnóstico/preços alheios | JWT + M + autorizar diagnostic.osId |
| E02 | DiagnosticController | GET `/api/v1/diagnosticos?osId={uuid}` | Consultar diagnóstico da OS | Basic/aut | M | S, mesmo para consulta por parâmetro | IDOR por OS | JWT + M + autorizar osId |
| E03 | DiagnosticController | POST `/api/v1/diagnosticos/{id}/itens` | Registrar item e preço previsto | Basic/aut | M (D) | S + política de estimativa de preço aprovada; IN_PROGRESS | Manipulação técnica com efeito financeiro | JWT + M + escopo + regra de preço D |
| E04 | DiagnosticController | PATCH `/api/v1/diagnosticos/{id}/observacoes` | Atualizar observações | Basic/aut | M | S; PENDING/IN_PROGRESS | Adulteração técnica | JWT + M + escopo + estado existente |
| E05 | DiagnosticController | POST `/api/v1/diagnosticos/{id}/conclusao` | Concluir diagnóstico/emitir evento | Basic/aut | M (D) | S; itens válidos e preços autorizados; IN_PROGRESS | Disparar orçamento com itens indevidos | JWT + M + validação técnica/estimativa |
| E06 | RepairController | GET `/api/v1/reparos/{id}` | Consultar reparo | Basic/aut | M | S do repair.osId | IDOR e informação técnica | JWT + M + autorizar OS |
| E07 | RepairController | GET `/api/v1/reparos?osId={uuid}` | Consultar reparo da OS | Basic/aut | M | S | Consulta técnica alheia | JWT + M + autorizar osId |
| E08 | RepairController | PATCH `/api/v1/reparos/{id}/observacoes` | Registrar execução | Basic/aut | M | S; PENDING/IN_PROGRESS conforme domínio | Adulteração do registro de reparo | JWT + M + escopo/estado |
| E09 | RepairController | POST `/api/v1/reparos/{id}/conclusao` | Concluir reparo/emitir evento | Basic/aut | M | S; somente IN_PROGRESS, iniciado por comando legítimo | Conclusão indevida e cobrança derivada | JWT + M + escopo antes da transação |
| E10 | ExecutionHistoryController | GET `/api/v1/execucoes/historico?osId={uuid}` | Consultar histórico técnico | Basic/aut | M | S; autorizar mesmo se resultado vazio | Histórico técnico de terceiros | JWT + M + escopo da OS |
| E11 | BootstrapStatusController | GET `/internal/bootstrap` | Status técnico do bootstrap | Basic/aut | — | Identidade de serviço/operador técnico autorizada + rede | Reconhecimento técnico | Retirar de acesso humano comum; canal interno |

Cliente e atendente acompanham andamento pelos endpoints OS O11/O13. Não abrir os DTOs técnicos completos automaticamente. Consulta gerencial técnica detalhada depende de finalidade aprovada; GERENTE não recebe escrita técnica nem leitura irrestrita por herança.

### 3.3 Billing — 9 rotas (B-HTTP/B-SEC)

| ID | Controller | Método e caminho completo | Operação | Atual: autenticação/autorização | Papéis recomendados | Propriedade/condição adicional | Risco atual | Alteração 8.3.4 |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| B01 | OrcamentoController | GET `/api/v1/orcamentos/{id}` | Consultar orçamento | Basic/aut | C, G | C: P da OS do orçamento; G: S financeiro | Orçamento alheio | JWT + papel + resolver orçamento.osId |
| B02 | OrcamentoController | GET `/api/v1/orcamentos?osId={uuid}` | Consultar orçamento por OS | Basic/aut | C, G | P/S | IDOR financeiro por query | JWT + autorizar osId |
| B03 | OrcamentoController | GET `/api/v1/orcamentos/{id}/aprovacao` | Consultar decisão | Basic/aut | C, G | P/S da OS do orçamento, inclusive sem decisão | Exposição de decisão/identidade declarada | JWT + autorizar antes da consulta |
| B04 | OrcamentoController | POST `/api/v1/orcamentos/{id}/aprovar` | Aprovar orçamento | Basic/aut + CSRF | C (D) | P atual + consentimento aprovado + estado válido | Qualquer Basic decide por terceiro; responsavelId forjável | JWT + C + P dinâmica + ator derivado de sub |
| B05 | OrcamentoController | POST `/api/v1/orcamentos/{id}/rejeitar` | Rejeitar orçamento | Basic/aut + CSRF | C (D) | P atual + consentimento aprovado + motivo/estado | Rejeição de OS alheia e cancelamento da Saga | Mesmos controles B04; preservar evento/transação |
| B06 | PagamentoController | GET `/api/v1/pagamentos/{id}` | Consultar pagamento/tentativas | Basic/aut | C, G | C: P de pagamento.osId; G: S financeiro | Dados financeiros alheios | JWT + papel + P/S |
| B07 | PagamentoController | GET `/api/v1/pagamentos?osId={uuid}` | Listar pagamentos da OS | Basic/aut | C, G | P/S; autorizar também lista vazia | Enumeração financeira | JWT + autorizar osId antes de listar |
| B08 | CheckoutController | POST `/api/v1/pagamentos/{id}/checkout` | Criar/recuperar checkout | Basic/op + CSRF | C (D) | P atual + política explícita de checkout; orçamento aprovado e pagamento elegível | Operador genérico atua em qualquer pagamento | Migrar apenas após aprovação da substituição de BILLING_OPERATOR; JWT + P dinâmica |
| B09 | MercadoPagoWebhookController | POST `/api/v1/webhooks/mercado-pago` | Receber notificação externa | HMAC; exceção CSRF só nesta rota POST | — | HMAC/tempo/IDs + receipt + consulta verificada ao provedor | Falsificação/replay se proteção própria for contornada | Preservar HMAC; nenhum JWT final exigido |

Atendente não recebe acesso financeiro integral por padrão; eventual consulta operacional de orçamento exige aprovação específica. Gerente consulta finanças da área, mas não aprova em nome do cliente nem confirma pagamento. Não existe endpoint de reconciliação, redrive, refund ou ajuste de preço: são operações internas/operacionais, não rotas omitidas do inventário.

## 4. Matriz consolidada, justificativas e menor privilégio

`P` = recurso próprio comprovado dinamicamente; `S` = escopo operacional comprovado; `D` = condicionado à aprovação descrita em 12; `N` = negar. A combinação de papéis permite somente a união das permissões explícitas aplicáveis ao alvo, nunca elimina P/S ou segregação. Sem papel: nenhuma operação de negócio.

| Permissão / serviço responsável | CLIENTE | ATENDENTE | MECANICO | GERENTE | Necessidade e condições |
| --- | --- | --- | --- | --- | --- |
| Cadastrar/consultar clientes — OS O01–O03 | N | S | N | N | Atendimento precisa identificar cliente; acesso mínimo a PII, escopo D |
| Cadastrar veículos — OS O04 | N | S | N | N | Vincular veículo a cliente ativo durante atendimento |
| Consultar veículos — OS O05–O06 | P | S | N | N | Autoatendimento e identificação operacional; não ampliar por placa/CPF |
| Cadastrar filial — OS O07 | N | N | N | S,D | Administração organizacional delegada, sem autoconcessão |
| Consultar filiais — OS O08–O09 | N | S | N | S | Operação e gestão da área autorizada |
| Abrir OS — OS O10 | N | S | N | N | Atendimento inicia processo com relação cliente/veículo consistente |
| Consultar OS/status — OS O11–O13 | P | S | S,D | S | Cliente acompanha; atendimento opera; mecânico executa OS autorizada; gestão acompanha área |
| Inspecionar Saga — OS O14 | N | N | N | S,D | Suporte gerencial delimitado; lastError pode revelar detalhes |
| Consultar diagnóstico/reparo/histórico — Execution E01/E02/E06/E07/E10 | N | N | S,D | N | Trabalho técnico; atribuição/escopo ainda sem modelo |
| Registrar item técnico — Execution E03 | N | N | S,D | N | Insumos do diagnóstico; inclui estimativa de preço, exige decisão explícita |
| Alterar observações técnicas — Execution E04/E08 | N | N | S,D | N | Registrar diagnóstico/execução nos estados já válidos |
| Concluir diagnóstico — Execution E05 | N | N | S,D | N | Produz orçamento; estimativa técnica deve estar autorizada |
| Concluir reparo — Execution E09 | N | N | S,D | N | Confirma trabalho autorizado pela Saga; atendimento/gestão não herdam |
| Consultar orçamento/decisão — Billing B01–B03 | P | N | N | S | Cliente avalia sua contratação; gerente acompanha sua área |
| Aprovar/rejeitar orçamento — Billing B04–B05 | P,D | N | N | N | Consentimento do contratante; decidir representação/usuários compartilhados |
| Consultar pagamentos — Billing B06–B07 | P | N | N | S | Acompanhar obrigação própria e controle financeiro da área |
| Criar/recuperar checkout — Billing B08 | P,D | N | N | N | Pagador próprio, substituição explícita da autorização legada |
| Confirmar pagamento, reconciliar, processar comandos — internos | N | N | N | N | Responsabilidade de workers/consumidores confiáveis e provedor verificado |
| Gerenciar papéis/vínculos — Auth, fluxo futuro | N | N | N | N | ProvisioningAuthorization confiável e auditada; GERENTE sozinho insuficiente |
| Bootstrap técnico — Execution E11 | N | N | N | N | Identidade técnica específica, fora do RBAC humano |

Não existem indicadores gerenciais agregados nos controllers atuais. O acesso gerencial proposto refere-se às consultas existentes, não à entrega de um dashboard novo. Não incluir acesso universal a PII para suprir indicadores ausentes.

## 5. Propriedade e escopo operacional

### 5.1 Relações verificadas no código

`JWT.sub → Usuario.id → UsuarioCliente.clienteId → Cliente.id → Veiculo.clienteId → OrdemServico` é uma composição entre fontes independentes, não uma consulta SQL distribuída.

- Auth conhece usuário, ativo, papéis e vínculo lógico. `Usuario.podeAcessarCliente` exige ativo, CLIENTE e vínculo real.
- OS é autoridade de cliente, veículo e OS. `O application/usecase/OrdemServicoUseCase.java` carrega os três agregados ao abrir; `O domain/OrdemServico.java::abrir` exige cliente/filial ativos e `veiculo.pertenceAoCliente(cliente.id)`.
- OS guarda **clienteId e veiculoId na OS**, além de filialId. A raiz da autorização histórica recomendada é **OS.clienteId**, persistida na contratação, e não o proprietário atual do veículo isoladamente.
- Veículo próprio é verificado por `Veiculo.clienteId`. A integridade veículo-cliente é obrigatória na abertura. Transferir veículo futuramente não deve entregar automaticamente OS, orçamento e pagamentos antigos ao comprador. Não há fluxo de transferência exposto hoje; definir política antes de introduzi-lo.
- Billing (`Orcamento`, `Pagamento`) e Execution (`Diagnostic`, `Repair`) relacionam recursos por osId. Um UUID de orçamento/diagnóstico não comprova acesso: resolver o osId do agregado local e autorizar a OS real.

Regra proposta para cliente: JWT válido + ROLE_CLIENTE + usuário atualmente ativo/CLIENTE no Auth + vínculo vigente com OS.clienteId + operação permitida + estado de negócio válido. Para veículos, substituir OS.clienteId por Veiculo.clienteId. ClienteId enviado em query/body é apenas filtro/alvo, nunca evidência.

Para listas, obter conjunto autorizado e intersectar filtros no banco OS **antes** de paginar/contar. Filtro de outro cliente resulta em negação uniforme; ausência de filtro não permite pesquisar tudo. Não buscar toda a oficina e filtrar em memória. Vínculo inexistente deve negar acesso, inclusive quando o registro/lista não existe.

### 5.2 Comparação das alternativas

| Alternativa | Segurança e acoplamento | Latência/disponibilidade | Consistência, cache e revogação | Complexidade e Lambda/Kubernetes |
| --- | --- | --- | --- | --- |
| Consulta autenticada ao Auth usando API genérica de usuário | Só é segura com autenticação de serviço e campos mínimos; uma API genérica amplia PII e acopla consumidor ao agregado de identidade | Chamada remota nos acessos dependentes de propriedade; Auth indisponível bloqueia esses acessos | Pode refletir estado atual; cache positivo cria janela de revogação | Integração simples, mas API genérica pública/interna ainda não existe; Lambda funciona via HTTPS com cold starts e pool controlado |
| API interna mínima de resolução de vínculos | Mesma consulta síncrona, mas contrato específico limita dados e callers; Auth não decide domínio OS | Acréscimo de uma chamada OS→Auth; Billing/Execution passam antes pelo OS; falha fechada | Consulta atual sem cache positivo inicial; permite observar inativação; revogação de vínculo precisa primeiro existir | **Recomendada inicialmente**; sem novo serviço, compatível com API Gateway/Lambda e Service privado K8s |
| Projeção local de vínculos por eventos | Reduz consultas e mantém independência; requer eventos autenticados, versões, bootstrap, deduplicação e proteção da réplica | Baixa latência e leitura disponível sem Auth após sincronização | Eventual; remoção atrasada pode manter acesso. Exige SLA de lag, tombstones, invalidação, ressincronização e bloqueio por projeção atrasada | Auth ainda não publica eventos de identidade nem possui esse Outbox; maior custo, publisher Lambda e consumidores K8s adicionais |
| Serviço específico de autorização | Pode uniformizar políticas, mas centraliza privilégios e exige proteger contexto/alvos e autoria | Nova dependência remota crítica/cache e operação HA | Depende de fontes atualizadas; centralizar não elimina consistência/revogação | Desproporcional para três serviços neste estágio; **não criar**, exigiria justificativa e aprovação |

### 5.3 Recomendação de integração futura, ainda não implementada

1. Criar, após aprovação separada, **contrato interno mínimo no Auth** para resolver/validar os vínculos de um usuário autenticado, ativo e CLIENTE, retornando apenas IDs autorizados e estado necessário. Sem hash, email, CPF ou acesso ao banco OS. Não reutilizar uma consulta pública irrestrita de usuários. Nenhuma rota nova é criada nesta etapa.
2. OS recebe a requisição HTTP, valida JWT localmente, aplica RBAC e consulta o Auth **somente quando a decisão precisar de vínculo atual**. Consulta aos dados Auth é pelo adapter de uma porta de aplicação, sem dependência de banco. Auth não recebe ordem para consultar a OS.
3. Para Billing/Execution, o adapter de autorização chama um contrato interno do OS, que verifica o alvo, filial/propriedade e ação. O consumidor determina osId pelo recurso local; o frontend não escolhe o proprietário. OS delega resolução de vínculos ao Auth quando o ator é cliente. OS não passa a decidir transições financeiras/técnicas: cada domínio mantém sua política local.
4. Contratos internos devem autenticar **o serviço chamador e o usuário em nome de quem atua**, por canais separados. Proposta inicial: mTLS para serviço, JWT original propagado para usuário e revalidado no destino; endpoint interno só acessível a serviços permitidos. Alternativa AWS: assinatura SigV4 em API Gateway IAM + JWT do usuário como contexto assinado/verificado no destino. Não confiar em `X-User-Id`, `X-Roles` ou no mero sub declarado pelo serviço/browser. Valores de headers/rota ainda serão definidos em contrato aprovado.
5. Limitar serviço→ação: Billing só consulta autorização das operações financeiras da OS; Execution só escopo técnico; OS só resolução de vínculos. Decisão ligada a `(serviço, sub, ação, osId/clienteId, instante)`; não reutilizar aprovação de leitura para escrita nem para outro recurso. Não devolver um booleano genérico reutilizável pelo frontend. Evitar deputy com poderes amplos e não expor API de enumeração.
6. Inicialmente **sem cache positivo de vínculos ou decisões de negócio**; reduz complexidade de invalidação. Cada requisição de propriedade usa leitura atual do Auth, sem confundir isso com validação criptográfica do JWT. Timeout inicial proposto: conexão 1 s, leitura 2 s por dependência, orçamento total de autorização até 5 s; sem retries indiscriminados ou cache stale. Medir em Lambda e ajustar antes de produção.
7. Inacessibilidade/timeout não é ausência de vínculo: responder 503 sanitizado e não executar efeito; negação comprovada: 403, ou 404 uniforme para consulta individual a recurso alheio conforme política de não enumeração. Não transformar falha remota em permissão ou resultado vazio que esconda indisponibilidade.
8. Realizar autorização imediatamente antes da operação local. Não existe atomicidade global com a leitura Auth: revogação concorrente após a decisão ainda cria uma janela até o commit. Não prometer revogação instantânea serializável; se exigida para finanças, aprovar mecanismo específico de versão/decisão de curta validade e protocolo de revogação.

Essa abordagem **não consulta banco Auth para validar assinatura a cada HTTP**. Rotas que só precisam de JWT/RBAC continuam locais. Rotas que precisam de vínculo consultam explicitamente uma fonte dinâmica, por outro motivo. Bibliotecas Spring não devem chamar Auth implicitamente em todo decode.

### 5.4 Lacuna de escopo dos funcionários

Não há filial/atribuição de mecânico/escopo financeiro no JWT. Os modelos examinados também não implementam uma política usuário→filial ou mecânico→OS. Papel sozinho não garante os escopos S das tabelas.

Antes de habilitar S, aprovar a fonte de escopo. Proposta inicial mínima: configuração operacional auditada, administrada fora das APIs de usuário, associando sub a filiais e, no Execution, OS explicitamente autorizadas. Sem configuração correspondente, negar. Uma liberação para toda a oficina somente pode ocorrer como decisão explícita de negócio para sujeitos nomeados; não usar fallback de filial ausente = todas. Evolução para atribuição persistente exigirá outra especificação e eventual alteração de modelo/migração, fora desta análise.

Consultas gerenciais e financeiras exigem escopo do gerente, assim como técnicos exigem atribuição ou autorização explícita. A infraestrutura de resolução de escopo e eventual checagem dinâmica de ativo para funcionários são dependências a aprovar; não estão prontas por existir `ROLE_GERENTE`.

## 6. Arquitetura JWT/JWKS recomendada

Usar Spring Security OAuth2 Resource Server nos três serviços, com as dependências gerenciadas pelo BOM real de Boot 4.1.1. O BOM `spring-boot-dependencies:4.1.1`, conferido no cache Maven local, gerencia Spring Security **7.1.1**. O starter específico dessa versão é `spring-boot-starter-security-oauth2-resource-server`; conferir `dependency:tree` na implementação para a resolução efetiva de Spring Security/Nimbus, sem fixar bibliotecas transitivas ou copiar exemplos Boot 3/Security 6 cegamente. O projeto já usa Jackson 3 em controllers de Billing; não introduzir mistura de ObjectMappers para segurança.

`NimbusJwtDecoder` com JWKS HTTPS fixado por ambiente, algoritmo RS256 explícito, validators compostos e `JwtAuthenticationConverter`. Configurar **jwk-set-uri explícito + validação do issuer esperado**. O Auth não publica metadata OIDC; configurar somente issuer-uri com discovery presumido não atende ao contrato atual. O Auth fornece login próprio, não um servidor OAuth/OIDC completo nem client_credentials; Resource Server pode validar seu JWT sem transformar Auth em outro framework.

### Contrato obrigatório de validação

| Verificação | Política proposta |
| --- | --- |
| Transporte | `Authorization: Bearer`; TLS; não aceitar token em URL, body ou cookie como alternativa implícita |
| Algoritmo/assinatura | Somente RS256/RSA; rejeitar none, HS256, RS384 e demais; verificar assinatura antes de usar claims |
| Seleção de chave | kid não vazio e único correspondente no JWKS confiável, kty RSA/use sig/alg compatíveis; falhar se desconhecido/ambíguo; nunca seguir jku/x5u fornecido pelo token |
| Emissor | iss obrigatório e idêntico ao aprovado; sem normalizar host/trailing slash |
| Audiência | aud obrigatório, array contendo o identificador esperado; não basta emissor confiável |
| Tempo | exp, nbf, iat obrigatórios; exp > iat, nbf coerente, TTL máximo 900 s; rejeitar exp vencido/nbf futuro fora de tolerância; iat não futuro fora de tolerância |
| Relógio | Skew proposto 30 s, nunca acima de 60 s do contrato Auth; NTP em hosts/nodes e Clock controlado em testes |
| Subject/jti | sub UUID canônico não vazio (`UUID.fromString` + igualdade com representação canônica); jti UUID presente; não derivar cliente/CPF a partir deles |
| Papéis | roles array de strings da allowlist exata; forma inválida/papel desconhecido rejeita autenticação; lista vazia autentica sem permissão de negócio (403) |
| Erros | Ausente/inválido: 401 com desafio Bearer; papel insuficiente: 403; falha de infraestrutura: erro controlado, nunca acesso anônimo; não retornar token/stacktrace |

O validador de schema deve verificar tipos antes de conversões permissivas da biblioteca, e exigir claims que validadores temporais padrão podem tratar como opcionais. Audience e UUID não devem ser presumidos a partir dos defaults. Não confiar em `authenticated()` para usuário com roles vazias. A decisão de audiência inicial recomendada é um identificador lógico compartilhado da API oficina, compatível com o emissor que hoje emite uma audiência única. Isso permite apresentar o mesmo token aos três serviços, mas **não** concede todas as operações. Audiências exclusivas por serviço exigiriam evolução aprovada no emissor e propagação, não apenas três configurações divergentes.

### Authorities e posicionamento hexagonal

Converter `roles: ["MECANICO"]` em `ROLE_MECANICO`, com `JwtGrantedAuthoritiesConverter` configurado para claim `roles`/prefixo `ROLE_` e validador da allowlist. Usar consistentemente `hasRole("MECANICO")` ou `hasAuthority("ROLE_MECANICO")`; não prefixar duas vezes, não mapear para `SCOPE_`, não criar RoleHierarchy automática. Não mapear GERENTE para BILLING_OPERATOR.

Filtro de segurança faz autenticação e regras por método/caminho; políticas por recurso ficam em portas/serviços de aplicação que recebem contexto autenticado mínimo (sub, papéis, tipo do ator). Adapters traduzem Spring Security para contexto; domínio não depende de SecurityContextHolder. Proteger entradas HTTP e distinguir entradas internas confiáveis de consumidores; não colocar `@PreAuthorize` indiscriminado em use case também chamado por RabbitMQ, pois o listener não possui usuário HTTP. Nenhum bypass por argumento booleano controlado pelo cliente.

### Cache de JWKS e indisponibilidade

Proposta: cache compartilhado por instância/pod, TTL efetivo máximo **60 s**, alinhado ao header Auth; não usar default da biblioteca sem verificá-lo. Cache HTTP/decoder deve ter prazo combinado controlado, sem somar cinco minutos ocultos. Não há chaves privadas em consumidores.

- Com chave conhecida em cache ainda válido, validar localmente mesmo com Auth temporariamente indisponível.
- Em cache ausente/expirado ou kid novo, atualizar por HTTPS confiável com timeout limitado. Propor conexão/leitura de até 2 s, refresh concorrente consolidado e limitação de tentativas por kid desconhecido para evitar DoS.
- Se atualização não permitir validar, negar acesso; não usar cache expirado indefinidamente. Classificar indisponibilidade do fetch como 503 controlado quando distinguível, token/chave desconhecida após fetch bem-sucedido como 401. Nenhuma falha habilita Basic/anonimamente como fallback.
- Cold start/pod novo precisa obter JWKS antes de aceitar Bearer; não confundir readiness da aplicação com autorização já aquecida. Medir e testar comportamento real do decoder e cache na versão gerenciada.
- Auth prepara nova chave 90 s antes da assinatura; mantém antiga até pelo menos signUntil + 1.050 s. Fontes: `A infrastructure/security/RotatingKeyProvider.java`, `KeyDocuments.java` e `docs/authentication.md`. Preservar esses limites ao parametrizar cache/skew.
- Retirada emergencial de chave comprometida requer invalidar caches e procedimento operacional auditado. Rotação normal não revoga tokens individuais.

Nenhum pod consulta banco Auth para verificar JWT. Não haverá autorização dinâmica de inatividade/papéis de funcionários em todos os requests por efeito do Resource Server. Essa limitação é explícita e deve ser aceita ou receber solução separada.

Referências oficiais para a implementação: [Resource Server JWT](https://docs.spring.io/spring-security/reference/servlet/oauth2/resource-server/jwt.html), [starter no código Boot 4.1.1](https://github.com/spring-projects/spring-boot/blob/v4.1.1/starter/spring-boot-starter-security-oauth2-resource-server/build.gradle). Os limites adicionais de schema/cache/roles acima são decisões propostas do projeto, não garantias automáticas desses componentes.

## 7. Mensageria e modelo de confiança

### 7.1 Topologia efetiva

Fontes: O/E/B `infrastructure/messaging/RabbitMessagingConfig.java`, `RabbitMessageBrokerAdapter.java`, `OutboxPublisher.java`; O `SagaEventConsumer.java`; E/B `CommandConsumer.java`, `MessageCodec.java`; respectivos `application/message/*`, O `application/saga/*` e `domain/DiagnosticStartEnvelope.java`. Documentação confrontada: O `docs/events.md`, `docs/saga.md`, E/B `docs/messaging.md`.

Defaults (OS permite sobrescrever nomes via `oficina.messaging`; validar configuração real no ambiente):

| Exchange topic durável | Routing keys | Filas/consumidor | Efeito |
| --- | --- | --- | --- |
| `oficina.commands` | `diagnostic.start.v1` | `execution.diagnostic.start` / E CommandConsumer | Criar/iniciar diagnóstico |
| `oficina.commands` | `repair.start.v1` | `execution.repair.start` / E CommandConsumer | Autorizar/iniciar reparo após decisão |
| `oficina.commands` | `repair.cancel.v1` | `execution.repair.cancel` / E CommandConsumer | Tentar compensação conforme estado físico |
| `oficina.commands` | `quote.create.v1` | `billing.quote.create` / B CommandConsumer | Criar orçamento com itens do diagnóstico |
| `oficina.commands` | `payment.request.v1` | `billing.payment.request` / B CommandConsumer | Criar intenção de pagamento |
| `oficina.events` | `diagnostic.started.v1`, `diagnostic.completed.v1`, `diagnostic.failed.v1`, `repair.started.v1`, `repair.completed.v1`, `repair.failed.v1`, `repair.cancelled.v1`, `repair.cancellation-failed.v1` | `os.saga.events`, binding `#.v1` / O SagaEventConsumer | Resultados técnicos para orquestração |
| `oficina.events` | `quote.created.v1`, `quote.creation-failed.v1`, `quote.approved.v1`, `quote.rejected.v1`, `payment.confirmed.v1`, `payment.failed.v1` | Mesma fila OS / O SagaEventConsumer | Decisões e resultados financeiros |
| `execution.commands.retry` | Mesmas 3 keys de comando Execution | `execution.diagnostic.start.retry`, `execution.repair.start.retry`, `execution.repair.cancel.retry` | TTL retorna a oficina.commands |
| `execution.commands.dlx` | Binding `#` | `execution.commands.dlq` | Recuperação explícita de mensagens rejeitadas |
| `billing.commands.retry` | Mesmas 2 keys de comando Billing | `billing.quote.create.retry`, `billing.payment.request.retry` | TTL retorna a oficina.commands |
| `billing.commands.dlx` | Binding `#` | `billing.commands.dlq` | Rejeições/limite de tentativas |
| `oficina.events.dlx` | `saga.events.dead` | `os.saga.events.dlq` | Dead-letter de os.saga.events |

OS tem um único `application/saga/OrdemServicoSagaOrchestrator.java`; `SagaEventHandler` aplica eventos e gera comandos na Outbox. Execution usa `application/usecase/CommandHandler.java` e Billing `application/usecase/CommandHandler.java`. Publishers leem Outbox e usam broker adapters, não HTTP de usuário. Diagnóstico concluído leva a quote.create; quote.approved leva a repair.start; repair.completed leva a payment.request; payment.confirmed finaliza a OS. payment.failed mantém espera de pagamento, sem desfazer reparo físico.

Envelope: `eventId`, `eventType`, `occurredAt` ISO-8601, `correlationId`, `sagaId`, `osId`, `source`, `payload`. eventId identifica deduplicação; correlationId rastreia; sagaId/osId identificam execução/alvo; **nenhum é credencial**. E/B codecs verificam source=os-service e eventType=routing key. O `SagaEventHandler.validateEnvelopeFields` não autentica source/produtor: não tratar seu campo `source` como garantia criptográfica. A segurança da publicação precisa existir no broker.

Contratos relevantes: diagnostic.start contém clienteId/veiculoId/filialId/observacoes; diagnostic.completed contém itens com quantidade/precoPrevisto em strings decimais; quote.create transporta `items` suficientes para orçamento; repair.start tem payload vazio; repair.cancel contém reason; payment.request contém somente `repairId` no payload, com OS/Saga no envelope. Billing resolve o orçamento aprovado e o valor em seu próprio domínio (`CommandHandler.requestPayment`), sem aceitar valor de pagamento declarado na mensagem. Eventos de resultado preservam correlação/Saga. Consultar os records/serializers para o schema completo; não acrescentar claims/tokens nesta etapa.

### 7.2 Autorização do transporte e dos comandos

Não anexar nem exigir JWT de usuário nas mensagens. Um token expira durante retry e não representa a autorização de compensar, reconciliar ou concluir um comando previamente aceito. Papéis humanos autorizam a entrada HTTP; identidade do microsserviço autoriza publicação/consumo; domínio valida o comando interno. Não colocar JWT nos envelopes/Outbox/logs.

| Identidade de serviço | Publicação autorizada proposta | Consumo autorizado proposto |
| --- | --- | --- |
| OS | oficina.commands: as 5 keys de comandos inventariadas | os.saga.events |
| Execution | oficina.events: somente diagnostic.* e repair.* inventariados; seu retry/DLX restrito às próprias keys | Suas 3 filas principais |
| Billing | oficina.events: somente quote.* e payment.* inventariados; seu retry/DLX restrito às próprias keys | Suas 2 filas principais |
| Provisionador/operador | Declarações/topologia e redrive somente por procedimento auditado | DLQs/inspeção conforme atribuição explícita |

Proteger com credenciais distintas por serviço e ambiente, vhost compartilhado da oficina por ambiente (isolado de outros sistemas), TLS com verificação de certificado, rede privada/NetworkPolicy/SG e management restrito. Não reutilizar guest, senhas locais ou credencial administrativa no runtime. Permissões configure/read/write por recurso **e topic permissions por routing key** são necessárias: permitir escrita em oficina.events inteira permitiria ao Execution forjar payment.confirmed. Restringir também escrita no default exchange e filas alheias para evitar contornar exchanges por publicação direta. Fonte: [controle de acesso RabbitMQ](https://www.rabbitmq.com/docs/access-control).

Coordenar redução de configure com as declarações dinâmicas atuais: provisionar topologia separadamente e adaptar autodeclaração em etapa aprovada antes de retirar grants; não interromper startup. Validar permissões necessárias ao dead-letter TTL com a identidade responsável e sem conceder publicação arbitrária em comandos aos workers. Broker e provisionador podem encaminhar retry autorizado; isso não é novo comando humano. Não adicionar argumentos incompatíveis às filas existentes sem migração coordenada.

Mensagem válida de produtor confiável segue processamento interno normal: validar schema/versão/key, identidade autorizada no transporte, consistência OS/Saga, invariantes/estado, Inbox, transação local e Outbox. Não exigir SecurityContext HTTP, não checar se o usuário original ainda tem token válido para aplicar resultado financeiro já verificado. Cancelar autorização humana futura não apaga obrigação financeira/trabalho físico já contratado.

Preservar at-least-once e deduplicação, locks/leases, confirms e mandatory. E/B fazem encaminhamento confirmado para retry/DLQ; Billing usa ACK manual e Execution retorno do container após transação. Falha de autorização de publicação no broker deve manter Outbox recuperável, nunca marcar publicado sem confirmação. Reentrega não repete efeito financeiro. Auditar redrive sem apagar Inbox/ledger, alterar contratos ou introduzir outro orquestrador.

## 8. Billing, Mercado Pago e CSRF

### Proteções existentes que constituem baseline

`B infrastructure/config/SecurityConfig.java` exige `hasRole("BILLING_OPERATOR")` **somente** em POST `/api/v1/pagamentos/*/checkout`. Aprovar/rejeitar não exigem esse papel: usam authenticated + CSRF. `B infrastructure/web/security/CsrfTokenResponseFilter.java` expõe token mascarado em `X-CSRF-TOKEN` nos GET `/api/v1/**`, com sessão usada pelo mecanismo padrão. CSRF pode produzir 403 antes da avaliação Basic em POST sem token.

`B application/usecase/DecidirOrcamentoUseCase.java` aceita `responsavelId` do comando, verifica existência/decisão única/estado, grava aprovação e Outbox. Não vincula esse campo ao usuário autenticado. Nas próximas etapas, o ator auditável deve ser derivado de JWT.sub; manter campo REST por compatibilidade só como declaração não confiável ou exigir igualdade quando fornecido, decisão a aprovar. Não continuar persistindo impersonação como identidade comprovada. Adaptar testes que hoje esperam `id-informado`; não alterar contrato nesta etapa.

`B application/payment/ProviderTransactions.java::reserveCheckout` exige pagamento PENDING/PROCESSING, orçamento APPROVED e igualdade de valor/OS/Saga, antes da reserva. `PaymentWorkflow` mantém reserva/HTTP/finalização, tratamento UNKNOWN e reconciliação. A checagem de propriedade deve preceder a reserva/chamada externa e ser adicional a essas invariantes, sem refatorar o fluxo de idempotência/Outbox.

### Migração proposta sem redução silenciosa de privilégio

Não substituir BILLING_OPERATOR por `authenticated()` nem GERENTE indiscriminadamente. O Auth só emite os quatro papéis definidos. Escolha proposta: checkout de autoatendimento para CLIENTE com propriedade atual e finalidade explícita, após aprovação D. Até essa decisão, preservar rota legada restrita à rede/operadores com Basic + BILLING_OPERATOR + CSRF ou negar checkout no canal JWT; não criar alias automático de papéis. A coexistência legada deve ter prazo e plano de retirada, sem abrir canal público Basic.

Aprovação/rejeição pelo CLIENTE depende de regra de consentimento aprovada. Atendente/gerente não decidem por ele automaticamente. Caso representação seja necessária, exigir autorização delegada explícita e trilha de quem consentiu/quem executou em especificação própria. Negar enquanto pendente.

### Política CSRF por canal

- API exclusivamente Bearer em header, stateless, sem aceitar sessão/cookie/Basic como autenticação alternativa: CSRF pode ser dispensado **nesse canal delimitado**, pois credencial não é enviada automaticamente pelo navegador. CORS restrito e TLS continuam necessários; não armazenar Bearer em cookie sem reavaliar a política.
- Canal legado ou futuro com sessão/cookie, inclusive Basic enviado automaticamente por navegador: manter CSRF e sessão/token coerentes. Não usar a mera presença de `Authorization: Bearer` para dispensar CSRF e depois autenticar por cookie quando o Bearer falhar.
- Se coexistirem canais, separar filter chains/matchers com credenciais aceitas e ordem testadas: Bearer inválido falha, não cai no Basic; uma requisição não deve combinar autenticação de um canal com relaxamento CSRF de outro. Nenhuma cadeia secundária ampla pode aceitar negócio por authenticated sem a mesma política de recurso.
- A exceção exata de POST do webhook permanece separada. Não desabilitar CSRF globalmente no Billing para facilitar migração/testes.

Referência: [proteção CSRF no Spring Security](https://docs.spring.io/spring-security/reference/servlet/exploits/csrf.html). A separação acima é proposta de desenho; o código atual usa uma única chain.

### Webhook e workers financeiros

`B infrastructure/payment/MercadoPagoSignatureVerifier.java` valida HMAC-SHA256, ts/v1, formato de data.id/x-request-id, janela temporal padrão 5 min e comparação constante. Controller verifica tipo payment e igualdade de IDs query/body; `ProviderTransactions.receive` persiste receipt antes do 200. Assinatura inválida: 401; formato/IDs inconsistentes: 400; falha de persistência: 500; integração desligada: indisponibilidade controlada. Não exigir JWT final do Mercado Pago, nem usar sessão para esse POST.

`PaymentReconciliationScheduler`, `PaymentWorkflow.processNotification/processDue` e `ProviderTransactions.apply` consultam provedor e validam referência, moeda, valor, tentativa/preferência e modo de teste; confirmação não vem de status declarado no body. Preservar deduplicação e Outbox transacionais, casos UNKNOWN/REVIEW e pagamentos tardios. Não há endpoint de reconciliação/confirmar manualmente; identidade técnica do worker não é GERENTE. Configurações habilitam integração e varredura explicitamente, desligadas por padrão.

Operações administrativas financeiras futuras exigem segregação, escopo e auditoria próprios; não inventar endpoints ou concessão financeira geral para atender esta matriz. Links de checkout já entregues ao provedor podem continuar ativos após revogação do usuário: bloquear novo HTTP não invalida automaticamente preferências existentes. Manter política de expiração/reconciliação e decidir resposta a revogação sem prometer cancelamento retroativo.

## 9. Riscos e inconsistências identificados

| Risco | Evidência real | Tratamento proposto / limite |
| --- | --- | --- |
| IDOR horizontal em todos os domínios | Consultas por UUID/query sem contexto autenticado nos use cases | RBAC + autorização de alvo; listas/paginação restritas na origem |
| Basic não expressa identidade Auth | O/E SecurityConfig e conta padrão; B user configurável | Resource Server; retirar credenciais temporárias dos negócios no corte |
| Escopo de funcionários ausente | JWT sem filial; use cases não recebem atribuição de operador | Aprovar fonte auditada; negar S não configurado |
| ClienteId lógico não comprova titularidade | UsuarioCliente sem FK externa; VincularClienteUseCase interno | Provisionamento confiável com comprovação fora de CPF; integração futura sem banco compartilhado |
| Dependência de API Auth inexistente | Handler só login/JWKS | Bloqueio explícito para ownership real até contrato interno aprovado/implementado |
| Atribuição do ator financeiro forjável | OrcamentoController passa responsavelId de request | Derivar ator do sub e testar tentativa de impersonação |
| Permissão de preços técnicos ambígua | E AddDiagnosticItemRequest aceita precoPrevisto; diagnostic.completed alimenta orçamento | D sobre estimativa/limites/catálogo; negar E03/E05 até definir |
| BILLING_OPERATOR incompatível com enum Auth | B-SEC e A Papel | Aprovar política de checkout; nenhum mapeamento GERENTE→operador |
| Revogação stateless inexistente | Auth documenta tokens válidos após inativação | TTL curto; vínculo atual ajuda clientes; funcionários exigem aceite do risco ou revogação dinâmica separada |
| Swagger público e Saga.lastError | SecurityConfig e O SagaResponse | Restringir ambiente/rede e operação, sanitização de erros |
| Broker compartilhado permite falsificar eventos se ACL ampla | Exchanges topic compartilhadas e source textual | Credenciais + topic permissions, testar publicações cruzadas negadas |
| Credenciais/AMQP locais não são baseline de produção | application.yml: OS guest/5672; E defaults locais; vhost `/` | TLS, secrets por serviço, vhost por ambiente e rede privada |
| Readiness não cobre Rabbit | application.yml dos três desabilita health rabbit | Monitorar reconnect, lag, DLQ, Outbox FAILED; decidir readiness sem derrubar consumidores por indisponibilidade transitória |
| Documento histórico pode induzir erro | identity.md descreve fase 8.1; B messaging.md antecede MP | Código/commits atuais e authentication.md/mercado-pago.md prevalecem |
| IaC Auth ainda aponta fluxo legado | terraform/lambda.tf, network.tf, iam.tf | Planejar atualização separada; nenhuma aplicação de Terraform nesta etapa |

Não foi executado pentest ou scan de dependências, e não se afirma prontidão de produção por esta revisão estática.

## 10. Rotas públicas, técnicas e administrativas

| Classe/rotas | Estado atual | Proposta de exposição e autenticação |
| --- | --- | --- |
| Auth POST `/api/v1/auth/login` | Sem token anterior, email/senha e rate limiter | Público somente na borda HTTPS API Gateway, throttling/WAF; logs sem senha/token |
| Auth GET `/.well-known/jwks.json` | Público; somente chaves públicas | Público HTTPS, cache limitado; endereço fixado e rede de saída dos consumidores |
| Todos GET `/actuator/health` | permitAll; show-details never; exposure health | Preferir rede interna/probes; se balanceador exigir público, somente status sem detalhes |
| Todos GET `/actuator/health/liveness` e `/actuator/health/readiness` | permitAll e probes habilitados | Kubelet/LB/rede autorizada; sem JWT humano, sem divulgação de dependências/detalhes |
| Todos GET `/swagger-ui/**`, `/v3/api-docs/**` (inclui JSON/config/YAML conforme Springdoc) | permitAll | Desenvolvimento controlado; em produção desabilitar ou exigir identidade técnica/rede; não publicar documentação administrativa irrestrita |
| Execution GET `/internal/bootstrap` | Basic authenticated | Rede interna + identidade de serviço/operador técnico com finalidade explícita; nenhum papel humano genérico |
| Negócios `/api/v1/**` inventariados | Basic, exceto webhook | Bearer + RBAC + alvo/escopo; nenhum negócio público para preservar teste |
| Billing POST `/api/v1/webhooks/mercado-pago` | Público no filtro, HMAC no handler | Acessível ao provedor via HTTPS com HMAC e controles próprios; limite de body/rate na borda |
| Actuator métricas/env/configprops/loggers/heapdump etc. | Não expostos por exposure=health | Permanecer fechados; eventual observabilidade em canal técnico autenticado e restrito |
| `/error`, HEAD/OPTIONS gerados | Framework, sem negócio próprio | Tratamento de erros sem bypass, sem stacktrace; CORS preflight limitado a origens/métodos aprovados |
| APIs internas de vínculo/decisão propostas | **Inexistentes** | Não públicas; autenticação forte do serviço + contexto de usuário verificado; contratos ainda a aprovar |
| Administração de identidade/finanças/redrive | Casos internos/procedimentos, sem API pública | Operador confiável com segregação e auditoria; GERENTE não basta |

No total técnico gerado, há três paths health por serviço e famílias Springdoc; eles não entram nos 34 pares declarados pelos controllers. Restrição por rede não substitui verificação de alvo em negócios. Em K8s, executar probes diretamente no Service/Pod apropriado sem colocar segredo Bearer de usuário no manifesto.

## 11. Decisões arquiteturais propostas

| ADR | Decisão a revisar | Justificativa |
| --- | --- | --- |
| A01 | Resource Server JWT local nos três serviços | Mesmo contrato Auth e verificação criptográfica sem banco remoto por decode |
| A02 | roles→ROLE_, sem hierarquia | Menor privilégio consistente e ausência de promoção implícita de GERENTE |
| A03 | Propriedade histórica por OS.clienteId; veículo obrigatório na integridade de abertura | Evita transferência automática de dados históricos pelo veículo |
| A04 | API interna mínima Auth + decisão de alvo no OS | Fonte de vínculos preservada, sem dependência entre bancos nem novo serviço |
| A05 | Sem cache positivo inicial de vínculo; cache JWKS até 60 s | Consistência de propriedade distinta da disponibilidade criptográfica |
| A06 | Contexto técnico separado de humano em HTTP/Rabbit | Mantém Saga/retry independentes de token final expirável |
| A07 | ACL por key no broker, além de vhost/recursos | Impede serviço técnico de publicar resultado financeiro alheio |
| A08 | Billing Bearer delimitado; legado conserva CSRF; webhook HMAC | Migração sem retirar proteção antes de substituir seu mecanismo |
| A09 | Aprovação/checkout negados até aceite de política de consentimento/operador | Substituição de poder financeiro é decisão explícita |
| A10 | Deny por padrão para rota/método/role/escopo não previsto | Evita futuros controllers protegidos apenas por authenticated |

Nenhuma dessas ADRs está aplicada ao código por esta entrega. Não criar SDK obrigatório que acople versões dos serviços; compartilhar inicialmente contrato escrito e cenários de conformidade. Uma biblioteca pequena de validators/converter pode ser avaliada depois, sem domínio/entidades compartilhados.

## 12. Decisões de negócio pendentes de aprovação

| ID | Decisão necessária | Proposta / comportamento enquanto pendente |
| --- | --- | --- |
| D01 | Quem comprova e administra vínculo usuário-cliente, inclusive cliente empresarial/múltiplos usuários? | Provisionamento separado confiável e auditado; nunca CPF/clienteId autodeclarado; sem vínculo não há acesso próprio |
| D02 | Cliente pode aprovar/rejeitar? Qual usuário representa cliente com vários vínculos? | CLIENTE com vínculo atual; consentimento e representação precisam de aprovação; negar B04/B05 até então |
| D03 | Quem cria checkout e como substituir BILLING_OPERATOR? | Autoatendimento próprio C condicionado; não estender a A/M/G; preservar legado restrito ou negar JWT até decisão |
| D04 | Qual escopo por filial para A/G e por atribuição/OS para M? | Fonte de escopo auditada; sem associação, negar. Não inferir oficina única como autorização global |
| D05 | Mecânico define precoPrevisto? Quais limites e catálogo? | Reconhecer que E03 já aceita preço e E05 propaga a Billing; negar essas capacidades até política aprovada, sem conceder poder financeiro genérico |
| D06 | Gerente pode cadastrar filiais e ler Saga/lastError? | Somente delegação administrativa e área explícitas; negar capacidades pendentes |
| D07 | Quanto tempo um token de funcionário pode sobreviver à inativação/mudança de papel? | Aceite explícito de até TTL + skew, ou aprovar estado dinâmico/revogação antes de operações sensíveis; não prometer revogação atual |
| D08 | Qual política para transferência de veículo, mudança de contratante e desvinculação? | OS histórica permanece com contratante; retirada de vínculo bloqueia novas consultas após decisão atual; definir processo de revogação ainda ausente |
| D09 | Atendente precisa ler orçamento/pagamento ou gerente PII integral? | Negar nesta matriz; aprovar finalidade e dados mínimos antes de ampliar |
| D10 | Qual tolerância para decisão de autorização concorrente com revogação? | Leitura atual imediatamente antes do efeito; sem atomicidade entre serviços; exigência mais forte demanda novo protocolo aprovado |
| D11 | Quais issuer/audience/hosts por ambiente, identidades técnicas e retenção de auditoria? | Fixar em contrato de ambiente; sem valores confiáveis, falhar fechado |

Também exige aprovação técnica a criação futura da API interna no Auth/OS e seu mecanismo de autenticação de serviço. O pedido desta etapa **não autoriza sua implementação nem alteração do Auth**.

## 13. Plano incremental 8.3.2–8.3.5

### Gate anterior a qualquer implementação

Revisar esta matriz e aprovar D01–D11 aplicáveis. Fixar issuer/audience/JWKS, erros, authorities, escopos, política de preço, consentimento e migração do operador financeiro. Especificar contrato mínimo de vínculos/decisão de OS e canal técnico; planejar sua implementação separadamente, incluindo Auth somente quando explicitamente autorizado. Sem resolver essa dependência, é possível preparar JWT/RBAC nos serviços, mas não declarar ownership entregue nem habilitar autoatendimento por suposição.

### 8.3.2 — OS

1. Registrar baseline de testes/contratos; adicionar dependências Resource Server gerenciadas e decoder/converter/validators.
2. Regras explícitas por método/rota O01–O14 e deny para rotas restantes; retirar Basic do canal de negócios no corte.
3. Implementar portas/adapters de vínculo/escopo e autorização por alvo, conforme contratos previamente aprovados. Propriedade antes de buscar histórico/Saga e restrições de listas antes da paginação/contagem.
4. Disponibilizar resolução interna de autorização da OS somente com autenticação de serviço/usuário e ações allowlist, caso aprovada; sem ler bancos alheios.
5. Adaptar BusinessApiIntegrationTest, fixtures, OpenAPI e clientes. Verificar que abrir OS mantém criação de Saga, histórico e Outbox atômicos e que negações não criam nada.
6. Aceite: JWT negativos, isolamento entre dois clientes, escopo de funcionário e permissões internas aprovados. Não publicar canal cliente enquanto dependência de vínculos estiver ausente.

### 8.3.3 — Execution

1. Reutilizar contrato de validação e aplicar E01–E11 sem herdar privilégios de gerente/atendente.
2. Autorizar OS resolvida do diagnóstico/reparo; implementar escopo/atribuição aprovado; definir controle de estimativa antes de permitir E03/E05.
3. Separar adapters HTTP e comando interno; não exigir JWT do listener nem `@PreAuthorize` humano nos caminhos da Saga.
4. Adaptar ExecutionApiIntegrationTest, BootstrapWebIntegrationTest, integração HTTP e documentação. Provar que negação não grava histórico/Outbox nem conclui reparo.
5. Aceite: atendente não conclui reparo, cliente não edita técnico, mecânico fora da OS negado; diagnostic.start/repair.start/cancel e reentregas continuam válidos.

### 8.3.4 — Billing

1. Aplicar B01–B09 com resolução local de osId, RBAC e propriedade dinâmica no OS/Auth; autorização antes de reservar checkout/decidir orçamento.
2. Resolver ator financeiro com sub validado; compatibilidade do responsavelId explícita e testada, sem alterar arbitrariamente contrato REST.
3. Migrar BILLING_OPERATOR somente conforme D03 aprovada; isolar eventual transição Basic/CSRF e encerrar fallback no prazo definido.
4. Proteger canais Bearer e sessão conforme seção 8; manter HMAC e exceção exata do webhook, sem depender de login final no provedor.
5. Adaptar FinancialApiTests, ProviderIntegrationTests, MessagingIntegrationTests e testes OpenAPI/CSRF; preservar transações, invariantes, UNKNOWN/REVIEW, reconciliação, leases e Outbox.
6. Aceite: cliente não decide/cria checkout alheio; mecânico/atendente/gerente não recebem operação financeira de escrita; webhook válido sem JWT funciona e inválido não persiste receipt.

### 8.3.5 — Integração de segurança e Saga autenticada

1. Provisionar fixtures de teste isoladas: usuários reais Auth sintéticos, dois clientes/veículos/OS, papéis e escopos distintos e vínculos confiáveis preparados por harness autorizado, sem endpoint público de fixtures ou seed de produção.
2. Executar login e usar tokens reais por ator em todas as entradas HTTP; validar comunicação interna com identidades técnicas e permissões RabbitMQ por serviço.
3. Exercitar OS→diagnóstico→orçamento→decisão→reparo→pagamento→resultado verificado→OS finalizada, incluindo rejeição, falhas, compensação, reentrega e indisponibilidades.
4. Atualizar roteiros de integração e expectativas de segurança; não manter endpoint aberto para fazer script antigo passar.
5. Evidenciar isolamento, invariantes financeiras e ausência de duplicidade; revisar infraestrutura necessária antes de qualquer deploy separado.

### Adaptação de testes e clientes existentes

O `src/test/.../BusinessApiIntegrationTest.java` usa `.with(user("api"))`; E `ExecutionApiIntegrationTest.java` usa `@WithMockUser`/httpBasic; B `web/FinancialApiTests.java`, `payment/ProviderIntegrationTests.java`, `messaging/MessagingIntegrationTests.java` usam Basic/CSRF e o operador legado. B `BillingApplicationTests.java` verifica esquema OpenAPI Basic. Esses pontos devem mudar junto do contrato de segurança, não gerar falsos negativos ou manter bypasss.

Em testes de autorização MVC, `jwt()` com sub/papéis/authorities explícitos pode isolar políticas; ele **não testa assinatura, decoder, roles converter ou JWKS**. Complementar com HTTP Bearer de JWT RS256 real e JWKS em servidor HTTP local de teste controlado; chave efêmera por suíte, Clock fixo/injetado e claims/casos negativos determinísticos. HTTP local do JWKS somente por configuração de teste; produção exige HTTPS. Testes de domínio/persistência não precisam autenticar artificialmente o domínio.

B `integration/7.4.1/{run,probe}.ps1`, E `integration/` e B `integration/7.6/{common,prepare,run,export}.ps1` são pontos de revisão de Basic, sessão/CSRF e atores fixos. Roteiros novos devem obter login, renovar token por TTL sem registrar senha/token e escolher ator certo por ação. Manter testes do canal legado enquanto coexistir; para Bearer, atualizar 403 CSRF esperado somente onde o novo canal dispensa legitimamente essa proteção. Cenários oficiais Mercado Pago continuam em sandbox e dependem de credenciais/autorização próprias; mocks locais não equivalem a homologação no provedor.

## 14. Testes de segurança necessários

Tabela define o comportamento futuro esperado. Nada aqui foi executado como validação de uma implementação 8.3 inexistente.

| Cenário | Resultado esperado / evidência |
| --- | --- |
| Negócio sem token | 401 no canal Bearer, nenhuma mutação/Outbox; legado CSRF pode retornar 403 primeiro enquanto existir |
| Token inválido, assinatura errada, none, HS256, RS384 | 401; sem fallback Basic/sessão/anônimo |
| Token expirado / nbf futuro / iat incoerente | 401 fora do skew configurado; testar limites com Clock |
| Emissor ou audiência incorretos/ausentes | 401, inclusive assinatura válida de chave confiável |
| sub não UUID, abreviado/não canônico, ausente | 401; não converter CPF/clienteId |
| kid ausente, desconhecido ou ambíguo; JWK incompatível | 401 após fetch válido sem chave; indisponibilidade de fetch sem acesso privilegiado |
| roles vazias | JWT autenticado, 403 nos negócios |
| roles ausentes/malformadas/desconhecidas | 401 por contrato de schema proposto |
| Papel insuficiente | 403 para ação, incluindo mutação em recurso próprio com papel errado |
| Cliente A acessa OS/veículo de B | 404 uniforme em consulta individual (ou política 403 aprovada), nunca dados; filtro adulterado negado |
| Cliente A lista sem clienteId/com clienteId B | Interseção no banco, nenhuma OS B nem vazamento em total/paginação |
| Cliente acessa orçamento/aprovação/pagamento/checkout de B | Negar em todas as variantes id/query, inclusive listas vazias; nenhuma decisão/preferência/receipt/Outbox criada |
| Cliente fornece responsavelId de terceiro | Não impersona; ator auditável vem de sub, rejeição ou tratamento compatível conforme D aprovada |
| Mecânico executa operação financeira | 403; conhecimento do osId ou múltiplas tentativas não autoriza |
| Atendente conclui reparo | 403; não grava conclusão/histórico/evento |
| Mecânico fora da atribuição/OS autorizada | Negar leitura e escrita; sem fallback de escopo ausente |
| Gerente opera fora de filial/área ou tenta escrita técnica/financeira | Negar, sem herança automática de papéis |
| Usuário inativo tenta login | Auth recusa novas emissões, já implementado |
| Usuário inativado com token vigente | JWT stateless isolado continua aceitável até exp+skew; política cliente dinâmica proposta nega ao reler Auth; funcionários precisam solução D07 ou aceite explícito |
| Papéis alterados após emissão | Claims antigas persistem até exp+skew; concessão só aparece em novo token; remoção não tem fluxo atual. Revogação imediata exige mecanismo futuro |
| Vínculo removido após emissão | Não existe remoção hoje; futuro teste exige implementar fluxo e comprovar negação na próxima leitura, sem prometer atomicidade com operação concorrente |
| Auth/JWKS indisponível com cache conhecido válido | Validação JWT continua local; ownership dinâmico pode responder 503 por depender de outra API |
| JWKS indisponível em cold start/cache expirado/kid novo | Falhar fechado com erro controlado; nunca liberar acesso por ausência de chave |
| Rotação normal de duas chaves | Tokens antigos e novos válidos nas janelas; retirada após retenção; testar instâncias/cache de idades diferentes |
| Retirada emergencial de chave | Invalidar caches pelo procedimento aprovado; não confundir com revogação de jti |
| Escalada por headers internos/source de mensagem forjados | Contexto não autenticado negado; outro serviço não pode usar decisão de ação/recurso distinto |
| RabbitMQ publica key de outro domínio/default exchange | Broker nega; Execution não publica payment.confirmed e Billing não publica repair.start |
| Mensagem confiável após expiração do token do usuário original | Processamento interno continua conforme contrato/estado, sem depender de JWT final |
| Reentrega/concorrência RabbitMQ | Mesmo eventId não duplica agregado, histórico, efeito financeiro ou resultado; manter rollback e leases |
| Webhook válido sem JWT e sem sessão CSRF | 200 só após receipt durável; processamento financeiro posterior verificado |
| Webhook HMAC inválido/ts fora da janela/IDs divergentes | 401/400 conforme erro; sem receipt/efeito financeiro; integração desligada não abre exceção permissiva |
| Webhook com JWT inválido adicional | Cadeia específica conserva autenticação HMAC; JWT final irrelevante para identidade do provedor; testar matchers/ordem |
| POST financeiro por cookie/Basic sem CSRF | 403 enquanto canal existir, mesmo com credenciais válidas |
| POST Bearer inválido com cookie/sessão válida | 401; não autenticar por fallback nem aproveitar exceção CSRF |
| Health/docs/internal em produção | Health mínimo via rede prevista; documentação e bootstrap inacessíveis a humano sem autorização técnica |
| Saga completa autenticada | Atores corretos em cada HTTP, broker restrito, resultado MP verificado; OS finaliza uma vez; casos de rejeição/compensação preservados |

Apenas assinatura/algoritmo/claims/tempo e roles presentes no token são garantias stateless. Estado atual do usuário, remoção de papel, vínculo atual e revogação imediata exigem fontes dinâmicas ou protocolo de revogação; ter jti não resolve sozinho. Não criar blacklist por pod/Lambda.

## 15. Dependências AWS/Kubernetes e entrega desta etapa

Planejamento de infraestrutura, **sem execução**:

- Auth Lambda precisa rotas API Gateway HTTP v2 login/JWKS e, se aprovada, API interna com autorização de serviço. IAM de invocação impede forjar contexto/sourceIp; permissionamento direto não pode contornar a borda.
- Antes de implantar Auth, atualizar IaC legado: `terraform/lambda.tf` ainda injeta DB_* e JWT_SECRET do banco antigo, `network.tf` só libera saída 5432 e `iam.tf` não concede Secrets Manager. Preparar banco Auth exclusivo, AUTH_*, secret ARN, `GetSecretValue` mínimo/Decrypt quando aplicável e HTTPS 443 via endpoint privado/NAT. Não aplicar Terraform existente como se já suportasse 8.2/8.3.
- JVM/pods Resource Server precisam DNS e egress HTTPS ao JWKS/API interna, trust store/CA confiáveis e relógios sincronizados. Eles **não precisam** da chave privada Auth nem de acesso aos secrets de assinatura.
- Para Auth Lambda→serviço Kubernetes ou serviço→Lambda interno: planejar ingress privado/API Gateway/IAM ou mTLS/PKI, trust anchors, expiração/rotação de credenciais de serviço, allowlists e timeouts. Auth não acessa banco OS; seu runtime atual não chama APIs de negócio para resolver propriedade.
- Kubernetes: Secrets por serviço/ambiente, ServiceAccounts/IAM apropriados, NetworkPolicies entre serviços/broker/bancos e ingress mínimo. Nenhum Bearer de usuário em manifestos/probes. API Gateway/IAM e mTLS são alternativas a escolher e validar, não capacidades já instaladas.
- RabbitMQ: credenciais/TLS por serviço, vhost por ambiente, ACL de recurso/topic e default exchange, gestão privada, provisionamento compatível com retry/DLQ. Monitorar rejeições, consumo, lag, Outbox FAILED e rotação de credenciais sem perda de mensagens.
- Operação financeira: segredos Mercado Pago separados, webhook HTTPS, limites de body/rate na borda, janela HMAC/relógio e reconciliação controlada. Exposição de métricas/documentação somente por canal técnico restrito.
- Auth: dimensionar concorrência Lambda/pool JDBC máximo 2 por contexto, eventual RDS Proxy, cold starts, orçamento de consultas de vínculo e proteção contra enumeração/DoS. Rotação de chaves e limpeza de rate limits exigem procedimentos separados já pendentes na 8.2.
- Observabilidade: registrar sub, identidade do serviço, ação, alvo, resultado e correlação com acesso/retenção auditados, sem Bearer, senhas, chaves, HMAC completo ou PII desnecessária. Não modificar envelopes de Saga para isso nesta etapa.

### Estado final e limites da validação

Entrega exclusivamente documental: criado `docs/security/authorization-8.3.1.md` no Auth. Nenhum arquivo preexistente, controller, SecurityConfig, contrato, migração, teste ou infraestrutura foi alterado. Nenhum checkout, commit, push, deploy, Terraform, recurso AWS ou workflow executado/reativado. Os três repositórios de negócio permanecem limpos em seus HEADs originais; Auth permanece em homolog com somente este documento não rastreado.

Validação desta etapa: inspeção estática dos fontes/documentação, conferência de commits locais/remotos, contagem dos mappings dos controllers e revisão de whitespace/estado Git. Não foram executadas suítes Maven, E2E ou testes de segurança: não há implementação nova a validar, e os resultados históricos citados nas documentações anteriores não são resultados desta análise.

**Próximo passo: revisão e aprovação da arquitetura e decisões pendentes. Não iniciar automaticamente a Etapa 8.3.2.**
