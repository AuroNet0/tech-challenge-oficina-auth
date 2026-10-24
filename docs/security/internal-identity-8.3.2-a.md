# Etapa 8.3.2-A — Contrato interno de identidade e resolução de vínculos

Data: 24/10/2026. Repositório `AuroNet0/tech-challenge-oficina-auth`, branch `homolog`, base `eb1809a081d2c7cc6a2c01576807fd248f9f3065`.

## 1. Entrega e condição de exposição

**Implementados somente contratos de aplicação, porta de autenticação e caso de uso interno de verificação de vínculo, com testes. A rota HTTP continua inexistente e retorna 404 no handler atual.** Não foi implementado um verificador de serviço, validador JWT de entrada interna, API Gateway IAM ou adapter HTTP interno. Não existe flag local que ative a rota.

A análise obrigatória abrangeu `docs/identity.md`, `docs/authentication.md`, `docs/security/authorization-8.3.1.md`, modelos, casos de uso, JDBC/transações, handler/bootstrap, configuração Lambda/Terraform e testes existentes. A 8.3.1 estava não rastreada e foi preservada sem edição. Não foram alterados os outros três microsserviços.

O Terraform atual declara Lambda, IAM básico/VPC e banco/rede legados, mas não um API Gateway com autorização de serviço. Não existe PKI/mTLS ou uma cadeia de validação SigV4 local que comprove a origem de um evento Lambda. Implementar leitura de `requestContext.authorizer.iam` sem essa fronteira de confiança permitiria a um invocador direto forjar contexto. Portanto, foi aplicada a alternativa explicitamente autorizada nesta etapa: entregar o núcleo testável e bloquear exposição até existir autenticação técnica verificável.

Isso não é uma aprovação pendente para criar um novo serviço: não será criado Authorization Service. Falta aprovar/provisionar e validar o canal técnico do próprio Auth em etapa separada. Testes unitários com doubles da porta não comprovam autenticação criptográfica e não são apresentados como tal.

## 2. Decisões de negócio aprovadas e responsabilidades

As aprovações recebidas nesta etapa complementam a fotografia histórica da 8.3.1, sem sobrescrevê-la:

- CLIENTE autenticado e atualmente vinculado pode consultar seus recursos, decidir orçamento próprio e iniciar checkout próprio. O ator real da aprovação deve vir de identidade autenticada, nunca de `responsavelId` autodeclarado.
- ATENDENTE opera somente nas filiais autorizadas.
- MECANICO opera somente em OS atribuídas ou explicitamente autorizadas e pode registrar preços previstos no diagnóstico. O orçamento final depende de aprovação do cliente antes do reparo, seguindo a Saga existente.
- GERENTE tem permissões gerenciais concedidas dentro de suas filiais; não herda os demais papéis e não aprova orçamento pelo cliente apenas por ser gerente.

| Autoridade | Responsabilidade |
| --- | --- |
| Auth | Identidade UUID, credenciais, ativo, papéis atuais, vínculos usuário-cliente e confirmação mínima desse vínculo |
| OS | Clientes/veículos/filiais/OS, cliente contratante da OS, escopos funcionário-filial e atribuições mecânico-OS |
| Billing/Execution | Autorização da sua operação, estado local e invariantes financeiras/técnicas, consumindo decisões confiáveis sobre OS quando necessário |
| Canal técnico | Autenticar o serviço solicitante e preservar integridade/vinculação com a prova de identidade do usuário e o alvo |

Auth não recebe OS para consultar seu banco, não decide quem pode concluir reparo e não fornece acesso administrativo por meio da verificação de vínculo. OS não recebe acesso ao banco Auth.

## 3. Modelo atual de vínculos

Fontes: `domain/model/Usuario.java`, `domain/model/UsuarioCliente.java`, `domain/enums/Papel.java`, `infrastructure/persistence/jdbc/JdbcUsuarioRepository.java` e `src/main/resources/db/migration/V1__create_identity_schema.sql`, sob o pacote `br.com.fiap.oficina.auth` quando aplicável.

`UsuarioCliente(usuarioId, clienteId, criadoEm)` não possui ativo, validade, revogadoEm ou método de remoção. A tabela `usuario_clientes` tem PK `(usuario_id, cliente_id)` e FK interna composta para papel CLIENTE. **A relação é N:N:** um usuário pode ter vários clientes e vários usuários podem compartilhar o mesmo cliente. Não existe unicidade individual em cliente_id ou usuario_id que imponha 1:1.

`Usuario.podeAcessarCliente` exige simultaneamente usuário ativo, papel CLIENTE e vínculo presente. `JdbcUsuarioRepository` persiste associações por inserção idempotente; `salvar` não remove vínculos ausentes de uma coleção. Não seria correto implementar uma desvinculação apenas removendo item em memória.

Vínculo “vigente” nesta versão significa vínculo persistido presente e usuário atualmente ativo/CLIENTE. Não há expiração individual ou revogação de vínculo implementada. UUID do cliente no Auth é referência lógica; nem prova de existência no OS nem prova de titularidade civil. CPF não é prova de identidade/propriedade.

### Revogação futura

Propor caso de uso administrativo de desvinculação com `ProvisioningAuthorization` específica, alvo verificado, lock do usuário, persistência explícita e auditoria de ator técnico/humano, motivo e instante. Definir exclusão controlada versus tombstone/histórico e idempotência em especificação própria. Não criar endpoint público nem alterar V1/V2 para antecipar essa decisão.

Inativar usuário já impede decisão positiva na próxima leitura confirmada. Papéis e vínculos usados na decisão são carregados do banco atual; um JWT emitido antes da inativação não substitui essa consulta. Isso não revoga criptograficamente o JWT para outros serviços. Não há blacklist nem invalidação distribuída de tokens implementada.

## 4. Componentes implementados

Todos os caminhos de produção abaixo são relativos a `src/main/java/br/com/fiap/oficina/auth/`:

| Componente | Contrato implementado |
| --- | --- |
| `application/port/in/AcessoClienteView.java` | Resultado mínimo `boolean autorizado`; sem entidades, listas ou dados pessoais |
| `application/port/out/IdentidadeAcessoCliente.java` | Contexto esperado de um adapter confiável: usuarioId autenticado, servicoId técnico, clienteId alvo e validoAte |
| `application/port/out/ClientAccessAuthentication.java` | Porta `autenticar(UUID clienteId)`, sem implementação de produção nesta etapa |
| `application/usecase/VerificarAcessoClienteUseCase.java` | Validação do alvo, exigência de contexto autenticado e allowlist técnica, leitura transacional atual e decisão mínima |

O caso de uso recebe apenas o **clienteId** externo como string UUID canônica minúscula. Não recebe usuarioId, roles ou um contexto construído pelo consumidor no método `executar`. O usuário é exclusivamente o subject que o adapter futuro deverá comprovar. Isso impede selecionar outra identidade por um campo do comando. Entretanto, um record Java não é prova criptográfica: o contexto só será confiável quando produzido por adapter validado em fronteira controlada, e por isso não existe binding no `AuthBootstrap`/`AuthServices`.

O construtor exige `IdentityTransaction`, `ClientAccessAuthentication`, conjunto imutável de identidades técnicas autorizadas para **esta operação** e Clock. Allowlist vazia nega tudo; não há serviço autorizado por padrão. IDs de serviço são comparados por igualdade exata, sem wildcard. O nome `os-service` existe apenas nas fixtures; produção deverá usar identidade derivada do mecanismo real, por exemplo role ARN estável aprovada. Não mapear uma session ARN arbitrária para role por substring.

### Contrato de confiança da porta de autenticação

`ClientAccessAuthentication.autenticar(alvo)` deverá futuramente:

1. Operar sobre evidências **da invocação atual**, capturadas pelo adapter de entrada/segurança; não aceitar contexto persistido de outra requisição ou dados de cabeçalhos arbitrários.
2. Autenticar a identidade técnica e a identidade do usuário por mecanismos independentes.
3. Validar o JWT e derivar usuarioId somente de seu sub UUID, sem consulta por email/CPF e sem usuário escolhido pela credencial técnica.
4. Verificar integridade conjunta entre serviço autenticado, prova JWT, alvo e envelope da requisição; recusar substituição de token/alvo, corpo ambíguo ou contexto não confiável.
5. Retornar contexto vinculado ao clienteId exato e validade efetiva máxima igual ao menor prazo das evidências envolvidas, também limitado pela janela da requisição. Não conservar contexto entre invocações de uma Lambda aquecida.
6. Lançar falha sanitizada se qualquer evidência faltar, estiver inválida/expirada, ou não puder ser verificada. Não retornar identidade parcial ou supor serviço a partir do host/URL.

O núcleo valida que o contexto corresponde ao alvo, não está expirado e identifica um serviço explicitamente permitido, **antes de abrir transação**. Revalida alvo/validade após a leitura, para que expiração durante espera do lock não produza autorização. O contrato da porta é deliberadamente estreito; não serve para cadastrar usuários, alterar papéis ou listar clientes.

### Fluxo interno implementado

1. Parse estrito do clienteId; ausência, formato inválido, UUID abreviado/não canônico retornam falha de entrada.
2. Chamar a porta de autenticação vinculada à invocação; validar alvo e validade.
3. Exigir servicoId na allowlist desta operação; não consultar usuário para serviço não permitido.
4. Executar `IdentityTransaction` e `buscarPorId` exclusivamente com usuarioId do contexto confiável.
5. Calcular autorizado usando o agregado carregado e `podeAcessarCliente`, sem usar papéis/vínculos antigos do JWT como substitutos do banco.
6. Retornar apenas `AcessoClienteView` após o retorno bem-sucedido da transação. Falha de leitura/commit não produz resposta positiva.

Não há cache de resultado, acesso ao banco OS, alteração de usuário/vínculo ou logs de credenciais. O domínio permanece dependente somente de Java; novos componentes ficam na aplicação e dependem de portas, sem AWS/Spring.

## 5. Contrato HTTP proposto — não exposto

Rota candidata: **POST `/internal/v1/identity/client-access/check`**.

Compatibilidade: o handler atual usa `rawPath` e método em `requestContext.http.method`, com payload HTTP API v2. O caminho é compatível com esse roteamento semântico, mas está fora da allowlist atual e retorna 404 antes de inicializar serviços. O JAR de eventos `aws-lambda-java-events:3.15.0` possui representação `requestContext.authorizer.iam` (conferida na classe da dependência). Isso é apenas capacidade de transporte, não autenticação ou infraestrutura configuradas. Não há API Gateway declarado no Terraform que publique essa rota.

### Envelope proposto para IAM/SigV4

`Authorization` fica reservado à assinatura SigV4 do serviço. Para evitar conflito com Bearer, transportar a prova de usuário **dentro do corpo assinado**:

```json
{
  "clienteId": "00000000-0000-0000-0000-000000000001",
  "userAccessToken": "<JWT RS256 original do usuario>",
  "requestId": "00000000-0000-0000-0000-000000000002",
  "issuedAt": "2026-10-24T12:00:00Z"
}
```

Esse é um contrato candidato, não um DTO HTTP já implementado. Não enviar usuarioId, roles ou dados da OS. O token no corpo é segredo e exige desabilitar captura de body em API Gateway, proxies, logs/APM e exceptions. Não colocar token em query string. JSON estrito: chaves exatas, sem duplicatas/trailing content, UTF-8 e tipos corretos. Limite proposto de 12 KiB de corpo decodificado, JWT até 8 KiB, e limite correspondente de Base64/entrada bruta antes de alocar. Ajustar/testar limites antes de expor; o limite do login atual de 8 KiB não é alterado por esta proposta.

SigV4 deve vincular método, caminho, corpo com hash completo, timestamp e credencial temporária. Não aceitar `UNSIGNED-PAYLOAD` nesse contrato. É necessário testar que a fronteira/API Gateway escolhida exige essa integridade e que alteração do corpo/token/alvo falha; não inferir proteção apenas pela presença do header Authorization. Caso não seja possível impor esse requisito, não abrir a rota sem mecanismo equivalente aprovado.

Resposta proposta após autenticação e autorização técnica válidas:

```json
{"autorizado":true}
```

Ou `{"autorizado":false}`. Ambos HTTP 200 com `Cache-Control: no-store`. Não incluir usuarioId, clienteId, motivo individual, estado ativo, papéis, nome, email, CPF ou hash. O chamador já conhece o alvo/prova que apresentou. False engloba usuário ausente/inativo, sem CLIENTE ou vínculo ausente, sem explicar qual condição falhou. A confirmação não prova que uma OS pertence a esse cliente; OS deve verificar `OrdemServico.clienteId` e a ação de negócio.

Não existe API de listar vínculos. Um consumidor que precise filtrar listas de OS deverá planejar consultas restritas/paginação e orçamento de chamadas, sem criar consulta global no Auth ou inferir acesso pela ausência de erro. A resolução pontual não entrega automaticamente toda a estratégia de listagem da 8.3.2-B.

## 6. Autenticação técnica: opções e recomendação

| Opção | Vantagens | Limitações/dependências | Teste necessário |
| --- | --- | --- | --- |
| API Gateway HTTP API com AWS_IAM/SigV4 | Adequado à Lambda; role de workload do OS com credenciais temporárias; permissão execute-api por método/rota | Gateway/route/policies ainda ausentes, IAM do pod e rede a definir, contexto Lambda só é confiável com invocação restrita; integridade do envelope deve ser comprovada | Assinador/verificador criptográfico real ou equivalente determinístico local, casos de tampering e credenciais temporárias, mais aceite na AWS antes de exposição |
| mTLS com identidade do certificado | Identidade técnica independente de Bearer e viável em ambiente K8s/local | PKI, truststore, emissão/rotação/revogação e mapeamento certificado→serviço; fronteira TLS termina antes da Lambda; precisa impedir bypass do endpoint padrão e invocação direta | Handshake TLS real com CA de teste, certificados autorizados/desconhecidos/expirados, falhas de trust e transporte de contexto até Lambda |
| Credencial assimétrica própria por serviço + envelope assinado | Verificação local real é possível sem IAM; chave separada por workload | Novo protocolo, distribuição/rotação de chaves, audience/replay e operação adicional ainda não especificados | Vetores reais de assinatura, adulteração/replay/expiração/rotação; não apenas mock booleano |

**Recomendação para AWS:** API Gateway HTTP API com AWS_IAM na rota interna e role exclusiva do OS, mantendo JWT do usuário dentro do envelope assinado e validado também no Auth. Em Kubernetes AWS, escolher Pod Identity/IRSA ou mecanismo equivalente que entregue credenciais temporárias ao workload; não distribuir access key estática nem compartilhar segredo entre serviços. Para K8s fora da AWS, avaliar federação de workload/STS ou mTLS antes de escolher mecanismo de credencial.

Aplicar defesa em profundidade: execute-api:Invoke só para essa rota/método/stage, identidade técnica allowlist no Auth, trust policy mínima, TLS obrigatório, rate limit por serviço/alvo, e Lambda Invoke restrito ao gateway autorizado no ambiente de produção. Inventariar principals administrativos com InvokeFunction: payloads de invocação direta podem falsificar contexto de gateway, portanto são parte explícita da fronteira de confiança e não um canal autorizado de consumidores.

HTTP APIs não oferecem resource policies segundo a documentação consultada; não planejar uma resource policy inexistente como controle de rede desse produto. Distinguir policy IAM do chamador, resource policy de invocação da Lambda e restrições efetivamente suportadas pela modalidade de gateway escolhida. Se mTLS for selecionado, API Gateway não verifica revogação de certificado automaticamente: projetar checagem adicional e desabilitar o endpoint execute-api padrão para evitar bypass do domínio mTLS.

Somente validar JWT não satisfaz identidade técnica. Somente IAM não satisfaz identidade do usuário. Um serviço autenticado sem token válido não pode escolher usuarioId; possuir um JWT alheio capturado ainda representa risco de Bearer roubado. A vinculação ao corpo assinado impede alteração em trânsito, mas não prova intenção humana de consentimento nem elimina comprometimento do OS. Prova de consentimento para operações financeiras permanece responsabilidade do fluxo de negócio.

### JWT do usuário no adapter futuro

Verificar RS256 exclusivo, assinatura com chave pública confiável/kid, issuer e audience aprovados, exp/nbf/iat/coerência/TTL e sub UUID canônico. Não aceitar none/HS256/algoritmo alternativo, jku controlado pelo token, JWT sem assinatura ou claims de header como identidade. Considerar roles do JWT para contrato de entrada, mas exigir CLIENTE/ativo/vínculo **atuais** no banco para a decisão positiva. Novo adapter não pode reutilizar `JwtService` HS256 legado. Reutilizar chaves públicas do provider confiável sem dependência de banco OS e sem seguir URLs do token.

Esta validação interna não foi implementada/testada como nova entrada JWT; testes 8.2 continuam validando emissão/JWKS e seus negativos existentes.

### Replay

SigV4 e TLS limitam adulteração/exposição, mas não devem ser descritos como nonce descartável. Proposta: `issuedAt` com janela curta (por exemplo 60 s, Clock testável) e requestId assinado, com verificação de timestamp/credenciais/JWT em toda chamada. Esta operação é leitura e cada reentrega deve refazer a consulta atual, sem reutilizar decisão positiva. Não prometer rejeição de replay único enquanto não existir armazenamento atômico de nonces/IDs por principal e TTL. Se o requisito operacional exigir uso único, projetar esse armazenamento e sua limpeza antes de habilitar o canal, sem blacklist local por Lambda. Nenhuma assinatura, timestamp ou requestId é validado pelo núcleo isolado desta entrega: essa responsabilidade pertence ao adapter bloqueado.

Referências oficiais: [IAM para HTTP APIs](https://docs.aws.amazon.com/apigateway/latest/developerguide/http-api-access-control-iam.html) e [mTLS em HTTP APIs](https://docs.aws.amazon.com/apigateway/latest/developerguide/http-api-mutual-tls.html). O uso da plataforma não substitui testes de integridade e fronteira de confiança do projeto.

## 7. Transação, concorrência e falhas

`JdbcIdentityTransaction` mantém commit/rollback e tradução sanitizada de SQLState. `JdbcUsuarioRepository.buscarPorId` bloqueia a linha raiz por SELECT FOR UPDATE e carrega papéis/vínculos na mesma transação READ COMMITTED. Casos administrativos existentes também bloqueiam essa raiz. Uma inativação confirmada antes da obtenção do lock será observada pela decisão. Escritas futuras de vínculo devem respeitar a mesma disciplina de lock; SQL administrativo que a contorne não é protocolo suportado.

Após retornar uma decisão, outra transação pode inativar/revogar antes de o OS efetuar sua operação. **Não há atomicidade distribuída, lease de autorização ou garantia de revogação instantânea entre Auth e OS.** OS deverá verificar imediatamente antes do efeito; exigência maior demanda protocolo adicional aprovado. Não usar a validade do JWT como cache de vínculo.

Timeouts JDBC atuais, em `infrastructure/config/AuthDatabase.java`: pool máximo 2 por contexto, espera de conexão 3 s, connectTimeout 3 s, socketTimeout 5 s, statement_timeout 4 s, lock_timeout 2 s e idle_in_transaction_session_timeout 10 s. Não foram modificados. Futuro budget HTTP deve comportar a soma real de autenticação/espera/queries, respeitar timeout Lambda (atual 15 s) e medir contenção, sem anunciar SLA de 2 s usando esses defaults.

| Resultado/código interno | Situação | HTTP futuro sugerido |
| --- | --- | --- |
| `AcessoClienteView(true)` | Contexto técnico permitido + usuário ativo/CLIENTE/vínculo atual | 200/no-store |
| `AcessoClienteView(false)` | Usuário ausente/inativo/sem CLIENTE/sem vínculo | 200/no-store, mesmo schema/mensagem |
| `IdentityException(INVALIDO)` | UUID alvo inválido/não canônico | 400 genérico |
| `IdentityException(CREDENCIAIS_INVALIDAS)` | Evidência ausente/inválida/expirada, contexto nulo ou alvo divergente | 401 genérico na aplicação; gateway IAM pode recusar antes com seu status próprio |
| `IdentityException(NAO_AUTORIZADO)` | Serviço autenticado não permitido nesta operação | 403 genérico |
| `IdentityException(PERSISTENCIA/CONCORRENCIA)` | Banco/conexão/lock/commit ou dependência de verificação indisponível | 503 sanitizado; não retornar false/true |
| Erro inesperado | Falha não prevista | 500 genérico, falha fechada |

Esses códigos reutilizam `domain/exception/IdentityException.java`, sem alterar seu enum. O adapter deverá lançar as falhas correspondentes para problemas de autenticação/infraestrutura. O status de uma rota inexistente hoje é sempre 404 para eventos v2 válidos, não os status hipotéticos da tabela. Não há tentativa de mascarar indisponibilidade como “sem vínculo”. Respostas iguais não garantem tempo perfeitamente constante; aplicar limites e monitoração para mitigar enumeração temporal.

## 8. Escopos operacionais — modelo recomendado, não implementado

O Auth atual possui somente papéis e vínculos com cliente. JWT não contém filial nem atribuição de OS. OS possui `Filial`, `OrdemServico.clienteId/veiculoId/filialId`; a análise 8.3.1 não encontrou relação usuário-funcionário-filial ou mecânico-OS implementada. Nenhum escopo universal foi criado.

**Autoridade de escopo: OS**, pois controla filiais, OS e atribuições operacionais. Propor registros operacionais com usuarioId lógico Auth, alvo local (filial/OS), capacidades explícitas, concedidoPor/em, motivo, estado/revogadoPor/em e versão para concorrência. Não inserir lista de filiais/OS no access token. Não há nova tabela, migração ou adapter dessa proposta nesta etapa.

Contratos lógicos mínimos a especificar no OS:

| Operação proposta | Entradas de negócio e contexto confiável | Decisão mínima |
| --- | --- | --- |
| Verificar operação em filial | filialId, ação allowlist, usuário autenticado e serviço solicitante autorizado | Permitido somente com papel compatível e concessão ativa da capacidade nessa filial |
| Verificar operação técnica em OS | osId, ação técnica allowlist, contexto confiável | MECANICO com atribuição/concessão ativa nessa OS; estado local continua validado no Execution |
| Verificar acesso a OS própria | osId e ação, contexto confiável | OS resolve seu clienteId e pede confirmação pontual ao Auth; nenhum clienteId do frontend é prova |

Atendente/gerente precisam da associação à filial e da capacidade específica. Mecânico não recebe todas as OS da filial automaticamente. GERENTE não ganha escrita técnica ou aprovação financeira pela associação. Sem papel/concessão/registro, deny; dependência indisponível é erro fechado, não concessão global.

Provisionamento/revogação operacionais devem ter autorização administrativa separada, actor real, alvo, capacidades, motivo, histórico e controle concorrente no OS, com concessões nomeadas e sem autoconcessão. OS deverá verificar identidade/estado/papel do funcionário via contrato confiável adequado ou política de frescor/revogação explicitamente definida; **esta API de vínculo CLIENTE não é API genérica de escopo ou consulta de funcionário**. A decisão sobre frescor de papéis de funcionários permanece necessária na 8.3.2-B.

## 9. Privacidade e controles antes de expor

- TLS, identidade forte do serviço, permissão técnica específica, JWT validado e envelope íntegro são todos obrigatórios.
- Não retornar o agregado Usuario, UsuarioView com lista de clientes, hashes, CPF, email ou nome. O DTO novo contém somente boolean.
- Não registrar body/token, assinatura SigV4 completa, credenciais STS, CPF ou dumps de eventos. Sanitizar logs/API Gateway/APM e erros; definir redaction antes de ativar o adapter.
- Auditoria mínima futura: identidade técnica, sub UUID, alvo UUID, operação, resultado genérico, requestId e instante, com acesso e retenção definidos. UUIDs também são dados correlacionáveis, não anonimização. Não retornar essa trilha em resposta pública.
- Limitar payload, JSON/base64 e tempo de validação/consulta. Não autenticar o serviço por `X-Service-Id`, `X-User-Id`, `X-Roles`, conhecimento da URL ou modo local.
- Não aceitar contexto de autenticação obtido em invocação anterior da mesma Lambda. Reutilizar pool/provider é distinto de reutilizar identidade do request.
- Não reutilizar esta checagem para provisionar conta, criar vínculos, atribuir papéis ou aprovar em nome de terceiro.

## 10. Testes e evidências

### Novos testes implementados

`application/VerificarAcessoClienteUseCaseTest.java` verifica no núcleo:

- Usuário ativo/CLIENTE/vinculado e resultado serializado exclusivamente como boolean.
- Ausência de usuário/vínculo/papel, usuário inativo e GERENTE sem CLIENTE negados uniformemente.
- Múltiplos clientes por usuário, alvo não vinculado e isolamento pelo usuarioId do contexto; não é possível fornecer usuarioId a executar.
- UUID nulo/inválido/abreviado/não canônico, antes da porta/banco.
- Contexto ausente/expirado, alvo trocado, credencial recusada pela porta e contexto estruturalmente incompleto.
- Allowlist técnica vazia ou identidade não permitida, sem abrir transação.
- Sem cache positivo, revalidação de validade após esperar transação, falhas de dependência e falha de commit sem retorno positivo.

**Esses testes injetam doubles da porta e comprovam a política de aplicação. Não comprovam SigV4, mTLS, JWT de entrada ou autenticação real de serviço.** Nenhum verificador criptográfico de serviço foi implementado nesta etapa; seus cenários permanecem pendentes, conforme a condição de exposição.

`infrastructure/persistence/jdbc/ClientAccessPostgresIT.java` usa PostgreSQL 16.6 real Testcontainers, Flyway V1/V2 e adapter JDBC existente para comprovar:

- N:N real com dois usuários compartilhando cliente e um usuário com dois clientes; sem alterações nas associações durante consultas.
- Usuário/cliente-alvo não vinculados negados.
- Releitura após inativação confirmada, sem cache; rollback de inativação conserva acesso.
- Inativação concorrente detém lock de usuário, leitor realmente espera no PostgreSQL e depois observa o estado confirmado. A espera é constatada em pg_stat_activity, não presumida a partir de tempo de sleep.
- Banco indisponível gera erro de persistência, sem decisão positiva ou falsa negação.

`handler/AuthHandlerTest.java` garante 404 da rota interna para POST/GET/OPTIONS, mesmo com headers forjados, sem inicializar AuthServices. `infrastructure/PackagedRuntimeProbe.java` verifica no JAR a presença do caso de uso e a rota interna fechada, além do login/JWKS/Argon2/migrações já verificados pelo probe.

### Cenários HTTP/criptográficos explicitamente pendentes

Credencial técnica válida/ausente/falsa/expirada, IAM permitido/negado real, tampering de corpo/JWT/alvo, substituição de contexto por invocação direta, replay/janela, validação JWT interna (assinatura/issuer/audience/kid/exp/nbf), limites JSON/payload e logs de borda devem usar verificador real/equivalente criptográfico determinístico e, depois, ambiente implantado controlado. Mock do authorizer ou evento Lambda construído manualmente não aprova esses cenários. A única propriedade HTTP nova comprovada aqui é **não exposição**.

### Execução local

Validação final em 24/10/2026, JDK Microsoft 21.0.12.1, Maven e Docker Desktop locais:

- Testes direcionados iniciais: 19 execuções, zero falhas/erros/ignorados.
- `mvn clean verify` final: **BUILD SUCCESS**, 61 testes unitários + 16 de integração = **77 testes**, zero falhas, zero erros e zero ignorados. Uma execução completa anterior também passou; a final inclui o teste adicional de falha de commit.
- Novo caso de uso: 18 execuções unitárias; novo teste PostgreSQL: 4 cenários. Suítes das Etapas 8.1/8.2 preservadas e executadas, incluindo login, RS256/JWKS, rotação, rate limiting e migrações.
- JaCoCo de todo o código de produção: **667/726 linhas, 91,87%**, gate de 80% aprovado sem exclusões adicionais. Relatórios em `target/site/jacoco/index.html` e `jacoco.xml`.
- Flyway V1/V2 aplicadas/validadas nos bancos descartáveis Testcontainers; arquivos de migração originais sem alterações.
- JAR Shade `target/tech-challenge-oficina-auth.jar`: **24.945.120 bytes**. Probe em processo Java separado aprovado com marcador `PACKAGED_RUNTIME_OK`, login real pelo handler empacotado, verificação pública do JWT/JWKS, Argon2 e migração explícita; caso de uso interno carregável e rota interna 404.
- Log final em `target/verify-8.3.2-a.log`; relatórios individuais Surefire/Failsafe no target. Esses artefatos são ignorados pelo Git.
- `git diff --check` sem erros de whitespace. SHA-256 da documentação preservada 8.3.1: `92c50e343586e5b4e8bd305a76b305dd43e93759b9c5eae65a49decfa42bd74e`.

Nenhum teste requer credencial AWS/OS/Mercado Pago real. Docker e cache Maven foram acessados fora do sandbox de arquivos para permitir os testes autorizados. Não houve conexão com infraestrutura AWS. Avisos já existentes de SLF4J sem binding, APIs depreciadas e código de teste unchecked não impediram o build; não foi adicionada dependência de logging para alterar trabalho fora do escopo.

## 11. Dependências e limitações operacionais

Antes de expor HTTP, aprovar e concluir:

1. API Gateway HTTP v2 com AWS_IAM na rota/stage exatos; role do OS com execute-api:Invoke mínimo e credenciais temporárias de workload. Contexto IAM precisa vir exclusivamente da fronteira autenticada.
2. Policy de invocação Lambda restrita, sem consumidor com InvokeFunction capaz de forjar eventos de gateway; revisão dos operadores privilegiados e ausência de caminhos alternativos permissivos.
3. Contrato e teste de corpo SigV4 com hash integral, token original, alvo, requestId/issuedAt; proteção de replay definida, limites e validação JWT implementados com chaves públicas confiáveis.
4. Adapter de entrada/segurança por invocação, allowlist de identidades técnicas de ambiente e binding deliberado no bootstrap. Não inicializar com um autorizador permissivo para testes/development.
5. Testes criptográficos locais reais e testes de IAM/Gateway/Lambda em ambiente autorizado; nenhuma exposição apenas porque o modelo Java suporta getIam().
6. Banco Auth exclusivo e grants/timeouts adequados. Terraform ainda injeta DB_*/JWT_SECRET legado, aponta RDS antigo e não tem API Gateway. Ajustes de AUTH_*, Secrets Manager/IAM/HTTPS/rede permanecem dependências separadas; Terraform/Actions não foram modificados.
7. Rede K8s→Gateway e DNS/CA/TLS, IAM/federação do pod, rate limiting e monitoração sanitizada de erro/latência/lock. Não criar conexão OS→PostgreSQL Auth.

O núcleo usa o repositório atual que carrega agregado completo internamente (inclusive hash e todos os vínculos do usuário). Isso não vaza no retorno, mas pode aumentar leitura/lock em usuários com muitos vínculos. Antes de otimizar com consulta pontual, medir e preservar a mesma consistência/checagem de ativo/papel. Não foi introduzido cache nem acesso cruzado a bancos.

Vínculo não pode ser removido hoje; compartilhamento N:N significa que todo usuário ativo CLIENTE vinculado passa na mesma confirmação mínima. Concessões com capacidades distintas por vínculo exigiriam novo modelo; não simular isso por CPF ou relação 1:1. Revogação concorrente e inativação entre decisão Auth e commit OS continuam sem atomicidade distribuída.

## 12. Arquivos e próxima etapa

Criados quatro arquivos de produção listados na seção 4 e dois arquivos de teste: `VerificarAcessoClienteUseCaseTest.java` e `ClientAccessPostgresIT.java`. Alterados somente testes preexistentes `AuthHandlerTest.java` e `PackagedRuntimeProbe.java`. Criado este documento. Não foram alterados modelos, JDBC, handler/bootstrap de produção, dependências, migrations V1/V2, Terraform, workflows, contratos REST/RabbitMQ ou Saga. A documentação não rastreada da 8.3.1 permanece preservada.

**8.3.2-B recomendada:** preparar segurança JWT/RBAC e autorização de alvo no OS com as decisões de negócio aprovadas; para integração real de vínculo, resolver primeiro o canal técnico/adapter pendente. Pode testar uma porta OS com contrato simulado devidamente identificado, mas não declarar ownership distribuído pronto nem abrir endpoints de cliente com bypass enquanto o Auth não expõe uma entrada confiável. Definir escopos operacionais no OS com provisionamento/revogação auditáveis e menor privilégio.

Nenhum commit, push, deploy, Terraform, recurso AWS ou workflow executado/reativado. Não iniciar 8.3.2-B automaticamente.

Estado Git final: branch `homolog` no mesmo HEAD inicial; dois arquivos de teste rastreados modificados, sete arquivos novos desta etapa não rastreados e a documentação 8.3.1 preexistente ainda não rastreada. OS/Execution/Billing permanecem limpos em suas branches homolog. Nenhum arquivo de produção preexistente foi modificado.
