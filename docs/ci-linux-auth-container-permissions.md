# Correção do teste de container Auth no Linux

## Escopo e causa

Branch `homolog`, HEAD inicial `d722c035eb6d0cd63cd22c2e0b8e272a565a2768`,
checkout inicialmente limpo. Alterações restritas a testes e este relatório.
Dockerfile, runtime produtivo, autenticação, domínio, Maven e workflow preservados.

O `@TempDir` cria um diretório POSIX `0700`, pertencente ao usuário que executa
o Maven. O teste montava esse diretório inteiro como `/tls`, mas a imagem executa
com UID/GID `10001:10001`. O processo não podia atravessar a raiz do volume para
ler o keystore. READ_ONLY não concede permissões POSIX adicionais.

Reprodução em Ubuntu WSL/Docker Linux com fixture descartável e a própria imagem:

```text
Diretório: 0700, proprietário UID 1000
Arquivo: 0644, proprietário UID 1000
Processo no container: UID 10001
cat /tls/server.p12: Permission denied
ORIGINAL_ACCESS_EXIT=1

Diretório: 0755; arquivo: 0444; mesmo UID e bind readonly
FIXED_ACCESS_EXIT=0
```

Isso confirma o defeito de acesso do cenário original. A execução histórica do
GitHub não publicou o stderr do processo Java; sua exceção interna específica
continua indisponível. O diagnóstico é sustentado pela reprodução Linux do
mesmo mecanismo e pela validação do teste corrigido, não por uma validação Windows.

## Correção

- `TestTls.serverMount()` cria um subdiretório temporário exclusivo e copia
  somente `server.p12` e `trust.p12`. Em POSIX aplica `0755` ao diretório e `0444`
  aos dois arquivos. Não modifica a pasta original nem as chaves da CA/clientes.
- O diretório compartilhável permanece dentro do `@TempDir` privado; no host,
  os ancestrais continuam restritos. O bind expõe apenas a subpasta ao container.
  Não há `0777`, mudança de usuário, chmod em arquivos produtivos ou aumento
  de timeout. Em Windows, nenhuma API POSIX é exigida.
- `InternalContainerIT` usa o bundle exclusivo no bind READ_ONLY. A fixture JWKS
  também recebe só os stores necessários e seu documento público, sem chave CA
  ou identidades de outros consumidores.
- O teste verifica conjunto exato de arquivos, preservação das permissões do
  diretório original, modos POSIX, UID 10001, metadado readonly do volume, leitura
  dos stores e impossibilidade de criar arquivo no mount.
- `ContainerStartupDiagnostics` captura saída de inicialização em buffer limitado,
  retém classes/mensagens das causas e identifica PERMISSION, TLS, CONFIGURATION
  ou UNKNOWN. Substitui as senhas TLS/DB conhecidas e propriedades de senha por
  `[redacted]`. Não encadeia a exceção original não sanitizada no relatório.
- Testes unitários validam sanitização e classificação. Os cenários anteriores
  HTTPS, mTLS, JWT, PostgreSQL, indisponibilidade, healthcheck, SIGTERM e reinício
  permanecem no teste produtivo completo.

## Validação

A imagem produtiva foi reconstruída localmente, sem alteração de seu Dockerfile
ou código. Java/Maven do estágio de build foram extraídos para um diretório
descartável do Ubuntu WSL; fontes copiadas para filesystem Linux, fora do NTFS.
As imagens locais Auth/PostgreSQL/Ryuk foram carregadas no daemon Linux. Não foi
usado mock de TLS ou de banco, nem executado workflow remoto, push ou deploy.

Comando no Linux:

```text
mvn -B -ntp -Dmaven.repo.local=<cache-temporario> clean verify -Dauth.internal.image=oficina-auth-ci-linux:local
```

Resultado de 08/11/2026: **BUILD SUCCESS**, em 7 min 36 s, com Maven 3.9.9 e
Temurin 21.0.7+6 no Ubuntu WSL. Os containers executaram a imagem produtiva Java
21, com PostgreSQL 17.6 e as regressões existentes com PostgreSQL 16.6.

| Verificação | Resultado |
| --- | --- |
| Surefire Linux | 85 testes; 0 falhas, 0 erros, 0 skips |
| Failsafe Linux | 17 testes; 0 falhas, 0 erros, 0 skips |
| Total Linux | **102 testes; 0/0/0** |
| InternalContainerIT Linux | 1 teste aprovado, incluindo HTTPS, mTLS, JWT, UID 10001, volume readonly, PostgreSQL, SIGTERM e reinício |
| JaCoCo | Gate mínimo de 80% aprovado, sem exclusões novas |
| Diagnósticos no Windows | 2 testes unitários aprovados; compilação dos testes aprovada |
| Whitespace e escopo | git diff --check aprovado; nenhum diff em Dockerfile, pom.xml, .github ou src/main |

Log persistido: `.local-secrets/ci-linux-verify.log`, ignorado pelo Git. O log
contém também a reprodução negativa esperada com `Permission denied`, seguida
do acesso corrigido e do resultado Maven completo. Os XMLs/HTMLs gerados sob
`/tmp` não estavam disponíveis numa sessão WSL posterior; por isso não se afirma
um percentual exato de cobertura Linux além do gate comprovadamente aprovado.
Nenhum teste foi pulado para obter sucesso. O GitHub Actions remoto ainda deve
ser reexecutado pelo usuário após integrar a correção.

Arquivos deste patch:

- `src/test/java/br/com/fiap/oficina/auth/support/TestTls.java`.
- `src/test/java/br/com/fiap/oficina/auth/infrastructure/internal/InternalContainerIT.java`.
- `src/test/java/br/com/fiap/oficina/auth/infrastructure/internal/ContainerStartupDiagnostics.java` (novo).
- `src/test/java/br/com/fiap/oficina/auth/infrastructure/internal/ContainerStartupDiagnosticsTest.java` (novo).
- Este relatório.

## CI e recomendação

`.github/workflows/ci.yml` permanece somente de verificação: build Docker local,
Maven, checagem de evidências e upload de resumos de teste. Sem docker push,
publicação ECR, credenciais AWS ou deploy. Os arquivos produtivos e o workflow
não fazem parte do patch.

Após revisão, commit sugerido: `test(auth): fix non-root TLS fixture mounts on Linux`.
Não foi realizado commit ou push. A validação local Linux não substitui a próxima
execução do GitHub Actions após o usuário integrar a correção.
