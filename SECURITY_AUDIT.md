# Relatório de Auditoria de Segurança - NebulaAuth.jl

**Data da Auditoria:** 21 de Maio de 2026
**Escopo:** Todo o projeto (Código-fonte principal em `src/`)

Abaixo estão listadas as vulnerabilidades, inconsistências lógicas e falhas técnicas encontradas durante a investigação profunda no projeto NebulaAuth.jl. Os problemas foram categorizados por Criticidade, Impacto e Probabilidade de serem explorados.

---

## 1. Bug Lógico de Negação de Serviço em `removePermission`
- **Severidade:** **CRÍTICA**
- **Impacto:** Alto (Impossibilidade de revogar permissões concedidas a usuários).
- **Probabilidade:** Alta (100% de falha ao executar a função).
- **Arquivo:** `src/roles.jl`
- **Descrição:** Na função `removePermission(user_id::Int, permission::String)`, o código tenta encontrar a permissão atribuída comparando o ID inteiro do banco de dados com a String de entrada: `if perm.permissionId == permission`. Em Julia, essa comparação (`Int == String`) sempre retorna `false`. Consequentemente, a variável `existing` permanece `nothing` e a chamada `delete!(existing)` resulta em um `MethodError` (crash da aplicação).
- **Recomendação:** Buscar o modelo `OrionAuth_Permission` usando a string fornecida e, em seguida, comparar `perm.permissionId == permission_model.id`, assim como é feito na função `assignPermission`.

## 2. Vulnerabilidade a Ataques de Tempo (Timing Attack) em Assinaturas JWT
- **Severidade:** **ALTA**
- **Impacto:** Alto (Possibilidade de forjar tokens JWT válidos e assumir identidades).
- **Probabilidade:** Média (Exige tempo e rede estáveis, mas é um vetor clássico).
- **Arquivo:** `src/jwt.jl`
- **Descrição:** A função `__ORION__Verify` compara a assinatura calculada com a assinatura recebida usando o operador padrão de igualdade (`==`). Em Julia, a comparação de strings faz "short-circuit", ou seja, é interrompida no primeiro caractere diferente. Isso permite que um invasor descubra a assinatura correta medindo o tempo de resposta do servidor (HMAC timing attack).
- **Recomendação:** Utilizar uma função de comparação em tempo constante (Constant-Time Compare) para a verificação de assinaturas (ex: equivalente a `crypto_verify` do libsodium ou comparando o hash de ambos).

## 3. Race Condition (TOCTOU) e Falta de Restrição UNIQUE em Cadastros
- **Severidade:** **MÉDIA**
- **Impacto:** Médio/Alto (Contas duplicadas, possíveis falhas de lógica de autenticação).
- **Probabilidade:** Média.
- **Arquivo:** `src/auth.jl` (função `signup`) e `src/OrionAuth.jl` (Modelos).
- **Descrição:** O schema do banco de dados (`OrionAuth_User`) não define a coluna `email` com restrição `UNIQUE`. Na função `signup`, o sistema verifica se o usuário existe com um `findFirst` antes de inseri-lo. Se duas requisições simultâneas ocorrerem para o mesmo email, ambas passarão pela verificação e criarão duas contas distintas com o mesmo email.
- **Recomendação:** Adicionar uma restrição UNIQUE no nível do banco de dados para a coluna de e-mail e tratar a exceção adequadamente na camada da aplicação.

## 4. Inconsistência de Fuso Horário (Timezone) na Expiração de Reset de Senha
- **Severidade:** **MÉDIA**
- **Impacto:** Médio (Tokens podem expirar instantaneamente ou durar horas além do esperado).
- **Probabilidade:** Alta (Depende exclusivamente do fuso horário do servidor/banco).
- **Arquivo:** `src/password_reset.jl`
- **Descrição:** A função `verify_reset_token` verifica a validade do token somando minutos ao `created_at` (que vem do banco de dados via `CURRENT_TIMESTAMP()`, normalmente em UTC) e comparando com `Dates.now()`, que retorna o horário local do servidor. Se o servidor não estiver em UTC, o token poderá ser invalidado assim que for gerado ou ficar aberto por horas.
- **Recomendação:** Usar `Dates.now(UTC)` consistentemente ou padronizar as datas ao parsear o valor do banco de dados.

## 5. Enumeração de Usuários na Autenticação (User Enumeration)
- **Severidade:** **BAIXA**
- **Impacto:** Baixo (Revelação de emails cadastrados).
- **Probabilidade:** Alta.
- **Arquivo:** `src/auth.jl` (função `signin`).
- **Descrição:** A função `signin` retorna mensagens de erro diferentes quando um email não existe (`"User not found"`) e quando a senha está incorreta (`"Invalid password"`). Além da diferença nas mensagens, a verificação de senha cara (Argon2) não é executada se o usuário não for encontrado, revelando via tempo de resposta quais emails existem no sistema.
- **Recomendação:** Retornar uma mensagem genérica (ex: "E-mail ou senha incorretos") e realizar um hash (dummy verify) em tempo constante mesmo se o usuário não existir, para mitigar oráculos de tempo.

## 6. Ausência de Proteção contra Força Bruta (Rate Limiting)
- **Severidade:** **MÉDIA**
- **Impacto:** Médio/Alto (Contas podem ser comprometidas por ataques de dicionário se as senhas forem fracas).
- **Probabilidade:** Alta.
- **Arquivo:** `src/auth.jl`
- **Descrição:** O framework não possui nenhum mecanismo nativo de limitação de tentativas de login ou bloqueio de conta temporário.
- **Recomendação:** Implementar rate limiting por IP/Usuário no módulo de auth, ou pelo menos documentar que essa responsabilidade deve ser delegada a proxies ou firewalls da camada da aplicação.

## 7. Acesso Inseguro a Claims do JWT
- **Severidade:** **BAIXA**
- **Impacto:** Baixo (Internal Server Error 500).
- **Probabilidade:** Baixa.
- **Arquivo:** `src/auth.jl` (função `Auth`).
- **Descrição:** Na função `Auth`, a linha `payload["permissions"]` extrai a claim diretamente. Se um token mais antigo ou modificado maliciosamente não contiver essa chave, a aplicação lançará um `KeyError`, gerando um erro 500 ao invés de um tratamento apropriado (ex: 401/403).
- **Recomendação:** Utilizar `get(payload, "permissions", [])` ao invés do acesso direto.

---

## 8. Conformidade com Padrões de Segurança

O NebulaAuth.jl demonstra uma base sólida seguindo princípios modernos, mas ainda carece de rigor em aspectos de controle de fluxo e arquitetura defensiva.

- **OWASP Top 10 (Adesão Parcial):**
    - **A01:2021-Broken Access Control:** Atendido parcialmente com RBAC, mas vulnerável devido ao bug crítico em `removePermission` e falta de `UNIQUE` no banco.
    - **A02:2021-Cryptographic Failures:** Atendido com Argon2id por padrão, mas falha em mitigar Timing Attacks em assinaturas JWT.
    - **A07:2021-Identification and Authentication Failures:** Falta proteção nativa contra força bruta (Rate Limiting).
- **NIST SP 800-63B (Guidelines de Senhas):**
    - **Aderente:** Uso de Argon2id e hashing adaptável é o padrão ouro recomendado.
    - **O que falta:** Implementar verificação de "senhas comuns/vazadas" e melhorar oráculos de tempo na autenticação.

## 9. Avaliação de Qualidade e Segurança

- **Nível de Qualidade:** **Médio-Alto**. O código é limpo, bem documentado (Docstrings) e possui uma abstração de adaptadores HTTP muito inteligente e desacoplada. A estrutura de módulos é coerente.
- **Nível de Segurança:** **Médio (Beta/Early Stage)**. Embora utilize primitivas criptográficas fortes (libsodium/Nettle), as falhas de lógica em funções de gerenciamento de permissões e as vulnerabilidades a ataques de canal lateral (timing) impedem que o sistema seja considerado "Production-Ready" para aplicações de alto risco.

## 10. Adequação da Aplicação

| Tipo de Aplicação | Adequação | Justificativa | O que melhorar |
| :--- | :---: | :--- | :--- |
| **MVPs e Protótipos** | **Excelente** | Rápida integração com framework Oxygen e Genie; setup imediato de DB. | Nada urgente para esta fase. |
| **SaaS B2B de Baixo Risco** | **Boa** | RBAC flexível e suporte a JWT facilitam integrações front-end. | Corrigir bugs de revogação de permissão e adicionar Rate Limit. |
| **Aplicações Fintech/Saúde** | **Não Recomendado** | Falta de trilhas de auditoria imutáveis e proteção contra ataques de tempo. | Implementar Constant-Time compare, MFA e logs de segurança assinados. |
| **Enterprise de Grande Escala** | **Moderada** | Depende muito da maturidade do OrionORM para lidar com volumes massivos. | Adicionar suporte a Refresh Tokens (atualmente apenas Access Tokens) e Revogação (Blacklist). |

---
**Fim do Relatório Expandido**