# 🛡️ Relatório de Auditoria de Segurança - NebulaAuth.jl (V2)

**Data da Auditoria:** 21 de Maio de 2026  
**Versão:** 2.0 (Executive & Technical Review)  
**Escopo:** Todo o projeto (Código-fonte principal em `src/`)  

---

## 📑 1. Sumário Executivo

O projeto **NebulaAuth.jl** passou por uma rigorosa auditoria de segurança estática. A arquitetura geral do sistema é inteligente, modular e adota práticas criptográficas modernas e robustas (como o uso de *Argon2id*). No entanto, o sistema encontra-se em um estágio de maturidade que exige atenção imediata a certas falhas de implementação lógica antes de ser promovido para ambientes de produção. 

Foram identificadas **7 vulnerabilidades**, destacando-se uma falha crítica de *Denial of Service (DoS)* no controle de acesso e vulnerabilidades clássicas de canais laterais (*Timing Attacks*).

### 📊 Dashboard de Riscos
| Severidade | Quantidade | Ação Exigida |
| :---: | :---: | :--- |
| 🔴 **CRÍTICA** | 1 | **Imediata (Hotfix)** |
| 🟠 **ALTA** | 1 | **Curto Prazo (Próxima Release)** |
| 🟡 **MÉDIA** | 3 | **Médio Prazo** |
| 🟢 **BAIXA** | 2 | **Longo Prazo (Backlog)** |

---

## 🔬 2. Descobertas Técnicas Detalhadas

### 🔴 2.1. Bug Lógico e Negação de Serviço (DoS) em `removePermission`
* **Impacto:** Impossibilidade de revogar permissões; Crash da aplicação (Erro 500).
* **Arquivo:** `src/roles.jl`
* **Detalhes Técnicos:** A função `removePermission(user_id::Int, permission::String)` tenta validar a existência da permissão com `if perm.permissionId == permission`. Em Julia, comparar um `Int` (ID do banco) com uma `String` sempre resulta em `false`. O fluxo segue com a variável `existing` nula, resultando em um `MethodError` na chamada `delete!(existing)`.
* **Remediação:** Buscar o modelo `OrionAuth_Permission` usando a string fornecida e comparar os IDs numéricos.

### 🟠 2.2. Vulnerabilidade a Ataques de Tempo (Timing Attack) no JWT
* **Impacto:** Possibilidade de forjar tokens e assumir identidades por meio de ataque de oráculo de tempo.
* **Arquivo:** `src/jwt.jl`
* **Detalhes Técnicos:** Na função `__ORION__Verify`, a comparação da assinatura é feita usando `==`. Este operador realiza *short-circuit evaluation*, retornando em tempos diferentes dependendo de qual caractere falha primeiro.
* **Remediação:** Substituir `==` por uma função de comparação de strings em tempo constante (Constant-Time Compare).

### 🟡 2.3. Condição de Corrida (TOCTOU) no Cadastro de Usuários
* **Impacto:** Contas duplicadas sob o mesmo email, o que pode corromper a lógica de recuperação de senha e login.
* **Arquivo:** `src/auth.jl` (`signup`) & `src/OrionAuth.jl` (Schema)
* **Detalhes Técnicos:** A verificação se um email já existe (`findFirst`) e a sua posterior inserção (`create`) não são atômicas. Múltiplos requests paralelos podem passar pela verificação antes da primeira inserção ocorrer. Além disso, falta uma restrição `UNIQUE` na tabela SQL.
* **Remediação:** Adicionar a constraint `UNIQUE` ao banco de dados no schema do OrionORM e usar blocos try-catch para tratar a violação da constraint no nível da aplicação.

### 🟡 2.4. Inconsistência de Fuso Horário (Timezone) na Expiração de Tokens
* **Impacto:** Tokens de redefinição de senha expirando prematuramente ou permanecendo válidos por tempo indeterminado.
* **Arquivo:** `src/password_reset.jl`
* **Detalhes Técnicos:** A função `verify_reset_token` mistura tempos UTC do banco de dados (`CURRENT_TIMESTAMP()`) com o horário local do servidor (`Dates.now()`). Se o servidor não rodar em UTC, a matemática de expiração falhará.
* **Remediação:** Padronizar todas as verificações de tempo para usar `Dates.now(UTC)` e garantir que o ORM também serialize em UTC.

### 🟡 2.5. Ausência de Proteção contra Força Bruta (Rate Limiting)
* **Impacto:** Suscetibilidade a ataques de preenchimento de credenciais (Credential Stuffing) e Dicionário.
* **Arquivo:** `src/auth.jl`
* **Detalhes Técnicos:** Os endpoints de login e reset de senha podem ser chamados infinitamente.
* **Remediação:** Implementar limites de taxa (Rate Limiting) baseados em IP ou nome de usuário, ou documentar formalmente a necessidade de um WAF/Gateway reverso.

### 🟢 2.6. Enumeração de Usuários (User Enumeration)
* **Impacto:** Divulgação da base de clientes (Information Disclosure).
* **Arquivo:** `src/auth.jl` (`signin`)
* **Detalhes Técnicos:** O sistema retorna `"User not found"` rapidamente, enquanto para senhas incorretas gasta processamento com Argon2, permitindo descobrir emails válidos via tempo de resposta e conteúdo do erro.
* **Remediação:** Unificar a mensagem de erro para "Credenciais inválidas" e realizar um hash dummy quando o usuário não existir.

### 🟢 2.7. Acesso Inseguro a Claims do JWT
* **Impacto:** Quebra inesperada da aplicação (Erro 500).
* **Arquivo:** `src/auth.jl` (`Auth`)
* **Detalhes Técnicos:** O acesso direto à chave de dicionário via `payload["permissions"]` causará um `KeyError` se um token for gerado sem essa claim.
* **Remediação:** Usar funções seguras como `get(payload, "permissions", [])`.

---

## 🏛️ 3. Conformidade, Qualidade e Arquitetura

### 3.1. Conformidade com Padrões Globais
* **NIST SP 800-63B:** **Alto alinhamento.** A utilização do *Argon2id* com limites de memória e operações configuráveis segue as melhores e mais recentes práticas recomendadas pelo NIST para armazenamento de segredos.
* **OWASP Top 10 (2021):** **Alinhamento Parcial.** 
    * A robustez criptográfica protege contra o *A02: Cryptographic Failures*.
    * Precisa melhorar em *A01: Broken Access Control* (devido aos bugs do RBAC) e *A07: Identification and Authentication Failures* (pela falta de rate limiting e proteção de oráculos temporais).

### 3.2. Avaliação Arquitetural
O NebulaAuth.jl apresenta uma excelente **coesão e baixo acoplamento**, destacando-se:
1. **Design de Adaptadores HTTP:** A abstração do contexto (`RequestContext`) permitindo suporte fluído a Genie, Oxygen e HTTP.jl é um padrão arquitetural brilhante.
2. **Uso Eficiente do Sistema de Tipos:** A seleção de algoritmos de senha via *Multiple Dispatch* (`AbstractPasswordAlgorithm`) facilita imensamente a evolução e a adoção futura de novos hashes.

---

## 🎯 4. Adequação da Aplicação (Market Fit)

| Segmento de Aplicação | Grau de Recomendação | Observações & Bloqueadores |
| :--- | :---: | :--- |
| **Startups, MVPs e Prototipagem** | ⭐⭐⭐⭐⭐ **(Excelente)** | *Plug-and-play* rápido com frameworks modernos do ecossistema Julia. Seguro o suficiente para validação de produto. |
| **SaaS B2B de Risco Baixo/Médio** | ⭐⭐⭐⭐ **(Boa)** | O RBAC é flexível e atende bem. Bloqueador: *Correção do bug crítico em `removePermission` é obrigatória.* |
| **Sistemas Corporativos de Larga Escala** | ⭐⭐⭐ **(Moderada)** | Bloqueador: *Requer implementação de Refresh Tokens e mecanismo de revogação de tokens (Blacklist/JTI).* |
| **Fintech, Saúde (HIPAA) e GovTech** | ⭐⭐ **(Não Recomendado)** | Bloqueador: *Ausência de Autenticação Multifator (MFA), proteção severa contra Timing Attacks e trilhas de auditoria criptograficamente assinadas.* |

---

## 🚀 5. Plano de Ação (Remediation Roadmap)

Para elevar o NebulaAuth.jl ao status de **Production-Ready**, recomenda-se a seguinte ordem de execução:

1. **Sprint 1 (Hotfixes - Imediato):**
   * Corrigir a comparação de tipos em `removePermission`.
   * Padronizar as datas em `verify_reset_token` para `UTC`.
   * Usar `get()` para acessar propriedades seguras no `payload` JWT.
2. **Sprint 2 (Segurança Criptográfica e Integridade):**
   * Implementar `Constant-Time Compare` no processo de verificação JWT.
   * Adicionar restrição `UNIQUE` na modelagem do banco de dados (OrionORM) para o e-mail.
3. **Sprint 3 (Melhorias de Resiliência):**
   * Unificar mensagens de erro no login e mitigar oráculos de tempo (Dummy Hash).
   * Implementar ou documentar formalmente a estratégia de Rate Limiting.