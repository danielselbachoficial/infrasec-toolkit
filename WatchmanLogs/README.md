# 🛡️ WatchmanLogs

> Script educacional para análise de logs do Apache2 com foco em detecção de ataques, vigilância responsável e boas práticas de segurança.

---

## 📋 Sobre o Projeto

**WatchmanLogs** é um script em Shell desenvolvido para auxiliar estudantes e profissionais de cibersegurança na análise manual e automatizada de logs do Apache2.

Seu objetivo é identificar padrões suspeitos, tentativas de ataque e comportamentos anômalos, promovendo:

- ✅ Responsabilidade técnica  
- ✅ Proteção de sistemas  
- ✅ Ética profissional  
- ✅ Mordomia digital  

Este projeto faz parte de um processo educacional, incentivando o aprendizado prático sem dependência de Inteligência Artificial.

---

## 🎯 Objetivo

Desenvolver um script simples para:

- Analisar arquivos `access.log`
- Identificar possíveis ataques
- Apoiar investigações iniciais
- Fortalecer a postura defensiva

---

## 🛠️ Requisitos

- Linux
- Bash / Shell
- Apache2
- Arquivo de log (`access.log`)
- Ferramentas básicas: `grep`, `cut`, `sort`, `uniq`, `head`, `tail`

---

## 🚀 Como Utilizar

### 1. Clone o repositório:

```bash
git clone https://github.com/seu-usuario/watchmanlogs.git
cd watchmanlogs
```

### 2. Dê permissão de execução:
```bash
chmod +x watchmanlogs.sh
```
### 3. Execute o script:
```bash
./watchmanlogs.sh access.log
```


## 🔍 Funcionalidades de Análise

### 1️⃣ Detecção de XSS (Cross-Site Scripting)
```bash
grep -iE "<script|%3Cscript" access.log
```

Busca por tentativas de injeção de scripts.

### 2️⃣ Detecção de SQL Injection
```bash
grep -iE "union|select|insert|drop|%27|%22" access.log
```

Identifica padrões comuns de ataques SQL.

### 3️⃣ Directory Traversal
```bash
grep -E "\.\./|\.\.%2f" access.log
```

Detecta tentativas de navegação indevida em diretórios.

### 4️⃣ Detecção de Scanners
```bash
grep -iE "nikto|nmap|sqlmap|acunetix|curl|masscan|python" access.log
```

Localiza ferramentas automatizadas de varredura.

### 5️⃣ Acesso a Arquivos Sensíveis
```bash
grep -iE "\.env|\.git|\.htaccess|\.bak" access.log
```

Detecta tentativas de acesso a arquivos críticos.

### 6️⃣ Possível Força Bruta (404)
```bash
grep " 404 " access.log | cut -d " " -f 1 | sort | uniq -c | sort -nr | head
```

Lista IPs com alto número de erros 404.

### 7️⃣ Primeiro e Último Acesso de um IP
```bash
grep "IP" access.log | head -n1
grep "IP" access.log | tail -n1
```

Auxilia na análise temporal de atividades suspeitas.

### 8️⃣ User-Agent de IP Suspeito
```bash
grep "IP_SUSPEITO" access.log | cut -d '"' -f 6 | sort | uniq
```

Identifica ferramentas utilizadas pelo atacante.

### 9️⃣ Contagem de Requisições por IP
```bash
cat access.log | cut -d " " -f 1 | sort | uniq -c
```

Mostra volume de acessos por endereço.

### 🔟 Acesso a Arquivo Específico
```bash
grep "arquivosensivel" access.log
```

Localiza tentativas direcionadas a arquivos definidos.

📚 Estrutura do Projeto
```bash
watchmanlogs/
├── watchmanlogs.sh
├── README.md
└── examples/
    └── sample-access.log
```
