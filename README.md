# 🛡️ InfraSec Toolkit

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![Maintenance](https://img.shields.io/badge/Maintained-yes-green.svg)](https://github.com/danielselbach/infrasec-toolkit/graphs/commit-activity)

> Coleção de ferramentas profissionais para automação de segurança, hardening de sistemas Linux, auditoria de redes e gerenciamento de infraestrutura.

Desenvolvido para ambientes de produção críticos com foco em **conformidade**, **automação** e **segurança**.

---

## 📋 Sobre o Projeto

**InfraSec Toolkit** é uma coleção de ferramentas open-source desenvolvidas para profissionais de:

- 🔐 **Cibersegurança** - Auditoria, hardening, detecção de vulnerabilidades
- 🌐 **Redes** - Análise de tráfego, monitoramento, troubleshooting
- 🐧 **Linux SysAdmin** - Automação, configuração, gerenciamento
- ⚙️ **DevOps/SRE** - CI/CD security, infrastructure as code

### Princípios

✅ **Segurança por Design** - Todas as ferramentas seguem best practices  
✅ **Conformidade** - Alinhado com CIS Benchmark, NIST, LGPD  
✅ **Automação** - Redução de tarefas manuais e erros humanos  
✅ **Produção-Ready** - Testado em ambientes críticos  
✅ **Open Source** - Código aberto, auditável e extensível  

---

## 🛠️ Ferramentas Disponíveis

### SSH Auditor and Hardening Tool v1.0

**Status:** ✅ Estável e Pronto para Produção

Ferramenta enterprise para auditoria e hardening automatizado de servidores SSH com conformidade total aos padrões CIS Benchmark 5.2.x e NIST SP 800-123.

#### Funcionalidades Principais

- ✅ **Auditoria Completa** - Verifica 24+ parâmetros críticos de segurança SSH
- ✅ **Hardening Automático** - Aplica correções com validação de sintaxe
- ✅ **Detecção de Chaves Fracas** - Identifica chaves RSA <3072 bits (NIST SP 800-57)
- ✅ **Correção de Permissões** - Ajusta permissões de arquivos críticos automaticamente
- ✅ **Fail2ban Integration** - Instalação e configuração automática
- ✅ **Gerenciamento de Usuários** - Criação de usuários sudo com senhas seguras
- ✅ **Menu Interativo** - Interface intuitiva para facilitar o uso
- ✅ **Logging Estruturado** - Logs em JSON prontos para SIEM
- ✅ **Rollback Automático** - Restauração de backup em caso de falha
- ✅ **Dry-Run Mode** - Simulação de mudanças sem aplicar

#### Conformidade

- **CIS Benchmark 5.2.x** - SSH Server Configuration
- **NIST SP 800-123** - Guide to General Server Security
- **NIST SP 800-57** - Key Management (RSA 3072+ bits)
- **LGPD Art. 46** - Segurança da Informação
