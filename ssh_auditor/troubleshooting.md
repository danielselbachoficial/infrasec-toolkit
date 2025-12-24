🔍 **Troubleshooting**

Problema: SSH não reinicia após correções

Sintoma:
`
❌ FALHA CRÍTICA: SSH não reiniciou corretamente
`

**Solução:**

1. **Verifique o status do SSH:**
   ```bash
   sudo systemctl status sshd
   ```

2. **Verifique logs do sistema:**

   ```bash
   sudo journalctl -u sshd -n 50
   ```

3. **Teste a configuração manualmente:**
   ```bash
   sudo sshd -t -f /etc/ssh/sshd_config
   ```

4. **Restaure o backup se necessário:**
   ```bash
   sudo cp /var/backups/ssh_auditor/sshd_config.bak_TIMESTAMP /etc/ssh/sshd_config
   sudo systemctl restart sshd
   ```
   
Problema: Bloqueio de acesso SSH


**Prevenção:**
- ✅ Sempre execute --dry-run primeiro
- ✅ Mantenha acesso alternativo (console/IPMI/KVM)
- ✅ Configure pelo menos 1 usuário com chave SSH antes de desabilitar senha
- ✅ Teste a chave SSH em nova sessão antes de fechar a atual


**Recuperação:**

1. **Acesse via console físico ou IPMI**

2. **Restaure o backup:**
  ```bash
   sudo cp /var/backups/ssh_auditor/sshd_config.bak_TIMESTAMP /etc/ssh/sshd_config
   sudo systemctl restart sshd
   ```

Problema: DeprecationWarning

**Sintoma:**
```bash
DeprecationWarning: datetime.datetime.utcnow() is deprecated
```
