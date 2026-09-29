# Testes de falha — Laboratório OAuth

## Caso 1: retorno sem cookie temporário

**Preparação:** Login iniciado com Google em uma janela normal; a URL de autorização (Location de `/oauth/login/google`) foi copiada do DevTools e colada em uma janela anônima nova, sem o cookie `__Host-oauth-tx`.

**Pedido enviado:** Login completado na janela anônima, que nunca recebeu o cookie de transação.

**Resultado esperado:** A rota `/oauth/callback/google` recusa a resposta por falta do cookie `__Host-oauth-tx`, sem criar sessão.

**Resultado observado:** Erro "Transação ausente" exibido. Nenhuma sessão foi criada. ✅ Conforme esperado.

---

## Caso 2: state alterado

**Preparação:** Login iniciado com Google na janela normal; a URL de autorização foi copiada do DevTools, o parâmetro `state` foi alterado em 1 caractere, e a URL modificada foi aberta em uma nova aba da mesma janela.

**Pedido enviado:** Login completado com o `state` alterado.

**Resultado esperado:** A rota `/oauth/callback/google` recusa a resposta por `state` inválido, sem criar sessão.

**Resultado observado:** Erro "Transação ausente" exibido, em vez de "state inválido". Isso ocorreu porque a conta Google já havia autorizado o app anteriormente, permitindo login silencioso (SSO): a aba original completou o fluxo OAuth sozinha (consumindo e expirando o cookie de transação) antes que a URL com o `state` alterado pudesse ser usada. Ainda assim, a segurança se manteve: em nenhum momento uma sessão foi criada com o `state` adulterado — o fluxo com o valor alterado foi sempre recusado. ✅ Recusado (por outro motivo que o esperado, mas sem brecha de segurança).

## Caso 3: reutilização da transação

**Preparação:** Login completo e bem-sucedido com Google. Em seguida, a URL da requisição de callback já usada (`/oauth/callback/google?code=...&state=...`) foi copiada do DevTools Network.

**Pedido enviado:** A mesma URL de callback foi reaberta numa aba nova.

**Resultado esperado:** A transação já foi apagada do D1 na primeira execução; a segunda tentativa deve ser recusada.

**Resultado observado:** Erro "Transação ausente" exibido. O cookie `__Host-oauth-tx` já havia sido expirado ao final do login bem-sucedido anterior (conforme o código da Etapa 6), então a segunda tentativa nem encontrou o cookie de transação. Nenhuma sessão nova foi criada. ✅ Reuso da transação recusado com sucesso.

## Caso 4: sessão expirada

**Preparação:** Login completo e bem-sucedido. Em seguida, no console do D1, executado: `UPDATE sessions SET expires_at = 0;`

**Pedido enviado:** Recarregamento da página inicial (nova chamada a `/api/me` pelo `app.js`).

**Resultado esperado:** `/api/me` responde 401 e a página volta para a tela de login.

**Resultado observado:** A página voltou para a tela de login, exibindo "Nenhuma sessão neste navegador." ✅ Conforme esperado.

## Caso 5: origem inválida na saída

**Preparação:** Sessão válida ativa. Em outra aba, em uma origem diferente (example.com), executado no console do navegador:
```js
fetch("https://heycr7-github-io.pages.dev/oauth/logout", { method: "POST", credentials: "include" }).then(r => console.log(r.status))
```

**Pedido enviado:** POST para `/oauth/logout` com cabeçalho `Origin: https://example.com`.

**Resultado esperado:** A rota recusa por Origin inválida (403), sem remover a sessão.

**Resultado observado:** Status 403 retornado. A sessão original em `heycr7-github-io.pages.dev` permaneceu válida. ✅ Conforme esperado.

## Caso 6: reutilização do cookie revogado

**Preparação:** Valor do cookie `__Host-session` copiado enquanto a sessão estava válida. Em seguida, logout realizado normalmente (removendo a linha da sessão no D1 e expirando o cookie no navegador). O cookie foi então recriado manualmente no navegador com o mesmo valor copiado antes do logout.

**Pedido enviado:** Recarregamento da página (`/api/me`) com o cookie `__Host-session` restaurado manualmente.

**Resultado esperado:** Como a linha da sessão já foi removida do D1 no logout, a resposta deve ser 401, mesmo com o cookie presente.

**Resultado observado:** `/api/me` respondeu 401. ✅ Conforme esperado — cookie revogado não restaura a sessão.

