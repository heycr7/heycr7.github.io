// public/app.js
fetch("/api/me", { credentials: "same-origin" })
  .then((response) => (response.ok ? response.json() : null))
  .then((user) => {
    const status = document.getElementById("status");
    const loggedOutArea = document.getElementById("logged-out-area");
    const loggedInArea = document.getElementById("logged-in-area");

    if (user) {
      status.textContent = `Sessão de ${user.email ?? user.displayName}.`;
      loggedOutArea.style.display = "none";
      loggedInArea.style.display = "block";
    } else {
      status.textContent = "Nenhuma sessão neste navegador.";
      loggedOutArea.style.display = "block";
      loggedInArea.style.display = "none";
    }
  })
  .catch(() => {
    document.getElementById("status").textContent = "Não foi possível consultar a sessão.";
  });
