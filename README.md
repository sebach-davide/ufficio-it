# Ufficio IT

Ufficio di agenti Claude per l'IT di Sebach. Primo reparto: **Segnalazioni** (bug e CR di Sebach Plus).

- `src/worker.src.js`, `src/dashboard.html`, `src/login.html`: Worker e dashboard. `node build.mjs` genera `worker.js`.
- `schema.sql`: tabelle del database D1 `ufficio-it`.
- `agenti/`: copia di riferimento delle istruzioni degli agenti. Quelle usate davvero stanno in D1, tabella `istruzioni`.
- `bugtracker/worker.js`: bug tracker Sebach Plus con lo stato «Preso in carico».

Il Worker legge il bug tracker (D1 `sebachplus-bugs`) ogni 10 minuti, importa i ticket in stato Nuovo e avvia gli agenti. Gli agenti lavorano solo su `ufficio-it`; il bug tracker lo aggiorna il Worker: «Preso in carico» all'avvio, «Aperto» con l'ID DevOps quando Davide invia dalla Revisione.

Secret del Worker: `DASH_PASSWORD`, `SESSION_KEY`, `ROUTINE_URL`, `ROUTINE_TOKEN`.
