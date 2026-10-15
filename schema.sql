CREATE TABLE IF NOT EXISTS impostazioni (chiave TEXT PRIMARY KEY, valore TEXT, aggiornato TEXT DEFAULT (datetime('now')));
CREATE TABLE IF NOT EXISTS reparti (id TEXT PRIMARY KEY, nome TEXT NOT NULL, colore TEXT NOT NULL, ordine INTEGER NOT NULL, area TEXT NOT NULL DEFAULT 'segnalazioni', descrizione TEXT, prompt TEXT);
CREATE TABLE IF NOT EXISTS agenti (id TEXT PRIMARY KEY, reparto_id TEXT NOT NULL, nome TEXT NOT NULL, ruolo TEXT, lead INTEGER DEFAULT 0, stato TEXT DEFAULT 'idle', attivita TEXT, aggiornato TEXT DEFAULT (datetime('now')));
CREATE TABLE IF NOT EXISTS segnalazioni (id INTEGER PRIMARY KEY AUTOINCREMENT, ticket_id INTEGER NOT NULL UNIQUE, codice TEXT, tipo_originale TEXT, titolo_originale TEXT, area TEXT, operazione TEXT, documento TEXT, errore TEXT, atteso TEXT, pro_check TEXT, severita TEXT, senza_messaggio INTEGER DEFAULT 0, tag TEXT, autore TEXT, autore_ruolo TEXT, ticket_stato TEXT, ticket_creato TEXT, ticket_aggiornato TEXT, note_ticket TEXT, allegati TEXT, stato TEXT NOT NULL DEFAULT 'nuova', tipo TEXT, tipo_motivo TEXT, modulo TEXT, priorita TEXT, permessi TEXT, permessi_analisi TEXT, doppione_di INTEGER, note_agenti TEXT, nota_davide TEXT, respingi_motivo TEXT, notificata_il TEXT, creato TEXT DEFAULT (datetime('now')), aggiornato TEXT DEFAULT (datetime('now')));
CREATE TABLE IF NOT EXISTS uscite (id INTEGER PRIMARY KEY AUTOINCREMENT, segnalazione_id INTEGER NOT NULL UNIQUE, tipo TEXT, titolo TEXT, testo TEXT, priorita TEXT, versione_agente TEXT, stato TEXT NOT NULL DEFAULT 'pronta', modificata INTEGER DEFAULT 0, motivo TEXT, devops_id TEXT, inviata_il TEXT, creato TEXT DEFAULT (datetime('now')), aggiornato TEXT DEFAULT (datetime('now')));
CREATE TABLE IF NOT EXISTS modifiche (id INTEGER PRIMARY KEY AUTOINCREMENT, uscita_id INTEGER NOT NULL, segnalazione_id INTEGER NOT NULL, campo TEXT NOT NULL, prima TEXT, dopo TEXT, analizzata INTEGER DEFAULT 0, creato TEXT DEFAULT (datetime('now')));
CREATE TABLE IF NOT EXISTS brain (id INTEGER PRIMARY KEY AUTOINCREMENT, tipo TEXT NOT NULL DEFAULT 'nota', titolo TEXT NOT NULL, contenuto TEXT, tag TEXT, fonte TEXT, attivo INTEGER DEFAULT 1, reparto_id TEXT, creato TEXT DEFAULT (datetime('now')), aggiornato TEXT DEFAULT (datetime('now')));
CREATE TABLE IF NOT EXISTS task (id INTEGER PRIMARY KEY AUTOINCREMENT, reparto_id TEXT, agente_id TEXT, titolo TEXT NOT NULL, dettaglio TEXT, origine TEXT DEFAULT 'agente', stato TEXT NOT NULL DEFAULT 'backlog', progresso INTEGER DEFAULT 0, creato TEXT DEFAULT (datetime('now')), aggiornato TEXT DEFAULT (datetime('now')));
CREATE TABLE IF NOT EXISTS eventi (id INTEGER PRIMARY KEY AUTOINCREMENT, reparto_id TEXT, agente_id TEXT, tipo TEXT NOT NULL DEFAULT 'info', messaggio TEXT NOT NULL, creato TEXT DEFAULT (datetime('now')));
CREATE TABLE IF NOT EXISTS chat (id INTEGER PRIMARY KEY AUTOINCREMENT, reparto_id TEXT NOT NULL, mittente TEXT NOT NULL, testo TEXT NOT NULL, stato TEXT NOT NULL DEFAULT 'nuovo', creato TEXT DEFAULT (datetime('now')));
CREATE TABLE IF NOT EXISTS istruzioni (chiave TEXT PRIMARY KEY, testo TEXT NOT NULL, aggiornato TEXT DEFAULT (datetime('now')));
CREATE INDEX IF NOT EXISTS idx_segn_stato ON segnalazioni(stato);
CREATE INDEX IF NOT EXISTS idx_uscite_stato ON uscite(stato);
CREATE INDEX IF NOT EXISTS idx_mod_analizzata ON modifiche(analizzata);
CREATE INDEX IF NOT EXISTS idx_brain_tipo ON brain(tipo, attivo);
CREATE INDEX IF NOT EXISTS idx_eventi_creato ON eventi(creato);
CREATE INDEX IF NOT EXISTS idx_task_stato ON task(stato);
CREATE INDEX IF NOT EXISTS idx_chat_reparto ON chat(reparto_id, creato);
INSERT OR IGNORE INTO reparti (id, nome, colore, ordine, area, descrizione) VALUES
('accettazione', 'Accettazione', '#3fa7d6', 1, 'segnalazioni', 'Riceve i ticket nuovi dal bug tracker, controlla i doppioni e prepara il fascicolo per gli altri.'),
('triage', 'Triage', '#d9a93f', 2, 'segnalazioni', 'Decide se è un BUG o una CR, assegna modulo e priorità.'),
('permessi', 'Permessi', '#d95f7f', 3, 'segnalazioni', 'Valuta se il problema può dipendere da ruoli, profili o permessi utente, usando i documenti del Brain.'),
('redazione', 'Redazione', '#2bb59a', 4, 'segnalazioni', 'Riscrive la segnalazione pulita e pronta da inviare, applicando le lezioni imparate dalle tue modifiche.'),
('revisione', 'Revisione', '#8e6bd8', 5, 'segnalazioni', 'La tua stanza: qui trovi tutto ciò che è pronto da inviare. La modifichi, la invii, e il Brain impara dalle tue correzioni.');
INSERT OR IGNORE INTO reparti (id, nome, colore, ordine, area, descrizione) VALUES ('monitoraggio', 'Monitoraggio', '#e0884a', 6, 'segnalazioni', 'Segue i ticket inviati fino alla risoluzione, misura i tempi del fornitore in giorni lavorativi e il lunedì scrive una valutazione.');
INSERT OR IGNORE INTO reparti (id, nome, colore, ordine, area, descrizione) VALUES ('cr', 'Change Request', '#9aa84a', 7, 'segnalazioni', 'Il magazzino delle CR: tiene quelle archiviate (Sospese, senza ID DevOps) finché non decidete di farle, poi le segue da Approvate a Risolte.');
INSERT OR IGNORE INTO agenti (id, reparto_id, nome, ruolo, lead) VALUES
('acc-lead', 'accettazione', 'Lead Accettazione', 'Smista i ticket nuovi', 1),
('acc-dup', 'accettazione', 'Doppioni', 'Cerca segnalazioni uguali o collegate', 0),
('tri-lead', 'triage', 'Lead Triage', 'BUG o CR', 1),
('tri-pri', 'triage', 'Priorità e modulo', 'Gravità, area, modulo', 0),
('per-lead', 'permessi', 'Lead Permessi', 'Ipotesi su ruoli e permessi', 1),
('per-prof', 'permessi', 'Profili utente', 'Confronta con i profili nel Brain', 0),
('red-lead', 'redazione', 'Redattore', 'Testo pronto da inviare', 1),
('red-stile', 'redazione', 'Stile e lezioni', 'Applica le correzioni di Davide', 0),
('rev-davide', 'revisione', 'Davide', 'Rivede, modifica e invia', 1),
('mon-lead', 'monitoraggio', 'Analista tempi', 'Tempi del fornitore e report settimanale', 1),
('cr-arch', 'cr', 'Archivista', 'Custodisce le CR archiviate', 1);
INSERT OR IGNORE INTO impostazioni (chiave, valore) VALUES ('auto', '1');
INSERT OR IGNORE INTO eventi (id, tipo, messaggio) VALUES (1, 'info', 'Ufficio IT creato. Primo reparto: Segnalazioni Sebach Plus.');
CREATE TABLE IF NOT EXISTS allegati (id INTEGER PRIMARY KEY AUTOINCREMENT, segnalazione_id INTEGER, ticket_id INTEGER NOT NULL, origine_id INTEGER UNIQUE, nome TEXT, mime TEXT, size INTEGER, data TEXT, creato TEXT DEFAULT (datetime('now')));
CREATE TABLE IF NOT EXISTS tempi (ticket_id INTEGER PRIMARY KEY, codice TEXT, titolo TEXT, tipo TEXT, modulo TEXT, priorita TEXT, fonte_priorita TEXT, devops_id TEXT, stato TEXT, creato TEXT, aperto_il TEXT, risolto_il TEXT, gg_nostri REAL, gg_fornitore REAL, esito TEXT);
CREATE TABLE IF NOT EXISTS report (id INTEGER PRIMARY KEY AUTOINCREMENT, tipo TEXT NOT NULL DEFAULT 'fornitore', periodo TEXT, testo TEXT NOT NULL, creato TEXT DEFAULT (datetime('now')));
CREATE TABLE IF NOT EXISTS push (endpoint TEXT PRIMARY KEY, dati TEXT, browser TEXT, creato TEXT DEFAULT (datetime('now')));
