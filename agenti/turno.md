TURNO SEGNALAZIONI
Parte quando il Worker trova lavoro (controllo ogni 10 minuti) o quando Davide preme AVVIA ORA. Il messaggio di avvio dice cosa c'è in coda.

0. Studio delle correzioni (Redazione, agente red-stile): SELECT * FROM modifiche WHERE analizzata=0 ORDER BY segnalazione_id, id. Per ogni segnalazione confronta prima e dopo e ricava regole generali e riutilizzabili: stile, lunghezza, termini, struttura, classificazione BUG/CR, priorità; campo nota_rifai = Davide ha rimandato indietro con una nota; campo scartata = Davide l'ha scartata con un motivo. Una lezione è una regola chiara di 1-3 righe. Se esiste già una lezione simile aggiornala (UPDATE brain SET contenuto=..., aggiornato=datetime('now')) invece di duplicarla; altrimenti INSERT INTO brain (tipo, titolo, contenuto, tag, fonte, reparto_id) VALUES ('lezione', <titolo>, <regola>, <tag>, 'modifiche #id,...', 'redazione'). Non creare lezioni da un singolo refuso corretto. Poi UPDATE modifiche SET analizzata=1 per quelle studiate.

1. Accettazione (acc-lead, acc-dup): SELECT * FROM segnalazioni WHERE stato='nuova' ORDER BY id. Lavorale TUTTE, una alla volta, fino in fondo ai passi 2-4. Per ognuna: UPDATE segnalazioni SET stato='in_lavoro', aggiornato=datetime('now'). Cerca doppioni tra le segnalazioni degli ultimi 60 giorni (stesso problema, stessa area o funzione): se è un doppione certo imposta doppione_di=<id della segnalazione originale> e scrivilo in note_agenti; continua comunque il giro.

2. Triage (tri-lead, tri-pri): decidi il tipo BUG o CR.
   - Regola fissa: se l'errore si presenta anche su Sebach Pro (pro_check='anche_su_pro') è una CR.
   - Una funzione mai prevista o una richiesta di cambiamento è una CR; un malfunzionamento di qualcosa che dovrebbe già funzionare è un BUG.
   Scrivi tipo, tipo_motivo (una riga), modulo (area o funzione di Sebach Plus) e priorita tra bloccante, alta, media, bassa: parti dalla gravità indicata dall'utente (severita) e correggila se il testo dice altro (es. "non è bloccante").

3. Permessi (per-lead, per-prof): valuta se la causa può essere un problema di ruoli, profili o permessi utente. Segnali tipici: succede solo con un certo utente o profilo (es. concessionario, area C-), errori di permesso o di accesso, campi o tabelle non visibili o non modificabili, funziona per altri utenti. Usa documenti e nozioni del Brain sui profili. Imposta permessi a 'probabile', 'possibile' o 'escluso' e scrivi in permessi_analisi 2-4 righe: perché, quale profilo o permesso controllare, quale documento del Brain hai usato. Se per decidere ti manca un documento che nel Brain non c'è, dillo chiaramente.

4. Redazione (red-lead, red-stile): scrivi il testo pronto da inviare, applicando prima le lezioni del Brain.
   Se Davide ha lasciato una nota (nota_davide), seguila prima di tutto.
   Struttura di partenza:
   - titolo: breve e specifico, nella forma "modulo: problema".
   - testo: contesto (utente o profilo, menù o area, documento se c'è); passi per riprodurre, numerati e dedotti dal ticket senza inventare; risultato atteso; risultato ottenuto (con il messaggio di errore, oppure "nessun messaggio a video"); impatto; ipotesi permessi se probabile o possibile; cosa mostrano gli allegati (es. «screenshot: errore 'Valore non valido' sulla maschera Anagrafica cliente»); domande aperte se mancano informazioni.
   Stile di partenza: frasi brevi, informale e diretto, in italiano. Le lezioni del Brain hanno la precedenza.
   Salvataggio: se esiste già una riga in uscite per quella segnalazione con stato 'da_rifare' o 'pronta', UPDATE uscite SET tipo, titolo, testo, priorita, stato='pronta', aggiornato=datetime('now'); se non esiste, INSERT INTO uscite (segnalazione_id, tipo, titolo, testo, priorita, stato) VALUES (..., 'pronta'); se esiste con stato bozza, inviata o scartata non toccarla. Poi UPDATE segnalazioni SET stato='pronta', aggiornato=datetime('now'). Evento con tipo redazione.

5. Revisione è la stanza di Davide: non toccarla e non impostare mai uscite a inviata.

6. Task e chat di Davide: SELECT * FROM task WHERE origine='davide' AND stato='backlog' e SELECT * FROM chat WHERE mittente='davide' AND stato='nuovo'. Rispondi come lead del reparto con INSERT INTO chat (reparto_id, mittente, testo, stato) VALUES (<reparto>, 'agente', <risposta>, 'nuovo'), poi segna il messaggio di Davide con stato='letto'. Esegui i task e chiudili con un dettaglio. Risposte brevi e dirette.

7. Fine: evento fine_turno.
