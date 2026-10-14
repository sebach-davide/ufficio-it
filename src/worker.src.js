const DASHBOARD_HTML = __DASHBOARD_HTML__;
const LOGIN_HTML = __LOGIN_HTML__;

const enc = new TextEncoder();
const keyCache = new Map();
const TESTO_MAX = 900000;
const ATTESA_TRA_AVVII_MIN = 15;

async function hmacKey(secret) {
  if (!keyCache.has(secret)) keyCache.set(secret, await crypto.subtle.importKey('raw', enc.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']));
  return keyCache.get(secret);
}

async function sign(env, msg) {
  const s = await crypto.subtle.sign('HMAC', await hmacKey(env.SESSION_KEY), enc.encode(msg));
  return [...new Uint8Array(s)].map(b => b.toString(16).padStart(2, '0')).join('');
}

function safeEq(a, b) {
  a = String(a || ''); b = String(b || '');
  if (a.length !== b.length) return false;
  let r = 0;
  for (let i = 0; i < a.length; i++) r |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return r === 0;
}

function json(data, status = 200, headers = {}) {
  return new Response(JSON.stringify(data), { status, headers: { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store', ...headers } });
}

function html(body) {
  return new Response(body, { headers: { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store' } });
}

function getCookie(req, name) {
  const m = (req.headers.get('cookie') || '').match(new RegExp('(?:^|; )' + name + '=([^;]*)'));
  return m ? decodeURIComponent(m[1]) : null;
}

async function sessionOk(req, env) {
  const v = getCookie(req, 'sess');
  if (!v) return false;
  const [exp, sig] = v.split('.');
  if (!exp || !sig || Date.now() > Number(exp)) return false;
  return safeEq(sig, await sign(env, `sess|${exp}`));
}

async function body(req) {
  try { return await req.json(); } catch { return {}; }
}

const txt = (v, max = 20000) => String(v ?? '').slice(0, max);

async function getImp(env, k) {
  const r = await env.DB.prepare('SELECT valore, aggiornato FROM impostazioni WHERE chiave = ?1').bind(k).first();
  return r ? r.valore : null;
}

function setImp(env, k, v) {
  return env.DB.prepare("INSERT INTO impostazioni (chiave, valore, aggiornato) VALUES (?1, ?2, datetime('now')) ON CONFLICT(chiave) DO UPDATE SET valore = excluded.valore, aggiornato = excluded.aggiornato").bind(k, v == null ? null : String(v)).run();
}

async function evento(env, reparto, agente, tipo, messaggio) {
  await env.DB.prepare('INSERT INTO eventi (reparto_id, agente_id, tipo, messaggio) VALUES (?1, ?2, ?3, ?4)').bind(reparto, agente, tipo, txt(messaggio, 1000)).run();
}

async function sincronizza(env) {
  const db = env.DB, bugs = env.BUGS;
  if (!bugs) return { nuove: 0, errore: 'Binding BUGS mancante' };
  const giaR = await db.prepare('SELECT ticket_id, stato, ticket_aggiornato FROM segnalazioni').all();
  const gia = new Map(giaR.results.map(r => [r.ticket_id, r]));
  const { results } = await bugs.prepare("SELECT t.id, t.code, t.type, t.title, t.area, t.operation, t.doc_number, t.error_text, t.expected, t.pro_check, t.severity, t.status, t.no_error_message, t.tag, t.created_at, t.updated_at, u.full_name AS autore, u.role AS autore_ruolo FROM tickets t LEFT JOIN users u ON u.id = t.created_by WHERE t.status IN ('nuovo','preso_in_carico') ORDER BY t.id").all();
  let nuove = 0, aggiornate = 0;
  for (const t of results) {
    const prima = gia.get(t.id);
    if (prima && prima.ticket_aggiornato === t.updated_at) continue;
    if (!prima && t.status !== 'nuovo') continue;
    const note = await bugs.prepare('SELECT n.body, n.system, n.created_at, u.full_name AS autore FROM notes n LEFT JOIN users u ON u.id = n.user_id WHERE n.ticket_id = ?1 ORDER BY n.id').bind(t.id).all();
    const all = await bugs.prepare('SELECT filename, mime, size FROM attachments WHERE ticket_id = ?1 ORDER BY id').bind(t.id).all();
    const campi = [t.code, t.type, t.title, t.area, t.operation, t.doc_number, t.error_text, t.expected, t.pro_check, t.severity, t.no_error_message ? 1 : 0, t.tag, t.autore, t.autore_ruolo, t.status, t.created_at, t.updated_at, JSON.stringify(note.results), JSON.stringify(all.results)];
    if (!prima) {
      await db.prepare("INSERT INTO segnalazioni (ticket_id, codice, tipo_originale, titolo_originale, area, operazione, documento, errore, atteso, pro_check, severita, senza_messaggio, tag, autore, autore_ruolo, ticket_stato, ticket_creato, ticket_aggiornato, note_ticket, allegati, stato) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19, ?20, 'nuova')").bind(t.id, ...campi).run();
      await evento(env, 'accettazione', 'acc-lead', 'ticket', `Nuovo ticket ${t.code || '#' + t.id}: ${txt(t.title, 140)}`);
      nuove++;
    } else {
      const riapri = ['pronta', 'in_lavoro'].includes(prima.stato);
      await db.prepare(`UPDATE segnalazioni SET codice = ?2, tipo_originale = ?3, titolo_originale = ?4, area = ?5, operazione = ?6, documento = ?7, errore = ?8, atteso = ?9, pro_check = ?10, severita = ?11, senza_messaggio = ?12, tag = ?13, autore = ?14, autore_ruolo = ?15, ticket_stato = ?16, ticket_creato = ?17, ticket_aggiornato = ?18, note_ticket = ?19, allegati = ?20${riapri ? ", stato = 'nuova', note_agenti = COALESCE(note_agenti, '') || ' [ticket modificato nel bug tracker: da rivedere]'" : ''}, aggiornato = datetime('now') WHERE ticket_id = ?1`).bind(t.id, ...campi).run();
      if (riapri) await evento(env, 'accettazione', 'acc-lead', 'ticket', `Ticket ${t.code || '#' + t.id} modificato nel bug tracker: torna in lavorazione`);
      aggiornate++;
    }
  }
  const aperti = [...gia.entries()].filter(([, r]) => !['inviata', 'scartata'].includes(r.stato)).map(([id]) => id);
  for (let i = 0; i < aperti.length; i += 50) {
    const ids = aperti.slice(i, i + 50);
    const st = await bugs.prepare(`SELECT id, status FROM tickets WHERE id IN (${ids.map(() => '?').join(',')})`).bind(...ids).all();
    for (const r of st.results) await db.prepare('UPDATE segnalazioni SET ticket_stato = ?2 WHERE ticket_id = ?1 AND ticket_stato IS NOT ?2').bind(r.id, r.status).run();
  }
  await setImp(env, 'ultimo_sync', new Date().toISOString());
  await setImp(env, 'ultimo_sync_esito', `ok · ${results.length} in stato nuovo · ${nuove} importati${aggiornate ? ' · ' + aggiornate + ' aggiornati' : ''}`);
  return { nuove, aggiornate, inNuovo: results.length };
}

async function utenteBug(env) {
  const u = await env.BUGS.prepare('SELECT id, full_name FROM users WHERE lower(username) = ?1').bind(String(env.BUG_UTENTE || 'davide.petrone').toLowerCase()).first();
  if (!u) throw new Error(`Utente ${env.BUG_UTENTE || 'davide.petrone'} non trovato nel bug tracker`);
  return u;
}

const ET_STATO = { nuovo: 'Nuovo', preso_in_carico: 'Preso in carico', aperto: 'Aperto', approvato: 'Approvato', risolto: 'Risolto', respinto: 'Respinto', sospesa: 'Sospesa' };

async function presaInCarico(env) {
  if ((await getImp(env, 'stato_preso_in_carico')) !== '1') return 0;
  const { results } = await env.DB.prepare("SELECT ticket_id FROM segnalazioni WHERE stato = 'nuova' AND ticket_stato = 'nuovo'").all();
  if (!results.length) return 0;
  const u = await utenteBug(env);
  let n = 0;
  for (const r of results) {
    const ch = await env.BUGS.prepare("UPDATE tickets SET status = 'preso_in_carico', status_by = ?2, status_at = datetime('now'), updated_at = datetime('now') WHERE id = ?1 AND status = 'nuovo'").bind(r.ticket_id, u.id).run();
    if (ch.meta.changes) {
      await env.BUGS.prepare('INSERT INTO notes (ticket_id, user_id, body, system) VALUES (?1, ?2, ?3, 1)').bind(r.ticket_id, u.id, 'Ufficio IT ha impostato lo stato da «Nuovo» a «Preso in carico».').run();
      const t = await env.BUGS.prepare('SELECT updated_at FROM tickets WHERE id = ?1').bind(r.ticket_id).first();
      await env.DB.prepare("UPDATE segnalazioni SET ticket_stato = 'preso_in_carico', ticket_aggiornato = ?2 WHERE ticket_id = ?1").bind(r.ticket_id, t ? t.updated_at : null).run();
      n++;
    }
  }
  if (n) await evento(env, 'accettazione', 'acc-lead', 'ticket', `${n} ticket messi «Preso in carico» nel bug tracker`);
  return n;
}

async function apriSuBugTracker(env, ticketId, devopsId) {
  const t = await env.BUGS.prepare('SELECT id, status, devops_id, updated_at FROM tickets WHERE id = ?1').bind(ticketId).first();
  if (!t) return { ok: false, esito: 'ticket non trovato nel bug tracker' };
  const u = await utenteBug(env);
  if (['nuovo', 'preso_in_carico'].includes(t.status)) {
    await env.BUGS.prepare("UPDATE tickets SET status = 'aperto', devops_id = ?2, reject_reason = NULL, status_by = ?3, status_at = datetime('now'), updated_at = datetime('now') WHERE id = ?1").bind(ticketId, devopsId, u.id).run();
    await env.BUGS.prepare('INSERT INTO notes (ticket_id, user_id, body, system) VALUES (?1, ?2, ?3, 1)').bind(ticketId, u.id, `${u.full_name} ha impostato lo stato da «${ET_STATO[t.status] || t.status}» a «Aperto», l’ID DevOps a «${devopsId}».`).run();
    return { ok: true, esito: 'ticket aperto con ID DevOps ' + devopsId, stato: 'aperto' };
  }
  if (['aperto', 'approvato'].includes(t.status)) {
    if (t.devops_id && t.devops_id !== devopsId) return { ok: false, esito: `ticket già aperto con un altro ID DevOps (${t.devops_id}): non toccato`, stato: t.status };
    if (!t.devops_id) {
      await env.BUGS.prepare("UPDATE tickets SET devops_id = ?2, updated_at = datetime('now') WHERE id = ?1").bind(ticketId, devopsId).run();
      await env.BUGS.prepare('INSERT INTO notes (ticket_id, user_id, body, system) VALUES (?1, ?2, ?3, 1)').bind(ticketId, u.id, `${u.full_name} ha impostato l’ID DevOps a «${devopsId}».`).run();
    }
    return { ok: true, esito: 'ticket già aperto, ID DevOps ' + devopsId, stato: t.status };
  }
  return { ok: false, esito: `ticket ${ET_STATO[t.status] || t.status} nel bug tracker: non toccato`, stato: t.status };
}

async function lavoroInCoda(env) {
  return await env.DB.prepare(`SELECT
    (SELECT COUNT(*) FROM segnalazioni WHERE stato = 'nuova') AS segnalazioni,
    (SELECT COUNT(*) FROM task WHERE origine = 'davide' AND stato = 'backlog') AS task,
    (SELECT COUNT(*) FROM chat WHERE mittente = 'davide' AND stato = 'nuovo') AS chat,
    (SELECT COUNT(*) FROM modifiche WHERE analizzata = 0) AS modifiche`).first();
}

async function turnoInCorso(env) {
  const ultimo = await getImp(env, 'ultimo_avvio');
  if (!ultimo) return false;
  const ts = Date.parse(ultimo);
  if (Date.now() - ts > 40 * 60000) return false;
  const fine = await env.DB.prepare("SELECT creato FROM eventi WHERE tipo = 'fine_turno' ORDER BY id DESC LIMIT 1").first();
  const fineTs = fine ? Date.parse(fine.creato.replace(' ', 'T') + 'Z') : 0;
  return fineTs < ts;
}

async function avviaAgenti(env, motivo, forza) {
  if (!env.ROUTINE_URL || !env.ROUTINE_TOKEN) return { ok: false, errore: 'Avvio degli agenti non configurato: mancano ROUTINE_URL e ROUTINE_TOKEN nei secret del Worker' };
  if (await turnoInCorso(env)) return { ok: false, inCorso: true, errore: 'Gli agenti sono già al lavoro' };
  const ultimo = await getImp(env, 'ultimo_avvio');
  if (!forza && ultimo && Date.now() - Date.parse(ultimo) < ATTESA_TRA_AVVII_MIN * 60000) return { ok: false, errore: 'Avviati da poco' };
  const coda = await lavoroInCoda(env);
  const ids = await env.DB.prepare("SELECT codice, ticket_id FROM segnalazioni WHERE stato = 'nuova' ORDER BY id LIMIT 60").all();
  const testo = `Avvio ${motivo}. In coda: ${coda.segnalazioni} segnalazioni nuove (${ids.results.map(r => r.codice || '#' + r.ticket_id).join(', ') || 'nessuna'}), ${coda.task} task di Davide, ${coda.chat} messaggi in chat, ${coda.modifiche} modifiche di Davide da studiare.`;
  let r, j = {};
  try {
    r = await fetch(env.ROUTINE_URL, { method: 'POST', headers: { authorization: `Bearer ${env.ROUTINE_TOKEN}`, 'anthropic-version': '2023-06-01', 'content-type': 'application/json' }, body: JSON.stringify({ text: testo }) });
    j = await r.json().catch(() => ({}));
  } catch (e) {
    await setImp(env, 'avvio_esito', 'errore: ' + txt(e.message || e, 200));
    return { ok: false, errore: 'Chiamata agli agenti non riuscita' };
  }
  if (!r.ok) {
    const msg = (j.error && j.error.message) || `HTTP ${r.status}`;
    await setImp(env, 'avvio_esito', 'errore: ' + txt(msg, 200));
    await evento(env, null, null, 'allarme', `Avvio agenti non riuscito: ${msg}`);
    return { ok: false, errore: 'Avvio non riuscito: ' + msg };
  }
  await setImp(env, 'ultimo_avvio', new Date().toISOString());
  await setImp(env, 'avvio_esito', 'ok · ' + motivo);
  try { await presaInCarico(env); } catch (e) { await evento(env, 'accettazione', 'acc-lead', 'allarme', 'Presa in carico sul bug tracker non riuscita: ' + txt(e.message || e, 200)); }
  if (j.claude_code_session_url) await setImp(env, 'ultima_sessione', j.claude_code_session_url);
  await evento(env, null, null, 'avvio', `Agenti avviati (${motivo}): ${coda.segnalazioni} segnalazioni in coda`);
  return { ok: true, coda };
}

async function controllo(env, motivo, forza) {
  let sync;
  try { sync = await sincronizza(env); }
  catch (e) {
    await setImp(env, 'ultimo_sync', new Date().toISOString());
    await setImp(env, 'ultimo_sync_esito', 'errore: ' + txt(e.message || e, 200));
    sync = { errore: String(e.message || e) };
  }
  const coda = await lavoroInCoda(env);
  const daFare = coda.segnalazioni + coda.task + coda.chat + coda.modifiche;
  if (!forza && ((await getImp(env, 'auto')) !== '1' || !daFare)) return { sync, coda, avvio: null };
  if (forza && !daFare) return { sync, coda, avvio: { ok: false, errore: 'Niente da fare: nessun bug in stato nuovo e nessuna richiesta in coda' } };
  return { sync, coda, avvio: await avviaAgenti(env, motivo, forza) };
}

async function stato(env) {
  const db = env.DB;
  const [reparti, agenti, task, eventi, segn, uscite, metriche, brainTipi, chatNuovi, imp] = await Promise.all([
    db.prepare('SELECT id, nome, colore, ordine, area, descrizione FROM reparti ORDER BY ordine').all(),
    db.prepare('SELECT id, reparto_id, nome, ruolo, lead, stato, attivita, aggiornato FROM agenti ORDER BY reparto_id, lead DESC, id').all(),
    db.prepare("SELECT id, reparto_id, agente_id, titolo, dettaglio, origine, stato, progresso, creato, aggiornato FROM task WHERE stato != 'done' OR aggiornato > datetime('now', '-2 days') ORDER BY aggiornato DESC LIMIT 80").all(),
    db.prepare('SELECT id, reparto_id, agente_id, tipo, messaggio, creato FROM eventi ORDER BY id DESC LIMIT 40').all(),
    db.prepare("SELECT s.id, s.ticket_id, s.codice, s.tipo_originale, s.titolo_originale, s.area, s.severita, s.pro_check, s.autore, s.ticket_stato, s.ticket_creato, s.stato, s.tipo, s.modulo, s.priorita, s.permessi, s.doppione_di, s.aggiornato, u.id AS uscita_id, u.titolo AS uscita_titolo, u.stato AS uscita_stato, u.modificata FROM segnalazioni s LEFT JOIN uscite u ON u.segnalazione_id = s.id WHERE s.stato NOT IN ('inviata','scartata') OR s.aggiornato > datetime('now', '-30 days') ORDER BY s.id DESC LIMIT 200").all(),
    db.prepare("SELECT COUNT(*) AS n FROM uscite WHERE stato IN ('pronta','bozza')").first(),
    db.prepare(`SELECT
      (SELECT COUNT(*) FROM segnalazioni WHERE stato = 'nuova') AS nuove,
      (SELECT COUNT(*) FROM segnalazioni WHERE stato = 'in_lavoro') AS inLavoro,
      (SELECT COUNT(*) FROM segnalazioni WHERE creato > datetime('now','-7 days')) AS arrivate7,
      (SELECT COUNT(*) FROM segnalazioni WHERE tipo = 'BUG' AND stato NOT IN ('nuova','scartata')) AS bug,
      (SELECT COUNT(*) FROM segnalazioni WHERE tipo = 'CR' AND stato NOT IN ('nuova','scartata')) AS cr,
      (SELECT COUNT(*) FROM segnalazioni WHERE doppione_di IS NOT NULL) AS doppioni,
      (SELECT COUNT(*) FROM segnalazioni WHERE permessi = 'probabile') AS permProbabili,
      (SELECT COUNT(*) FROM segnalazioni WHERE permessi = 'possibile') AS permPossibili,
      (SELECT COUNT(*) FROM uscite WHERE stato IN ('pronta','bozza')) AS daRivedere,
      (SELECT COUNT(*) FROM uscite WHERE stato = 'pronta') AS pronte,
      (SELECT COUNT(*) FROM uscite WHERE stato = 'inviata' AND inviata_il > datetime('now','-7 days')) AS inviate7,
      (SELECT COUNT(*) FROM uscite WHERE stato = 'inviata') AS inviate,
      (SELECT COUNT(*) FROM uscite WHERE stato = 'inviata' AND modificata = 1) AS inviateModificate,
      (SELECT COUNT(*) FROM modifiche WHERE analizzata = 0) AS modificheDaStudiare,
      (SELECT COUNT(*) FROM brain WHERE tipo = 'lezione' AND attivo = 1) AS lezioni`).first(),
    db.prepare('SELECT tipo, COUNT(*) AS n FROM brain WHERE attivo = 1 GROUP BY tipo').all(),
    db.prepare("SELECT reparto_id, COUNT(*) AS n FROM chat WHERE mittente = 'agente' AND stato = 'nuovo' GROUP BY reparto_id").all(),
    db.prepare("SELECT chiave, valore, aggiornato FROM impostazioni WHERE chiave IN ('auto','ultimo_sync','ultimo_sync_esito','ultimo_avvio','avvio_esito','ultima_sessione')").all()
  ]);
  const I = Object.fromEntries(imp.results.map(r => [r.chiave, r.valore]));
  return {
    ora: new Date().toISOString(),
    impostazioni: { auto: I.auto === '1', ultimoSync: I.ultimo_sync || null, syncEsito: I.ultimo_sync_esito || null, ultimoAvvio: I.ultimo_avvio || null, avvioEsito: I.avvio_esito || null, sessione: I.ultima_sessione || null, configurato: !!(env.ROUTINE_URL && env.ROUTINE_TOKEN), bugTracker: !!env.BUGS },
    inCorso: await turnoInCorso(env),
    reparti: reparti.results,
    agenti: agenti.results,
    task: task.results,
    eventi: eventi.results,
    segnalazioni: segn.results,
    daRivedere: uscite.n,
    metriche,
    brain: Object.fromEntries(brainTipi.results.map(r => [r.tipo, r.n])),
    chatNuovi: Object.fromEntries(chatNuovi.results.map(r => [r.reparto_id, r.n]))
  };
}

const CAMPI_USCITA = ['tipo', 'priorita', 'titolo', 'testo'];

async function snapshotAgente(env, u) {
  if (u.versione_agente) return JSON.parse(u.versione_agente);
  const v = Object.fromEntries(CAMPI_USCITA.map(k => [k, u[k] ?? '']));
  await env.DB.prepare('UPDATE uscite SET versione_agente = ?2 WHERE id = ?1').bind(u.id, JSON.stringify(v)).run();
  return v;
}

function valoriUscita(b) {
  return {
    tipo: ['BUG', 'CR'].includes(b.tipo) ? b.tipo : 'BUG',
    priorita: txt(b.priorita, 40),
    titolo: txt(b.titolo, 300).trim(),
    testo: txt(b.testo, 40000)
  };
}

const norm = s => String(s ?? '').replace(/\r\n/g, '\n').trim();

async function apiDashboard(req, env, url, ctx) {
  const p = url.pathname, m = req.method, db = env.DB;

  if (p === '/api/stato' && m === 'GET') return json(await stato(env));

  if (p === '/api/avvia' && m === 'POST') {
    const r = await controllo(env, 'forzato da Davide', true);
    return json(r);
  }

  if (p === '/api/impostazioni' && m === 'POST') {
    const b = await body(req);
    if (b.chiave === 'auto' && ['0', '1'].includes(String(b.valore))) {
      await setImp(env, 'auto', String(b.valore));
      await evento(env, null, null, 'impostazioni', String(b.valore) === '1' ? 'Avvio automatico attivo: gli agenti partono da soli sui bug nuovi' : 'Avvio automatico in pausa: gli agenti partono solo se li avvii tu');
      return json({ ok: true });
    }
    return json({ errore: 'Impostazione non valida' }, 400);
  }

  let mm = p.match(/^\/api\/segnalazioni\/(\d+)$/);
  if (mm && m === 'GET') {
    const s = await db.prepare('SELECT * FROM segnalazioni WHERE id = ?1').bind(Number(mm[1])).first();
    if (!s) return json({ errore: 'Segnalazione non trovata' }, 404);
    const u = await db.prepare('SELECT * FROM uscite WHERE segnalazione_id = ?1').bind(s.id).first();
    const mod = u ? await db.prepare('SELECT id, campo, prima, dopo, analizzata, creato FROM modifiche WHERE uscita_id = ?1 ORDER BY id').bind(u.id).all() : { results: [] };
    return json({ segnalazione: s, uscita: u, modifiche: mod.results });
  }

  mm = p.match(/^\/api\/segnalazioni\/(\d+)\/rifai$/);
  if (mm && m === 'POST') {
    const b = await body(req);
    const nota = txt(b.nota, 2000).trim();
    const s = await db.prepare('SELECT id, codice, ticket_id FROM segnalazioni WHERE id = ?1').bind(Number(mm[1])).first();
    if (!s) return json({ errore: 'Segnalazione non trovata' }, 404);
    await db.prepare("UPDATE segnalazioni SET stato = 'nuova', nota_davide = ?2, aggiornato = datetime('now') WHERE id = ?1").bind(s.id, nota || null).run();
    await db.prepare("UPDATE uscite SET stato = 'da_rifare', versione_agente = NULL, motivo = ?2, aggiornato = datetime('now') WHERE segnalazione_id = ?1").bind(s.id, nota || null).run();
    if (nota) await db.prepare("INSERT INTO modifiche (uscita_id, segnalazione_id, campo, prima, dopo) SELECT id, segnalazione_id, 'nota_rifai', NULL, ?2 FROM uscite WHERE segnalazione_id = ?1").bind(s.id, nota).run();
    await evento(env, 'revisione', 'rev-davide', 'revisione', `Davide rimanda ${s.codice || '#' + s.ticket_id} agli agenti${nota ? ': ' + nota : ''}`);
    if (ctx) ctx.waitUntil(avviaAgenti(env, 'rifacimento chiesto da Davide', true).catch(() => {}));
    return json({ ok: true });
  }

  mm = p.match(/^\/api\/uscite\/(\d+)\/(salva|invia|scarta)$/);
  if (mm && m === 'POST') {
    const b = await body(req);
    const u = await db.prepare('SELECT * FROM uscite WHERE id = ?1').bind(Number(mm[1])).first();
    if (!u) return json({ errore: 'Uscita non trovata' }, 404);
    if (u.stato === 'inviata') return json({ errore: 'Già inviata' }, 409);
    const s = await db.prepare('SELECT id, codice, ticket_id FROM segnalazioni WHERE id = ?1').bind(u.segnalazione_id).first();
    const nome = s ? (s.codice || '#' + s.ticket_id) : '#' + u.segnalazione_id;
    if (mm[2] === 'scarta') {
      await db.prepare("UPDATE uscite SET stato = 'scartata', motivo = ?2, aggiornato = datetime('now') WHERE id = ?1").bind(u.id, txt(b.motivo, 1000) || null).run();
      await db.prepare("UPDATE segnalazioni SET stato = 'scartata', aggiornato = datetime('now') WHERE id = ?1").bind(u.segnalazione_id).run();
      if (b.motivo) await db.prepare("INSERT INTO modifiche (uscita_id, segnalazione_id, campo, prima, dopo) VALUES (?1, ?2, 'scartata', NULL, ?3)").bind(u.id, u.segnalazione_id, txt(b.motivo, 1000)).run();
      await evento(env, 'revisione', 'rev-davide', 'revisione', `${nome} scartata da Davide${b.motivo ? ': ' + txt(b.motivo, 200) : ''}`);
      return json({ ok: true });
    }
    const agente = await snapshotAgente(env, u);
    const v = valoriUscita(b);
    const devops = txt(b.devops_id, 40).trim();
    if (!v.titolo || !norm(v.testo)) return json({ errore: 'Titolo e testo non possono essere vuoti' }, 400);
    if (mm[2] === 'salva') {
      await db.prepare("UPDATE uscite SET tipo = ?2, priorita = ?3, titolo = ?4, testo = ?5, devops_id = ?6, stato = 'bozza', aggiornato = datetime('now') WHERE id = ?1").bind(u.id, v.tipo, v.priorita, v.titolo, v.testo, devops || null).run();
      return json({ ok: true });
    }
    if (!devops) return json({ errore: 'Scrivi l’ID DevOps: serve per aprire il ticket nel bug tracker' }, 400);
    let bt = { ok: false, esito: 'bug tracker non collegato' };
    try { if (env.BUGS && s) bt = await apriSuBugTracker(env, s.ticket_id, devops); }
    catch (e) { bt = { ok: false, esito: 'errore: ' + txt(e.message || e, 200) }; }
    const cambi = CAMPI_USCITA.filter(k => norm(agente[k]) !== norm(v[k]));
    const stmts = cambi.map(k => db.prepare('INSERT INTO modifiche (uscita_id, segnalazione_id, campo, prima, dopo) VALUES (?1, ?2, ?3, ?4, ?5)').bind(u.id, u.segnalazione_id, k, String(agente[k] ?? ''), String(v[k] ?? '')));
    stmts.push(db.prepare("UPDATE uscite SET tipo = ?2, priorita = ?3, titolo = ?4, testo = ?5, devops_id = ?7, stato = 'inviata', modificata = ?6, inviata_il = datetime('now'), aggiornato = datetime('now') WHERE id = ?1").bind(u.id, v.tipo, v.priorita, v.titolo, v.testo, cambi.length ? 1 : 0, devops));
    stmts.push(db.prepare("UPDATE segnalazioni SET stato = 'inviata', tipo = ?2, priorita = ?3, ticket_stato = COALESCE(?4, ticket_stato), aggiornato = datetime('now') WHERE id = ?1").bind(u.segnalazione_id, v.tipo, v.priorita, bt.stato || null));
    await db.batch(stmts);
    await evento(env, 'revisione', 'rev-davide', bt.ok ? 'revisione' : 'allarme', `${nome} inviata (DevOps ${devops})${cambi.length ? ' con modifiche a ' + cambi.join(', ') : ' senza modifiche'} · bug tracker: ${bt.esito}`);
    return json({ ok: true, cambi, bugTracker: bt });
  }

  if (p === '/api/brain' && m === 'GET') {
    const { results } = await db.prepare('SELECT id, tipo, titolo, substr(contenuto, 1, 1500) AS anteprima, length(contenuto) AS lunghezza, tag, fonte, attivo, reparto_id, creato, aggiornato FROM brain ORDER BY CASE tipo WHEN \'lezione\' THEN 0 WHEN \'nozione\' THEN 1 WHEN \'documento\' THEN 2 ELSE 3 END, id DESC LIMIT 300').all();
    return json(results);
  }

  mm = p.match(/^\/api\/brain\/(\d+)$/);
  if (mm && m === 'GET') {
    const r = await db.prepare('SELECT * FROM brain WHERE id = ?1').bind(Number(mm[1])).first();
    return r ? json(r) : json({ errore: 'Non trovato' }, 404);
  }

  if (p === '/api/brain' && m === 'POST') {
    const b = await body(req);
    const tipo = ['documento', 'nozione', 'lezione', 'nota'].includes(b.tipo) ? b.tipo : 'nozione';
    const titolo = txt(b.titolo, 200).trim();
    const contenuto = String(b.contenuto ?? '');
    if (!titolo || !contenuto.trim()) return json({ errore: 'Titolo e contenuto sono obbligatori' }, 400);
    if (contenuto.length > TESTO_MAX) return json({ errore: 'Contenuto troppo lungo: dividilo in parti' }, 413);
    await db.prepare("INSERT INTO brain (tipo, titolo, contenuto, tag, fonte, reparto_id) VALUES (?1, ?2, ?3, ?4, ?5, ?6)").bind(tipo, titolo, contenuto, txt(b.tag, 200) || null, txt(b.fonte, 300) || 'Davide', b.reparto_id ? txt(b.reparto_id, 40) : null).run();
    if (!b.silenzioso) await evento(env, null, null, 'brain', `Nel Brain: ${tipo} «${titolo}»`);
    return json({ ok: true });
  }

  mm = p.match(/^\/api\/brain\/(\d+)\/(aggiorna|elimina)$/);
  if (mm && m === 'POST') {
    const id = Number(mm[1]);
    if (mm[2] === 'elimina') {
      await db.prepare('DELETE FROM brain WHERE id = ?1').bind(id).run();
      return json({ ok: true });
    }
    const b = await body(req);
    const r = await db.prepare('SELECT * FROM brain WHERE id = ?1').bind(id).first();
    if (!r) return json({ errore: 'Non trovato' }, 404);
    const contenuto = b.contenuto != null ? String(b.contenuto) : r.contenuto;
    if (contenuto.length > TESTO_MAX) return json({ errore: 'Contenuto troppo lungo' }, 413);
    await db.prepare("UPDATE brain SET titolo = ?2, contenuto = ?3, tag = ?4, attivo = ?5, aggiornato = datetime('now') WHERE id = ?1").bind(id, b.titolo != null ? txt(b.titolo, 200) : r.titolo, contenuto, b.tag != null ? txt(b.tag, 200) : r.tag, b.attivo != null ? (b.attivo ? 1 : 0) : r.attivo).run();
    return json({ ok: true });
  }

  if (p === '/api/chat' && m === 'GET') {
    const rep = url.searchParams.get('reparto') || '';
    const { results } = await db.prepare('SELECT id, reparto_id, mittente, testo, stato, creato FROM chat WHERE reparto_id = ?1 ORDER BY id DESC LIMIT 40').bind(rep).all();
    await db.prepare("UPDATE chat SET stato = 'letto' WHERE reparto_id = ?1 AND mittente = 'agente' AND stato = 'nuovo'").bind(rep).run();
    return json(results.reverse());
  }

  if (p === '/api/chat' && m === 'POST') {
    const b = await body(req);
    const testo = txt(b.testo, 2000).trim();
    const rep = await db.prepare('SELECT id FROM reparti WHERE id = ?1').bind(String(b.reparto_id || '')).first();
    if (!testo || !rep) return json({ errore: 'Messaggio non valido' }, 400);
    await db.prepare("INSERT INTO chat (reparto_id, mittente, testo, stato) VALUES (?1, 'davide', ?2, 'nuovo')").bind(rep.id, testo).run();
    return json({ ok: true });
  }

  if (p === '/api/task' && m === 'POST') {
    const b = await body(req);
    const titolo = txt(b.titolo, 300).trim();
    const rep = b.reparto_id ? await db.prepare('SELECT id FROM reparti WHERE id = ?1').bind(String(b.reparto_id)).first() : null;
    if (!titolo) return json({ errore: 'Titolo mancante' }, 400);
    await db.prepare("INSERT INTO task (reparto_id, titolo, origine, stato) VALUES (?1, ?2, 'davide', 'backlog')").bind(rep ? rep.id : null, titolo).run();
    return json({ ok: true });
  }

  return json({ errore: 'Non trovato' }, 404);
}

export default {
  async scheduled(ev, env, ctx) {
    if (env.SESSION_KEY) ctx.waitUntil(controllo(env, 'automatico (controllo ogni 10 minuti)', false).catch(e => console.error(e)));
  },
  async fetch(req, env, ctx) {
    const url = new URL(req.url);
    if (!env.SESSION_KEY || !env.DASH_PASSWORD) return new Response('Configura i secret DASH_PASSWORD e SESSION_KEY nelle impostazioni del Worker.', { status: 500 });

    if (url.pathname === '/login' && req.method === 'POST') {
      const b = await body(req);
      if (!safeEq(b.password, env.DASH_PASSWORD)) {
        await new Promise(r => setTimeout(r, 800));
        return json({ errore: 'Password errata' }, 401);
      }
      const exp = Date.now() + 30 * 24 * 3600 * 1000;
      const v = `${exp}.${await sign(env, `sess|${exp}`)}`;
      return json({ ok: true }, 200, { 'set-cookie': `sess=${encodeURIComponent(v)}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=${30 * 24 * 3600}` });
    }
    if (url.pathname === '/logout') return new Response(null, { status: 302, headers: { location: '/', 'set-cookie': 'sess=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0' } });

    const logged = await sessionOk(req, env);
    if (url.pathname.startsWith('/api/')) {
      if (!logged) return json({ errore: 'Sessione scaduta' }, 401);
      try { return await apiDashboard(req, env, url, ctx); }
      catch (e) { return json({ errore: String(e.message || e) }, 500); }
    }
    return html(logged ? DASHBOARD_HTML : LOGIN_HTML);
  }
};
