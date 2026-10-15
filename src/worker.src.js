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
  const sosp = await bugs.prepare("SELECT t.id, t.code, t.type, t.title, t.area, t.operation, t.doc_number, t.error_text, t.expected, t.pro_check, t.severity, t.status, t.no_error_message, t.tag, t.created_at, t.updated_at, u.full_name AS autore, u.role AS autore_ruolo FROM tickets t LEFT JOIN users u ON u.id = t.created_by WHERE t.status = 'sospesa' ORDER BY t.id").all();
  for (const t of sosp.results) {
    if (gia.has(t.id)) continue;
    const note = await bugs.prepare('SELECT n.body, n.system, n.created_at, u.full_name AS autore FROM notes n LEFT JOIN users u ON u.id = n.user_id WHERE n.ticket_id = ?1 ORDER BY n.id').bind(t.id).all();
    const all = await bugs.prepare('SELECT filename, mime, size FROM attachments WHERE ticket_id = ?1 ORDER BY id').bind(t.id).all();
    const campi = [t.code, t.type, t.title, t.area, t.operation, t.doc_number, t.error_text, t.expected, t.pro_check, t.severity, t.no_error_message ? 1 : 0, t.tag, t.autore, t.autore_ruolo, t.status, t.created_at, t.updated_at, JSON.stringify(note.results), JSON.stringify(all.results)];
    const ins = await db.prepare("INSERT INTO segnalazioni (ticket_id, codice, tipo_originale, titolo_originale, area, operazione, documento, errore, atteso, pro_check, severita, senza_messaggio, tag, autore, autore_ruolo, ticket_stato, ticket_creato, ticket_aggiornato, note_ticket, allegati, stato, tipo, modulo, priorita, note_agenti) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19, ?20, 'archiviata', 'CR', ?5, ?11, 'importata dal bug tracker: era già sospesa') RETURNING id").bind(t.id, ...campi).first();
    const testo = [t.operation && 'contesto: ' + t.operation, t.error_text && 'richiesta: ' + t.error_text, t.expected && 'atteso: ' + t.expected, t.doc_number && 'documento: ' + t.doc_number].filter(Boolean).join('\n\n') || t.title;
    await db.prepare("INSERT INTO uscite (segnalazione_id, tipo, titolo, testo, priorita, stato, versione_agente) VALUES (?1, 'CR', ?2, ?3, ?4, 'archiviata', ?5)").bind(ins.id, t.title, testo, t.severity || 'media', JSON.stringify({ tipo: 'CR', priorita: t.severity || 'media', titolo: t.title, testo, importata: true })).run();
    await evento(env, 'cr', 'cr-arch', 'ticket', `${t.code || '#' + t.id} importata nel magazzino CR (era già sospesa)`);
  }
  const nAll = await sincronizzaAllegati(env);
  const segT = await db.prepare("SELECT ticket_id FROM segnalazioni WHERE stato != 'scartata' AND (ticket_stato IS NULL OR ticket_stato NOT IN ('risolto','respinto'))").all();
  const aperti = segT.results.map(r => r.ticket_id);
  for (let i = 0; i < aperti.length; i += 50) {
    const ids = aperti.slice(i, i + 50);
    const st = await bugs.prepare(`SELECT id, status FROM tickets WHERE id IN (${ids.map(() => '?').join(',')})`).bind(...ids).all();
    for (const r of st.results) await db.prepare('UPDATE segnalazioni SET ticket_stato = ?2 WHERE ticket_id = ?1 AND ticket_stato IS NOT ?2').bind(r.id, r.status).run();
  }
  await setImp(env, 'ultimo_sync', new Date().toISOString());
  await setImp(env, 'ultimo_sync_esito', `ok · ${results.length} in stato nuovo · ${nuove} importati${aggiornate ? ' · ' + aggiornate + ' aggiornati' : ''}${nAll ? ' · ' + nAll + ' allegati' : ''}`);
  return { nuove, aggiornate, inNuovo: results.length };
}

async function sincronizzaAllegati(env) {
  const db = env.DB, bugs = env.BUGS;
  const { results: segs } = await db.prepare("SELECT id, ticket_id, codice, stato, creato FROM segnalazioni WHERE stato NOT IN ('inviata','scartata')").all();
  if (!segs.length) return 0;
  const perTicket = new Map(segs.map(x => [x.ticket_id, x]));
  const { results: gia } = await db.prepare('SELECT origine_id FROM allegati').all();
  const presenti = new Set(gia.map(r => r.origine_id));
  const ids = [...perTicket.keys()];
  let copiati = 0;
  const riaperte = new Set();
  for (let i = 0; i < ids.length; i += 50) {
    const blocco = ids.slice(i, i + 50);
    const { results } = await bugs.prepare(`SELECT id, ticket_id, filename, mime, size, created_at FROM attachments WHERE ticket_id IN (${blocco.map(() => '?').join(',')}) ORDER BY id`).bind(...blocco).all();
    for (const a of results) {
      if (presenti.has(a.id)) continue;
      const d = await bugs.prepare('SELECT data FROM attachments WHERE id = ?1').bind(a.id).first();
      if (!d) continue;
      const sg = perTicket.get(a.ticket_id);
      await db.prepare('INSERT OR IGNORE INTO allegati (segnalazione_id, ticket_id, origine_id, nome, mime, size, data) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)').bind(sg.id, a.ticket_id, a.id, a.filename, a.mime, a.size, d.data).run();
      copiati++;
      if (sg.stato === 'pronta' && a.created_at > sg.creato && !riaperte.has(sg.id)) {
        riaperte.add(sg.id);
        await db.prepare("UPDATE segnalazioni SET stato = 'nuova', note_agenti = COALESCE(note_agenti, '') || ' [nuovo allegato nel bug tracker: da rivedere]', aggiornato = datetime('now') WHERE id = ?1").bind(sg.id).run();
        await evento(env, 'accettazione', 'acc-lead', 'ticket', `Nuovo allegato su ${sg.codice || '#' + sg.ticket_id}: torna in lavorazione`);
      }
    }
  }
  return copiati;
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

async function riclassifica(env, t, tipo, u) {
  if (!(tipo === 'BUG' || tipo === 'CR') || t.type === tipo) return null;
  const code = `${tipo}-${String(t.id).padStart(4, '0')}`;
  await env.BUGS.prepare("UPDATE tickets SET type = ?2, code = ?3, updated_at = datetime('now') WHERE id = ?1").bind(t.id, tipo, code).run();
  await env.BUGS.prepare('INSERT INTO notes (ticket_id, user_id, body, system) VALUES (?1, ?2, ?3, 1)').bind(t.id, u.id, `${u.full_name} ha impostato il tipo da «${t.type}» a «${tipo}». La segnalazione è stata riclassificata come ${code}.`).run();
  await env.DB.prepare('UPDATE segnalazioni SET codice = ?2 WHERE ticket_id = ?1').bind(t.id, code).run();
  await env.DB.prepare('UPDATE tempi SET codice = ?2, tipo = ?3 WHERE ticket_id = ?1').bind(t.id, code, tipo).run();
  return code;
}

async function apriSuBugTracker(env, ticketId, devopsId, tipo) {
  const dest = tipo === 'CR' ? 'approvato' : 'aperto';
  const t = await env.BUGS.prepare('SELECT id, type, code, status, devops_id, updated_at FROM tickets WHERE id = ?1').bind(ticketId).first();
  if (!t) return { ok: false, esito: 'ticket non trovato nel bug tracker' };
  const u = await utenteBug(env);
  if (['nuovo', 'preso_in_carico', 'sospesa'].includes(t.status)) {
    const nuovo = await riclassifica(env, t, tipo, u);
    await env.BUGS.prepare("UPDATE tickets SET status = ?4, devops_id = ?2, reject_reason = NULL, status_by = ?3, status_at = datetime('now'), updated_at = datetime('now') WHERE id = ?1").bind(ticketId, devopsId, u.id, dest).run();
    await env.BUGS.prepare('INSERT INTO notes (ticket_id, user_id, body, system) VALUES (?1, ?2, ?3, 1)').bind(ticketId, u.id, `${u.full_name} ha impostato lo stato da «${ET_STATO[t.status] || t.status}» a «${ET_STATO[dest]}», l’ID DevOps a «${devopsId}».`).run();
    return { ok: true, esito: `${nuovo ? 'riclassificato ' + nuovo + ', ' : ''}ticket ${ET_STATO[dest]} con ID DevOps ${devopsId}`, stato: dest };
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

async function archiviaSuBugTracker(env, ticketId) {
  const t = await env.BUGS.prepare('SELECT id, type, code, status FROM tickets WHERE id = ?1').bind(ticketId).first();
  if (!t) return { ok: false, esito: 'ticket non trovato nel bug tracker' };
  if (t.status === 'sospesa') return { ok: true, esito: 'già sospesa', stato: 'sospesa' };
  if (!['nuovo', 'preso_in_carico'].includes(t.status)) return { ok: false, esito: `ticket ${ET_STATO[t.status] || t.status} nel bug tracker: non toccato`, stato: t.status };
  const u = await utenteBug(env);
  const nuovo = await riclassifica(env, t, 'CR', u);
  await env.BUGS.prepare("UPDATE tickets SET status = 'sospesa', reject_reason = NULL, status_by = ?2, status_at = datetime('now'), updated_at = datetime('now') WHERE id = ?1").bind(ticketId, u.id).run();
  await env.BUGS.prepare('INSERT INTO notes (ticket_id, user_id, body, system) VALUES (?1, ?2, ?3, 1)').bind(ticketId, u.id, `${u.full_name} ha impostato lo stato da «${ET_STATO[t.status] || t.status}» a «Sospesa».`).run();
  return { ok: true, esito: `${nuovo ? 'riclassificata ' + nuovo + ', ' : ''}CR sospesa in magazzino`, stato: 'sospesa' };
}

async function respingiSuBugTracker(env, ticketId, motivo) {
  const t = await env.BUGS.prepare('SELECT id, status FROM tickets WHERE id = ?1').bind(ticketId).first();
  if (!t) return { ok: false, esito: 'ticket non trovato nel bug tracker' };
  if (!['nuovo', 'preso_in_carico', 'sospesa'].includes(t.status)) return { ok: false, esito: `ticket ${ET_STATO[t.status] || t.status} nel bug tracker: non toccato`, stato: t.status };
  const u = await utenteBug(env);
  await env.BUGS.prepare("UPDATE tickets SET status = 'respinto', reject_reason = ?2, status_by = ?3, status_at = datetime('now'), updated_at = datetime('now') WHERE id = ?1").bind(ticketId, motivo, u.id).run();
  await env.BUGS.prepare('INSERT INTO notes (ticket_id, user_id, body, system) VALUES (?1, ?2, ?3, 1)').bind(ticketId, u.id, `${u.full_name} ha impostato lo stato da «${ET_STATO[t.status] || t.status}» a «Respinto». Motivazione del rifiuto: «${motivo}»`).run();
  return { ok: true, esito: 'ticket respinto', stato: 'respinto' };
}

const PRIORITA = ['hotfix', 'bloccante', 'alta', 'media', 'bassa'];
const SOGLIE_DEFAULT = { hotfix: [0, 0], bloccante: [5, 5], alta: [5, 10], media: [10, 15], bassa: [20, 20] };

async function soglie(env) {
  let v = {};
  try { v = JSON.parse((await getImp(env, 'soglie')) || '{}'); } catch {}
  const out = {};
  for (const p of PRIORITA) {
    const x = Array.isArray(v[p]) ? v[p] : SOGLIE_DEFAULT[p];
    out[p] = [Math.max(0, Number(x[0]) || 0), Math.max(Number(x[0]) || 0, Number(x[1]) || 0)];
  }
  return out;
}

const fmtRoma = new Intl.DateTimeFormat('sv-SE', { timeZone: 'Europe/Rome', year: 'numeric', month: '2-digit', day: '2-digit' });
function giornoRoma(ms) { return fmtRoma.format(new Date(ms)); }
function msSql(t) { return t ? Date.parse(String(t).replace(' ', 'T') + (/[zZ]|[+-]\d\d:?\d\d$/.test(t) ? '' : 'Z')) : NaN; }

function giorniLavorativi(da, a) {
  if (!(a > da)) return 0;
  let tot = 0, t = da;
  while (t < a) {
    const d = new Date(t);
    const fine = Math.min(a, Date.UTC(d.getUTCFullYear(), d.getUTCMonth(), d.getUTCDate() + 1));
    const g = d.getUTCDay();
    if (g !== 0 && g !== 6) tot += fine - t;
    t = fine;
  }
  return tot / 86400000;
}

function esitoTempi(prio, apertoMs, fineMs, S) {
  if (prio === 'hotfix') return giornoRoma(fineMs) === giornoRoma(apertoMs) ? 'in_tempo' : 'in_ritardo';
  const [ok, lim] = S[prio] || S.media;
  const gg = giorniLavorativi(apertoMs, fineMs);
  return gg <= ok ? 'in_tempo' : gg <= lim ? 'al_limite' : 'in_ritardo';
}

async function aggiornaTempi(env) {
  const db = env.DB, bugs = env.BUGS;
  if (!bugs) return 0;
  const S = await soglie(env);
  const { results: tk } = await bugs.prepare("SELECT id, code, type, title, area, severity, status, devops_id, created_at, status_at FROM tickets WHERE status IN ('aperto','approvato','sospesa','risolto') OR devops_id IS NOT NULL").all();
  const { results: nt } = await bugs.prepare("SELECT ticket_id, body, created_at FROM notes WHERE system = 1 AND (body LIKE '%a «Aperto»%' OR body LIKE '%a «Approvato»%' OR body LIKE '%a «Risolto»%') ORDER BY id").all();
  const { results: us } = await db.prepare("SELECT s.ticket_id, s.modulo, u.priorita, u.inviata_il FROM segnalazioni s JOIN uscite u ON u.segnalazione_id = s.id WHERE u.stato = 'inviata'").all();
  const nostro = new Map(us.map(r => [r.ticket_id, r]));
  const storia = new Map();
  for (const n of nt) {
    const h = storia.get(n.ticket_id) || {};
    if (/a «(Aperto|Approvato)»/.test(n.body) && !h.aperto) h.aperto = n.created_at;
    if (/a «Risolto»/.test(n.body)) h.risolto = n.created_at;
    storia.set(n.ticket_id, h);
  }
  const ora = Date.now();
  const stm = [db.prepare('DELETE FROM tempi')];
  for (const t of tk) {
    if (['nuovo', 'preso_in_carico', 'respinto'].includes(t.status)) continue;
    const h = storia.get(t.id) || {};
    const ns = nostro.get(t.id);
    const apertoIl = h.aperto || (ns && ns.inviata_il) || t.status_at || t.created_at;
    const risoltoIl = t.status === 'risolto' ? (h.risolto || t.status_at) : null;
    const prio = ns && PRIORITA.includes(ns.priorita) ? ns.priorita : (PRIORITA.includes(t.severity) ? t.severity : 'media');
    const am = msSql(apertoIl), rm = risoltoIl ? msSql(risoltoIl) : ora;
    const ggF = giorniLavorativi(am, rm);
    const ggN = giorniLavorativi(msSql(t.created_at), am);
    const esito = t.status === 'sospesa' ? 'sospesa' : esitoTempi(prio, am, rm, S);
    stm.push(db.prepare('INSERT INTO tempi (ticket_id, codice, titolo, tipo, modulo, priorita, fonte_priorita, devops_id, stato, creato, aperto_il, risolto_il, gg_nostri, gg_fornitore, esito) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15)')
      .bind(t.id, t.code, t.title, t.type, (ns && ns.modulo) || t.area, prio, ns ? 'ufficio-it' : 'bug tracker', t.devops_id, t.status, t.created_at, apertoIl, risoltoIl, Math.round(ggN * 10) / 10, Math.round(ggF * 10) / 10, esito));
  }
  await db.batch(stm);
  await setImp(env, 'ultimi_tempi', new Date().toISOString());
  return tk.length;
}

async function anteprimaRisolti(env, testo) {
  const ids = [...new Set(String(testo || '').match(/\d{4,}/g) || [])].slice(0, 200);
  const righe = [];
  for (const id of ids) {
    const { results } = await env.BUGS.prepare('SELECT id, code, title, status FROM tickets WHERE devops_id = ?1').bind(id).all();
    if (!results.length) { righe.push({ devops: id, esito: 'Nessuna segnalazione con questo ID', azione: false }); continue; }
    for (const t of results) {
      const e = t.status === 'risolto' ? ['Già risolta', false] : t.status === 'respinto' ? ['Era stata respinta: da controllare a mano', false] : [`Verrà segnata come risolta (oggi: ${ET_STATO[t.status] || t.status})`, true];
      righe.push({ devops: id, ticket_id: t.id, codice: t.code, titolo: t.title, stato: t.status, esito: e[0], azione: e[1] });
    }
  }
  return righe;
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
  if (!env.ROUTINE_URL || !env.ROUTINE_TOKEN) {
    try { await presaInCarico(env); } catch (e) { await evento(env, 'accettazione', 'acc-lead', 'allarme', 'Presa in carico sul bug tracker non riuscita: ' + txt(e.message || e, 200)); }
    return { ok: false, orario: true, errore: 'Ticket in coda: gli agenti li lavorano al prossimo giro (8:07, 12:07, 16:07)' };
  }
  if (await turnoInCorso(env)) return { ok: false, inCorso: true, errore: 'Gli agenti sono già al lavoro' };
  const ultimo = await getImp(env, 'ultimo_avvio');
  if (!forza && ultimo && Date.now() - Date.parse(ultimo) < ATTESA_TRA_AVVII_MIN * 60000) return { ok: false, errore: 'Avviati da poco' };
  const coda = await lavoroInCoda(env);
  const ids = await env.DB.prepare("SELECT codice, ticket_id FROM segnalazioni WHERE stato = 'nuova' ORDER BY id LIMIT 60").all();
  const testo = `Avvio ${motivo}. In coda: ${coda.segnalazioni} segnalazioni nuove (${ids.results.map(r => r.codice || '#' + r.ticket_id).join(', ') || 'nessuna'}), ${coda.task} task di Davide, ${coda.chat} messaggi in chat, ${coda.modifiche} modifiche di Davide da studiare.`;
  let r, j = {};
  try {
    r = await fetch(env.ROUTINE_URL, { method: 'POST', headers: { authorization: `Bearer ${env.ROUTINE_TOKEN}`, 'anthropic-version': '2023-06-01', 'anthropic-beta': 'experimental-cc-routine-2026-04-01', 'content-type': 'application/json' }, body: JSON.stringify({ text: testo }) });
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
  try { await notificaPronte(env); } catch (e) { console.error('notifiche', e); }
  try {
    const ut = await getImp(env, 'ultimi_tempi');
    if (forza || !ut || Date.now() - Date.parse(ut) > 55 * 60000) await aggiornaTempi(env);
  } catch (e) { console.error('tempi', e); }
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
    db.prepare("SELECT s.id, s.ticket_id, s.codice, s.tipo_originale, s.titolo_originale, s.area, s.severita, s.pro_check, s.autore, s.ticket_stato, s.ticket_creato, s.stato, s.tipo, s.modulo, s.priorita, s.permessi, s.doppione_di, s.respingi_motivo, s.aggiornato, u.id AS uscita_id, u.titolo AS uscita_titolo, u.stato AS uscita_stato, u.modificata FROM segnalazioni s LEFT JOIN uscite u ON u.segnalazione_id = s.id WHERE s.stato NOT IN ('inviata','scartata') OR s.aggiornato > datetime('now', '-30 days') OR (s.tipo = 'CR' AND s.ticket_stato = 'approvato') ORDER BY s.id DESC LIMIT 300").all(),
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
      (SELECT COUNT(*) FROM segnalazioni WHERE stato = 'archiviata') AS crArchiviate,
      (SELECT COUNT(*) FROM segnalazioni WHERE tipo = 'CR' AND ticket_stato = 'approvato') AS crApprovate,
      (SELECT COUNT(*) FROM uscite WHERE stato = 'pronta') AS pronte,
      (SELECT COUNT(*) FROM uscite WHERE stato = 'inviata' AND inviata_il > datetime('now','-7 days')) AS inviate7,
      (SELECT COUNT(*) FROM uscite WHERE stato = 'inviata') AS inviate,
      (SELECT COUNT(*) FROM uscite WHERE stato = 'inviata' AND modificata = 1) AS inviateModificate,
      (SELECT COUNT(*) FROM modifiche WHERE analizzata = 0) AS modificheDaStudiare,
      (SELECT COUNT(*) FROM brain WHERE tipo = 'lezione' AND attivo = 1) AS lezioni,
      (SELECT COUNT(*) FROM tempi WHERE risolto_il IS NULL AND esito = 'in_ritardo') AS inRitardo,
      (SELECT COUNT(*) FROM tempi WHERE risolto_il IS NULL AND stato != 'sospesa') AS daRisolvere,
      (SELECT COUNT(*) FROM tempi WHERE risolto_il > datetime('now','-30 days')) AS risolti30,
      (SELECT COUNT(*) FROM tempi WHERE risolto_il > datetime('now','-90 days') AND esito = 'in_tempo') AS inTempo90,
      (SELECT COUNT(*) FROM tempi WHERE risolto_il > datetime('now','-90 days')) AS risolti90`).first(),
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
    priorita: PRIORITA.includes(b.priorita) ? b.priorita : 'media',
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

  if (p === '/api/push/chiave' && m === 'GET') return json({ pub: (await chiaviVapid(env)).pub });

  if (p === '/api/push/iscrivi' && m === 'POST') {
    const b = await body(req);
    const ep = String((b.subscription && b.subscription.endpoint) || '');
    if (!/^https:\/\//.test(ep)) return json({ errore: 'Iscrizione non valida' }, 400);
    await db.prepare("INSERT INTO push (endpoint, dati, browser) VALUES (?1, ?2, ?3) ON CONFLICT(endpoint) DO UPDATE SET dati = excluded.dati, browser = excluded.browser").bind(ep, JSON.stringify(b.subscription).slice(0, 4000), txt(req.headers.get('user-agent'), 300)).run();
    return json({ ok: true });
  }

  if (p === '/api/push/disiscrivi' && m === 'POST') {
    const b = await body(req);
    await db.prepare('DELETE FROM push WHERE endpoint = ?1').bind(String(b.endpoint || '')).run();
    return json({ ok: true });
  }

  if (p === '/api/push/prova' && m === 'POST') {
    await setImp(env, 'push_prova', new Date().toISOString());
    return json(await inviaPush(env, url.origin));
  }

  if (p === '/api/push/ultime' && m === 'GET') {
    const prova = await getImp(env, 'push_prova');
    const { results } = await db.prepare("SELECT s.id, s.ticket_id, s.codice, u.titolo FROM segnalazioni s JOIN uscite u ON u.segnalazione_id = s.id WHERE s.stato = 'pronta' AND u.stato = 'pronta' AND s.notificata_il > datetime('now', '-30 minutes') ORDER BY s.notificata_il DESC LIMIT 10").all();
    if (!results.length && prova && Date.now() - Date.parse(prova) < 120000) return json([{ id: 0, codice: 'PROVA', titolo: 'Le notifiche dell\'Ufficio IT funzionano' }]);
    return json(results);
  }

  if (p === '/api/risolvi/anteprima' && m === 'POST') {
    if (!env.BUGS) return json({ errore: 'Bug tracker non collegato' }, 500);
    const b = await body(req);
    const righe = await anteprimaRisolti(env, b.testo);
    if (!righe.length) return json({ errore: 'Non trovo nessun ID DevOps nel testo incollato (servono almeno 4 cifre)' }, 400);
    return json({ righe });
  }

  if (p === '/api/risolvi' && m === 'POST') {
    if (!env.BUGS) return json({ errore: 'Bug tracker non collegato' }, 500);
    const b = await body(req);
    const righe = (await anteprimaRisolti(env, (b.ids || []).join(' '))).filter(r => r.azione);
    const u = await utenteBug(env);
    const fatte = [];
    for (const r of righe) {
      const ch = await env.BUGS.prepare("UPDATE tickets SET status = 'risolto', reject_reason = NULL, status_by = ?2, status_at = datetime('now'), updated_at = datetime('now') WHERE id = ?1 AND status NOT IN ('risolto','respinto')").bind(r.ticket_id, u.id).run();
      if (!ch.meta.changes) continue;
      await env.BUGS.prepare('INSERT INTO notes (ticket_id, user_id, body, system) VALUES (?1, ?2, ?3, 1)').bind(r.ticket_id, u.id, `${u.full_name} ha impostato lo stato da «${ET_STATO[r.stato] || r.stato}» a «Risolto».`).run();
      await db.prepare("UPDATE segnalazioni SET ticket_stato = 'risolto' WHERE ticket_id = ?1").bind(r.ticket_id).run();
      fatte.push(r.codice || '#' + r.ticket_id);
    }
    if (fatte.length) await evento(env, 'monitoraggio', 'mon-lead', 'risolti', `${fatte.length} ticket segnati Risolto: ${fatte.join(', ')}`);
    try { await aggiornaTempi(env); } catch (e) { console.error(e); }
    return json({ ok: true, risolte: fatte.length, codici: fatte });
  }

  if (p === '/api/tempi' && m === 'GET') {
    const S = await soglie(env);
    const [righe, rep, ut] = await Promise.all([
      db.prepare("SELECT * FROM tempi WHERE risolto_il IS NULL OR risolto_il > datetime('now','-180 days') ORDER BY (risolto_il IS NULL) DESC, gg_fornitore DESC").all(),
      db.prepare('SELECT id, periodo, testo, creato FROM report ORDER BY id DESC LIMIT 1').first(),
      getImp(env, 'ultimi_tempi')
    ]);
    return json({ soglie: S, righe: righe.results, report: rep, aggiornato: ut });
  }

  if (p === '/api/tempi/soglie' && m === 'POST') {
    const b = await body(req);
    const v = {};
    for (const k of PRIORITA) {
      const x = b[k];
      if (!Array.isArray(x)) continue;
      const a = Math.max(0, Math.min(200, Number(x[0]) || 0)), c = Math.max(a, Math.min(200, Number(x[1]) || 0));
      v[k] = [a, c];
    }
    await setImp(env, 'soglie', JSON.stringify({ ...(await soglie(env)), ...v }));
    await aggiornaTempi(env);
    await evento(env, 'monitoraggio', 'mon-lead', 'impostazioni', 'Soglie dei tempi aggiornate da Davide');
    return json({ ok: true });
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
    const al = await db.prepare('SELECT id, nome, mime, size FROM allegati WHERE segnalazione_id = ?1 ORDER BY id').bind(s.id).all();
    return json({ segnalazione: s, uscita: u, modifiche: mod.results, allegati: al.results });
  }

  mm = p.match(/^\/api\/allegati\/(\d+)$/);
  if (mm && m === 'GET') {
    const a = await db.prepare('SELECT nome, mime, data FROM allegati WHERE id = ?1').bind(Number(mm[1])).first();
    if (!a) return json({ errore: 'Allegato non trovato' }, 404);
    const bin = Uint8Array.from(atob(a.data), c => c.charCodeAt(0));
    const sicuro = /^(image\/(png|jpeg|gif|webp)|application\/pdf|text\/plain)$/.test(a.mime || '');
    return new Response(bin, { headers: { 'content-type': sicuro ? a.mime : 'application/octet-stream', 'content-disposition': `${sicuro ? 'inline' : 'attachment'}; filename*=UTF-8''${encodeURIComponent(a.nome || 'allegato')}`, 'x-content-type-options': 'nosniff', 'cache-control': 'private, max-age=3600' } });
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

  mm = p.match(/^\/api\/uscite\/(\d+)\/(salva|invia|scarta|archivia)$/);
  if (mm && m === 'POST') {
    const b = await body(req);
    const u = await db.prepare('SELECT * FROM uscite WHERE id = ?1').bind(Number(mm[1])).first();
    if (!u) return json({ errore: 'Uscita non trovata' }, 404);
    if (u.stato === 'inviata') return json({ errore: 'Già inviata' }, 409);
    const s = await db.prepare('SELECT id, codice, ticket_id FROM segnalazioni WHERE id = ?1').bind(u.segnalazione_id).first();
    const nome = s ? (s.codice || '#' + s.ticket_id) : '#' + u.segnalazione_id;
    if (mm[2] === 'scarta') {
      const motivo = txt(b.motivo, 1000).trim();
      if (motivo.length < 10) return json({ errore: 'Scrivi una motivazione di almeno 10 caratteri: finisce nel bug tracker' }, 400);
      const sg = await db.prepare('SELECT ticket_id FROM segnalazioni WHERE id = ?1').bind(u.segnalazione_id).first();
      let bt = { ok: false, esito: 'bug tracker non collegato' };
      try { if (env.BUGS && sg) bt = await respingiSuBugTracker(env, sg.ticket_id, motivo); }
      catch (e) { bt = { ok: false, esito: 'errore: ' + txt(e.message || e, 200) }; }
      await db.prepare("UPDATE uscite SET stato = 'scartata', motivo = ?2, aggiornato = datetime('now') WHERE id = ?1").bind(u.id, motivo).run();
      await db.prepare("UPDATE segnalazioni SET stato = 'scartata', ticket_stato = COALESCE(?2, ticket_stato), aggiornato = datetime('now') WHERE id = ?1").bind(u.segnalazione_id, bt.stato || null).run();
      await db.prepare("INSERT INTO modifiche (uscita_id, segnalazione_id, campo, prima, dopo) VALUES (?1, ?2, 'scartata', NULL, ?3)").bind(u.id, u.segnalazione_id, motivo).run();
      await evento(env, 'revisione', 'rev-davide', bt.ok ? 'revisione' : 'allarme', `${nome} scartata: ${txt(motivo, 200)} · bug tracker: ${bt.esito}`);
      return json({ ok: true, bugTracker: bt });
    }
    const agente = await snapshotAgente(env, u);
    const v = valoriUscita(b);
    const devops = txt(b.devops_id, 40).trim();
    if (!v.titolo || !norm(v.testo)) return json({ errore: 'Titolo e testo non possono essere vuoti' }, 400);
    if (mm[2] === 'salva') {
      await db.prepare("UPDATE uscite SET tipo = ?2, priorita = ?3, titolo = ?4, testo = ?5, devops_id = ?6, stato = 'bozza', aggiornato = datetime('now') WHERE id = ?1").bind(u.id, v.tipo, v.priorita, v.titolo, v.testo, devops || null).run();
      return json({ ok: true });
    }
    const archivia = mm[2] === 'archivia';
    if (archivia) v.tipo = 'CR';
    if (!archivia && !devops) return json({ errore: 'Scrivi l’ID DevOps: serve per aprire il ticket nel bug tracker' }, 400);
    let bt = { ok: false, esito: 'bug tracker non collegato' };
    try { if (env.BUGS && s) bt = archivia ? await archiviaSuBugTracker(env, s.ticket_id) : await apriSuBugTracker(env, s.ticket_id, devops, v.tipo); }
    catch (e) { bt = { ok: false, esito: 'errore: ' + txt(e.message || e, 200) }; }
    if (archivia && !bt.ok) return json({ errore: 'Archiviazione non riuscita: ' + bt.esito }, 409);
    const statoFin = archivia ? 'archiviata' : 'inviata';
    const cambi = agente.importata ? [] : CAMPI_USCITA.filter(k => norm(agente[k]) !== norm(v[k]));
    const stmts = cambi.map(k => db.prepare('INSERT INTO modifiche (uscita_id, segnalazione_id, campo, prima, dopo) VALUES (?1, ?2, ?3, ?4, ?5)').bind(u.id, u.segnalazione_id, k, String(agente[k] ?? ''), String(v[k] ?? '')));
    stmts.push(db.prepare("UPDATE uscite SET tipo = ?2, priorita = ?3, titolo = ?4, testo = ?5, devops_id = ?7, stato = ?8, modificata = ?6, inviata_il = CASE WHEN ?8 = 'inviata' THEN datetime('now') ELSE inviata_il END, aggiornato = datetime('now') WHERE id = ?1").bind(u.id, v.tipo, v.priorita, v.titolo, v.testo, cambi.length ? 1 : 0, devops || null, statoFin));
    stmts.push(db.prepare("UPDATE segnalazioni SET stato = ?5, tipo = ?2, priorita = ?3, ticket_stato = COALESCE(?4, ticket_stato), aggiornato = datetime('now') WHERE id = ?1").bind(u.segnalazione_id, v.tipo, v.priorita, bt.stato || null, statoFin));
    await db.batch(stmts);
    await evento(env, archivia ? 'cr' : 'revisione', archivia ? 'cr-arch' : 'rev-davide', bt.ok ? 'revisione' : 'allarme', `${nome} ${archivia ? 'archiviata nel magazzino CR' : (v.tipo === 'CR' ? 'approvata' : 'inviata') + ' (DevOps ' + devops + ')'}${cambi.length ? ' con modifiche a ' + cambi.join(', ') : ''} · bug tracker: ${bt.esito}`);
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

const SW_JS = `self.addEventListener('install', () => self.skipWaiting());
self.addEventListener('activate', e => e.waitUntil(self.clients.claim()));
self.addEventListener('push', e => e.waitUntil((async () => {
  let r = [];
  try { const x = await fetch('/api/push/ultime', { credentials: 'include', cache: 'no-store' }); if (x.ok) r = await x.json(); } catch (_) {}
  const titolo = r.length > 1 ? r.length + ' segnalazioni pronte in Revisione' : 'Pronta in Revisione';
  const corpo = r.length ? r.slice(0, 4).map(x => (x.codice || '#' + x.ticket_id) + ' · ' + (x.titolo || '')).join('\\n') : 'Una segnalazione aspetta la tua revisione.';
  await self.registration.showNotification(titolo, { body: corpo, tag: 'ufficio-it-revisione', renotify: true, icon: '/icona.svg', badge: '/icona.svg', data: { url: r.length === 1 ? '/?seg=' + r[0].id : '/?tab=revisione' } });
})()));
self.addEventListener('notificationclick', e => {
  e.notification.close();
  const url = (e.notification.data && e.notification.data.url) || '/';
  e.waitUntil((async () => {
    const cl = await self.clients.matchAll({ type: 'window', includeUncontrolled: true });
    for (const c of cl) { if (new URL(c.url).origin === self.location.origin) { await c.focus(); c.postMessage({ apri: url }); return; } }
    await self.clients.openWindow(url);
  })());
});`;

const ICONA_SVG = `<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 64 64'><rect width='64' height='64' rx='14' fill='#1b1d2e'/><path d='M32 11 51 22 32 33 13 22Z' fill='#f2c75c'/><path d='M13 22 32 33V54L13 43Z' fill='#c9952b'/><path d='M51 22 32 33V54L51 43Z' fill='#e3b341'/><path d='M32 33V54' stroke='#1b1d2e' stroke-width='1.5'/></svg>`;

const b64u = buf => btoa(String.fromCharCode(...new Uint8Array(buf))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');

async function chiaviVapid(env) {
  const v = await getImp(env, 'vapid');
  if (v) { try { return JSON.parse(v); } catch {} }
  const k = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
  const out = { pub: b64u(await crypto.subtle.exportKey('raw', k.publicKey)), jwk: await crypto.subtle.exportKey('jwk', k.privateKey) };
  await setImp(env, 'vapid', JSON.stringify(out));
  return out;
}

async function inviaPush(env, origine) {
  const { results } = await env.DB.prepare('SELECT endpoint FROM push').all();
  if (!results.length) return { inviate: 0, iscritti: 0 };
  const V = await chiaviVapid(env);
  const key = await crypto.subtle.importKey('jwk', V.jwk, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign']);
  const enc = o => b64u(new TextEncoder().encode(JSON.stringify(o)));
  let inviate = 0;
  const esiti = [];
  for (const { endpoint } of results) {
    try {
      const aud = new URL(endpoint).origin;
      const dati = enc({ typ: 'JWT', alg: 'ES256' }) + '.' + enc({ aud, exp: Math.floor(Date.now() / 1000) + 12 * 3600, sub: origine });
      const firma = await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, key, new TextEncoder().encode(dati));
      const r = await fetch(endpoint, { method: 'POST', headers: { authorization: `vapid t=${dati}.${b64u(firma)}, k=${V.pub}`, ttl: '86400', urgency: 'high' }, body: '' });
      const testo = await r.text().catch(() => '');
      esiti.push({ servizio: new URL(endpoint).host, status: r.status, risposta: testo.slice(0, 300) });
      if (r.status === 404 || r.status === 410) await env.DB.prepare('DELETE FROM push WHERE endpoint = ?1').bind(endpoint).run();
      else if (r.ok) inviate++;
    } catch (e) { esiti.push({ servizio: endpoint.slice(0, 40), errore: String(e.message || e) }); }
  }
  await setImp(env, 'push_esito', JSON.stringify({ quando: new Date().toISOString(), esiti }));
  return { inviate, iscritti: results.length, esiti };
}

async function notificaPronte(env) {
  const { results } = await env.DB.prepare("SELECT s.id FROM segnalazioni s JOIN uscite u ON u.segnalazione_id = s.id WHERE s.stato = 'pronta' AND u.stato = 'pronta' AND (s.notificata_il IS NULL OR u.aggiornato > s.notificata_il)").all();
  if (!results.length) return 0;
  await env.DB.batch(results.map(r => env.DB.prepare("UPDATE segnalazioni SET notificata_il = datetime('now') WHERE id = ?1").bind(r.id)));
  await inviaPush(env, env.ORIGINE || 'https://ufficio-it.sebach-reparto-it.workers.dev');
  return results.length;
}

export default {
  async scheduled(ev, env, ctx) {
    if (env.SESSION_KEY) ctx.waitUntil(controllo(env, 'automatico (controllo ogni 10 minuti)', false).catch(e => console.error(e)));
  },
  async fetch(req, env, ctx) {
    const url = new URL(req.url);
    if (!env.SESSION_KEY || !env.DASH_PASSWORD) return new Response('Configura i secret DASH_PASSWORD e SESSION_KEY nelle impostazioni del Worker.', { status: 500 });

    if (url.pathname === '/sw.js') return new Response(SW_JS, { headers: { 'content-type': 'application/javascript; charset=utf-8', 'cache-control': 'no-cache' } });
    if (url.pathname === '/icona.svg') return new Response(ICONA_SVG, { headers: { 'content-type': 'image/svg+xml', 'cache-control': 'public, max-age=86400' } });

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
