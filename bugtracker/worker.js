/**
 * Sebach Plus - Gestione Bug & CR
 * Cloudflare Worker + D1
 *
 * Rotte:
 *   /api/*  -> API JSON
 *   /*      -> la pagina della dashboard
 */

/* ============================================================================
   FILE UNICO — da incollare nell'editor del Worker su Cloudflare.
   Contiene sia le API sia la pagina, logo compreso. Non serve nessun altro file.
   La pagina HTML sta nella costante PAGINA, poco sopra l'export finale.
   ============================================================================ */

const SESSION_COOKIE = 'sbp_session';
const SESSION_DAYS = 7;
const PBKDF2_ITER = 100_000;

/* ---------------------------------------------------------- utils */

const json = (data, status = 200, headers = {}) =>
  new Response(JSON.stringify(data), {
    status,
    headers: { 'content-type': 'application/json; charset=utf-8', ...headers },
  });

const fail = (message, status = 400) => json({ error: message }, status);

const bytesToHex = (buf) =>
  [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, '0')).join('');

const hexToBytes = (hex) => {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.substr(i * 2, 2), 16);
  return out;
};

const randomHex = (n = 32) => bytesToHex(crypto.getRandomValues(new Uint8Array(n)));

async function hashPassword(password, saltHex) {
  const key = await crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(password),
    'PBKDF2',
    false,
    ['deriveBits']
  );
  const bits = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', salt: hexToBytes(saltHex), iterations: PBKDF2_ITER, hash: 'SHA-256' },
    key,
    256
  );
  return bytesToHex(bits);
}

const safeEqual = (a, b) => {
  if (!a || !b || a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
};

function readCookie(request, name) {
  const raw = request.headers.get('Cookie') || '';
  for (const part of raw.split(';')) {
    const [k, ...v] = part.trim().split('=');
    if (k === name) return decodeURIComponent(v.join('='));
  }
  return null;
}

const cookieHeader = (token, maxAge) =>
  `${SESSION_COOKIE}=${token}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${maxAge}`;

const clean = (v, max = 4000) =>
  typeof v === 'string' ? v.trim().slice(0, max) : v == null ? null : String(v).slice(0, max);

/* ---------------------------------------------------------- auth */

async function currentUser(request, env) {
  const token = readCookie(request, SESSION_COOKIE);
  if (!token) return null;
  const row = await env.DB.prepare(
    `SELECT u.id, u.username, u.full_name, u.email, u.role, u.must_change_password, u.active
       FROM sessions s JOIN users u ON u.id = s.user_id
      WHERE s.token = ? AND s.expires_at > datetime('now')`
  )
    .bind(token)
    .first();
  if (!row || !row.active) return null;
  return row;
}

const isAdmin = (u) => u && u.role === 'admin';

/* ---------------------------------------------------------- ticket helpers */

const TICKET_SELECT = `
  SELECT t.*, u.full_name AS author_name, u.username AS author_username,
         a.full_name AS status_by_name,
         (SELECT COUNT(*) FROM notes n WHERE n.ticket_id = t.id) AS notes_count
    FROM tickets t
    JOIN users u ON u.id = t.created_by
    LEFT JOIN users a ON a.id = t.status_by`;

const VALID_STATUS = ['nuovo', 'preso_in_carico', 'aperto', 'approvato', 'risolto', 'respinto', 'sospesa'];
const VALID_SEVERITY = ['bloccante', 'alta', 'media', 'bassa'];
const VALID_PRO = ['anche_su_pro', 'solo_su_plus', 'non_applicabile'];

// l'utente può modificare il proprio ticket finché non è stato lavorato
const userCanEdit = (t, u) =>
  isAdmin(u) || (t.created_by === u.id && (t.status === 'nuovo' || t.status === 'preso_in_carico' || t.status === 'respinto'));

async function addSystemNote(env, ticketId, userId, body) {
  await env.DB.prepare(
    `INSERT INTO notes (ticket_id, user_id, body, system) VALUES (?, ?, ?, 1)`
  )
    .bind(ticketId, userId, body)
    .run();
}

/* ---------------------------------------------------------- storico modifiche */

const ETICHETTE_CAMPI = {
  title: 'il titolo',
  area: "l'area",
  operation: "l'operazione",
  doc_number: 'il numero documento',
  error_text: "la descrizione dell'errore",
  no_error_message: 'il flag «nessun messaggio a video»',
  severity: 'la gravità',
  pro_check: 'la verifica su Sebach Pro',
  type: 'il tipo',
  devops_id: "l'ID DevOps",
  devops_override: 'l\u2019override priority/severity',
  devops_priority: 'la priority forzata',
  devops_severity: 'la severity forzata',
  tag: 'il tag',
  status: 'lo stato',
};

// per questi campi non ha senso riportare il testo intero nello storico
const CAMPI_LUNGHI = new Set(['error_text', 'operation']);

// campi 0/1 che vanno mostrati come Sì/No invece che come numero
const CAMPI_BOOLEANI = new Set(['no_error_message', 'devops_override']);

const ETICHETTE_VALORI = {
  nuovo: 'Nuovo',
  preso_in_carico: 'Preso in carico',
  aperto: 'Aperto',
  approvato: 'Approvato',
  risolto: 'Risolto',
  respinto: 'Respinto',
  sospesa: 'Sospesa',
  bloccante: 'bloccante',
  alta: 'alta',
  media: 'media',
  bassa: 'bassa',
  anche_su_pro: 'stesso errore anche su Sebach Pro',
  solo_su_plus: 'su Sebach Pro funziona',
  non_applicabile: 'funzione solo su Sebach Plus',
  non_verificato: 'non verificato',
};

const mostraValore = (v) => {
  if (v === null || v === undefined || v === '') return '—';
  return ETICHETTE_VALORI[v] || String(v);
};

const elencoIt = (voci) =>
  voci.length === 1 ? voci[0] : `${voci.slice(0, -1).join(', ')} e ${voci[voci.length - 1]}`;

/** Confronta due versioni del ticket e descrive a parole cosa è cambiato. */
function descriviModifiche(prima, dopo) {
  const impostati = [];
  const riscritti = [];
  for (const campo of Object.keys(ETICHETTE_CAMPI)) {
    const a = prima[campo] ?? null;
    const b = dopo[campo] ?? null;
    if (String(a ?? '') === String(b ?? '')) continue;
    if (CAMPI_LUNGHI.has(campo)) {
      riscritti.push(ETICHETTE_CAMPI[campo]);
    } else if (CAMPI_BOOLEANI.has(campo)) {
      impostati.push(
        `${ETICHETTE_CAMPI[campo]} da «${a ? 'Sì' : 'No'}» a «${b ? 'Sì' : 'No'}»`
      );
    } else {
      impostati.push(`${ETICHETTE_CAMPI[campo]} da «${mostraValore(a)}» a «${mostraValore(b)}»`);
    }
  }
  const frasi = [];
  if (impostati.length) frasi.push(`ha impostato ${elencoIt(impostati)}`);
  if (riscritti.length) frasi.push(`ha riscritto ${elencoIt(riscritti)}`);
  return frasi;
}

async function registraModifiche(env, ticketId, utente, prima, dopo, coda = '') {
  const pezzi = descriviModifiche(prima, dopo);
  if (!pezzi.length && !coda) return;
  let testo = pezzi.length ? `${utente.full_name} ${pezzi.join(', ')}.` : `${utente.full_name}:`;
  if (coda) testo += ` ${coda}`;
  await addSystemNote(env, ticketId, utente.id, testo);
}

/* ---------------------------------------------------------- allegati */

const MAX_ALLEGATO = 1_200_000; // byte del file originale, prima della codifica base64
const MAX_ALLEGATI_PER_TICKET = 6;
const MIME_AMMESSI = [
  'image/png',
  'image/jpeg',
  'image/webp',
  'image/gif',
  'application/pdf',
  'text/plain',
  'text/csv',
  'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
  'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
  'application/vnd.ms-excel',
  'application/msword',
  'message/rfc822',
  'application/vnd.ms-outlook',
];

/* ---------------------------------------------------------- API */

async function handleApi(request, env, url) {
  const path = url.pathname.replace(/^\/api/, '');
  const method = request.method;
  const body = ['POST', 'PATCH', 'PUT'].includes(method)
    ? await request.json().catch(() => ({}))
    : {};

  /* ---- login ---- */
  if (path === '/auth/login' && method === 'POST') {
    const username = clean(body.username, 60)?.toLowerCase();
    const password = body.password || '';
    if (!username || !password) return fail('Inserisci utente e password.', 400);

    const user = await env.DB.prepare(`SELECT * FROM users WHERE lower(username) = ?`)
      .bind(username)
      .first();
    if (!user || !user.active) return fail('Utente o password non corretti.', 401);

    let ok = false;
    if (user.password_hash) {
      ok = safeEqual(await hashPassword(password, user.password_salt), user.password_hash);
    } else {
      ok = !!env.DEFAULT_PASSWORD && safeEqual(password, env.DEFAULT_PASSWORD);
    }
    if (!ok) return fail('Utente o password non corretti.', 401);

    const token = randomHex(32);
    await env.DB.prepare(
      `INSERT INTO sessions (token, user_id, expires_at)
       VALUES (?, ?, datetime('now', '+${SESSION_DAYS} days'))`
    )
      .bind(token, user.id)
      .run();

    return json(
      {
        id: user.id,
        username: user.username,
        full_name: user.full_name,
        role: user.role,
        must_change_password: user.must_change_password,
      },
      200,
      { 'Set-Cookie': cookieHeader(token, SESSION_DAYS * 86400) }
    );
  }

  if (path === '/auth/logout' && method === 'POST') {
    const token = readCookie(request, SESSION_COOKIE);
    if (token) await env.DB.prepare(`DELETE FROM sessions WHERE token = ?`).bind(token).run();
    return json({ ok: true }, 200, { 'Set-Cookie': cookieHeader('', 0) });
  }

  /* ---- da qui serve la sessione ---- */
  const me = await currentUser(request, env);
  if (!me) return fail('Sessione scaduta. Rientra.', 401);

  if (path === '/auth/me' && method === 'GET') return json(me);

  if (path === '/auth/change-password' && method === 'POST') {
    const current = body.current || '';
    const next = body.next || '';
    if (next.length < 8) return fail('La nuova password deve avere almeno 8 caratteri.', 400);
    if (!/[A-Za-z]/.test(next) || !/[0-9]/.test(next))
      return fail('La nuova password deve contenere almeno una lettera e un numero.', 400);

    const row = await env.DB.prepare(`SELECT * FROM users WHERE id = ?`).bind(me.id).first();
    const currentOk = row.password_hash
      ? safeEqual(await hashPassword(current, row.password_salt), row.password_hash)
      : !!env.DEFAULT_PASSWORD && safeEqual(current, env.DEFAULT_PASSWORD);
    if (!currentOk) return fail('La password attuale non è corretta.', 400);
    if (env.DEFAULT_PASSWORD && safeEqual(next, env.DEFAULT_PASSWORD))
      return fail('Scegli una password diversa da quella di default.', 400);

    const salt = randomHex(16);
    const hash = await hashPassword(next, salt);
    await env.DB.prepare(
      `UPDATE users SET password_hash = ?, password_salt = ?, must_change_password = 0 WHERE id = ?`
    )
      .bind(hash, salt, me.id)
      .run();
    return json({ ok: true });
  }

  // finché la password è quella di default si può solo cambiarla
  if (me.must_change_password && !path.startsWith('/auth/'))
    return fail('Devi prima cambiare la password.', 403);

  /* ---- elenco ticket ---- */
  if (path === '/tickets' && method === 'GET') {
    const { results } = await env.DB.prepare(`${TICKET_SELECT} ORDER BY t.id DESC`).all();
    return json(results || []);
  }

  /* ---- nuovo ticket ---- */
  if (path === '/tickets' && method === 'POST') {
    const title = clean(body.title, 200);
    const area = clean(body.area, 200);
    const operation = clean(body.operation, 300);
    const errorText = clean(body.error_text, 4000);
    const noErrorMessage = body.no_error_message ? 1 : 0;
    const expected = clean(body.expected, 2000);
    const proCheck = VALID_PRO.includes(body.pro_check) ? body.pro_check : 'non_applicabile';
    const severity = VALID_SEVERITY.includes(body.severity) ? body.severity : 'media';
    const tag = clean(body.tag, 60) || null;
    const type = body.type === 'CR' ? 'CR' : 'BUG';
    const priorita = Number(body.devops_priority);
    const prioritaValida = Number.isInteger(priorita) && priorita >= 1 && priorita <= 4 ? priorita : null;

    if (!title || title.length < 8) return fail('Il titolo deve essere più descrittivo.', 400);
    if (!area) return fail('Indica in che menu ti trovi.', 400);
    if (!noErrorMessage) {
      if (!errorText) return fail('Scrivi almeno qualche parola su cosa succede.', 400);
      if (errorText.length < 15)
        return fail('Descrivi meglio l\u2019errore che stai riscontrando.', 400);
    }

    const ins = await env.DB.prepare(
      `INSERT INTO tickets (type, title, area, operation, doc_number, error_text, no_error_message, expected,
                            pro_check, severity, tag, created_by, devops_priority, devops_override)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) RETURNING id`
    )
      .bind(
        type,
        title,
        area,
        operation,
        clean(body.doc_number, 80),
        errorText,
        noErrorMessage,
        expected,
        proCheck,
        severity,
        tag,
        me.id,
        prioritaValida,
        prioritaValida ? 1 : 0
      )
      .first();

    const code = `${type}-${String(ins.id).padStart(4, '0')}`;
    await env.DB.prepare(`UPDATE tickets SET code = ? WHERE id = ?`).bind(code, ins.id).run();

    const created = await env.DB.prepare(`${TICKET_SELECT} WHERE t.id = ?`).bind(ins.id).first();
    return json(created, 201);
  }

  /* ---- ticket singolo ---- */
  const ticketMatch = path.match(/^\/tickets\/(\d+)$/);
  if (ticketMatch) {
    const id = Number(ticketMatch[1]);
    const ticket = await env.DB.prepare(`${TICKET_SELECT} WHERE t.id = ?`).bind(id).first();
    if (!ticket) return fail('Ticket non trovato.', 404);

    if (method === 'GET') return json(ticket);

    if (method === 'PATCH') {
      if (!userCanEdit(ticket, me))
        return fail('Puoi modificare solo i ticket che hai aperto tu, prima della presa in carico.', 403);

      const fields = [];
      const values = [];
      const setIf = (col, value) => {
        if (value !== undefined) {
          fields.push(`${col} = ?`);
          values.push(value);
        }
      };
      setIf('title', body.title !== undefined ? clean(body.title, 200) : undefined);
      setIf('area', body.area !== undefined ? clean(body.area, 200) : undefined);
      setIf('operation', body.operation !== undefined ? clean(body.operation, 300) : undefined);
      setIf('doc_number', body.doc_number !== undefined ? clean(body.doc_number, 80) : undefined);
      setIf('error_text', body.error_text !== undefined ? clean(body.error_text, 4000) : undefined);
      if (body.no_error_message !== undefined) setIf('no_error_message', body.no_error_message ? 1 : 0);
      setIf('expected', body.expected !== undefined ? clean(body.expected, 2000) : undefined);
      setIf('tag', body.tag !== undefined ? (clean(body.tag, 60) || null) : undefined);
      if (VALID_SEVERITY.includes(body.severity)) setIf('severity', body.severity);
      if (VALID_PRO.includes(body.pro_check)) setIf('pro_check', body.pro_check);
      // il tipo (BUG o CR) lo sceglie chi segnala; l'admin lo può cambiare sempre
      if (body.type === 'BUG' || body.type === 'CR') setIf('type', body.type);
      if (isAdmin(me) && body.devops_id !== undefined) setIf('devops_id', clean(body.devops_id, 40));
      // priorità: la sceglie chi segnala, e l'admin la può forzare; vale finché il bug è Nuovo
      const aperto = ticket.status === 'nuovo' || ticket.status === 'preso_in_carico';
      if (body.devops_priority !== undefined && (isAdmin(me) || aperto)) {
        const p = Number(body.devops_priority);
        const ok = Number.isInteger(p) && p >= 1 && p <= 4;
        setIf('devops_priority', ok ? p : null);
        setIf('devops_override', ok ? 1 : 0);
      }
      // priority/severity forzate dall'admin: solo finché il bug è ancora Nuovo
      if (isAdmin(me) && aperto) {
        if (body.devops_override !== undefined) setIf('devops_override', body.devops_override ? 1 : 0);
        if (body.devops_severity !== undefined) setIf('devops_severity', clean(body.devops_severity, 60) || null);
      }

      if (!fields.length) return json(ticket);
      fields.push(`updated_at = datetime('now')`);
      await env.DB.prepare(`UPDATE tickets SET ${fields.join(', ')} WHERE id = ?`)
        .bind(...values, id)
        .run();

      let updated = await env.DB.prepare(`${TICKET_SELECT} WHERE t.id = ?`).bind(id).first();
      let coda = '';
      if (updated.type !== ticket.type) {
        // il codice segue il tipo: BUG-0007 diventa CR-0007
        const code = `${updated.type}-${String(id).padStart(4, '0')}`;
        await env.DB.prepare(`UPDATE tickets SET code = ? WHERE id = ?`).bind(code, id).run();
        coda = `La segnalazione è stata riclassificata come ${code}.`;
        updated = await env.DB.prepare(`${TICKET_SELECT} WHERE t.id = ?`).bind(id).first();
      }
      await registraModifiche(env, id, me, ticket, updated, coda);
      return json(updated);
    }

    if (method === 'DELETE') {
      if (!isAdmin(me)) return fail('Solo un admin può eliminare un ticket.', 403);
      await env.DB.prepare(`DELETE FROM tickets WHERE id = ?`).bind(id).run();
      return json({ ok: true });
    }
  }

  /* ---- cambio stato (solo admin) ---- */
  const statusMatch = path.match(/^\/tickets\/(\d+)\/status$/);
  if (statusMatch && method === 'POST') {
    if (!isAdmin(me)) return fail('Solo un admin può cambiare lo stato di un ticket.', 403);
    const id = Number(statusMatch[1]);
    const status = body.status;
    if (!VALID_STATUS.includes(status)) return fail('Stato non valido.', 400);

    const reason = clean(body.reject_reason, 2000);
    if (status === 'respinto' && (!reason || reason.length < 10))
      return fail('Per respingere un ticket devi scrivere una motivazione.', 400);

    const devopsId = body.devops_id !== undefined ? clean(body.devops_id, 40) : undefined;
    if (status === 'aperto' && !devopsId)
      return fail('Per aprire il ticket serve l\u2019ID di Azure DevOps.', 400);

    const before = await env.DB.prepare(`SELECT * FROM tickets WHERE id = ?`).bind(id).first();
    if (!before) return fail('Ticket non trovato.', 404);

    if (status === 'sospesa' && before.type !== 'CR')
      return fail('Solo le Change Request si possono sospendere.', 400);

    await env.DB.prepare(
      `UPDATE tickets
          SET status = ?,
              reject_reason = ?,
              devops_id = COALESCE(?, devops_id),
              status_by = ?,
              status_at = datetime('now'),
              updated_at = datetime('now')
        WHERE id = ?`
    )
      .bind(status, status === 'respinto' ? reason : null, devopsId ?? null, me.id, id)
      .run();

    const dopo = await env.DB.prepare(`${TICKET_SELECT} WHERE t.id = ?`).bind(id).first();
    const coda =
      status === 'respinto' ? `Motivazione del rifiuto: «${reason}»` : '';
    await registraModifiche(env, id, me, before, dopo, coda);

    return json(dopo);
  }

  /* ---- note ---- */
  const notesMatch = path.match(/^\/tickets\/(\d+)\/notes$/);
  if (notesMatch) {
    const id = Number(notesMatch[1]);
    if (method === 'GET') {
      const { results } = await env.DB.prepare(
        `SELECT n.id, n.body, n.system, n.created_at, u.full_name AS author_name, u.id AS user_id
           FROM notes n JOIN users u ON u.id = n.user_id
          WHERE n.ticket_id = ? ORDER BY n.id ASC`
      )
        .bind(id)
        .all();
      return json(results || []);
    }
    if (method === 'POST') {
      const text = clean(body.body, 2000);
      if (!text) return fail('Scrivi qualcosa prima di inviare.', 400);
      await env.DB.prepare(`INSERT INTO notes (ticket_id, user_id, body) VALUES (?, ?, ?)`)
        .bind(id, me.id, text)
        .run();
      await env.DB.prepare(`UPDATE tickets SET updated_at = datetime('now') WHERE id = ?`)
        .bind(id)
        .run();
      return json({ ok: true }, 201);
    }
  }

  /* ---- allegati ---- */
  const allegatiMatch = path.match(/^\/tickets\/(\d+)\/attachments$/);
  if (allegatiMatch) {
    const id = Number(allegatiMatch[1]);
    if (method === 'GET') {
      const { results } = await env.DB.prepare(
        `SELECT a.id, a.filename, a.mime, a.size, a.created_at, a.user_id, u.full_name AS author_name
           FROM attachments a JOIN users u ON u.id = a.user_id
          WHERE a.ticket_id = ? ORDER BY a.id ASC`
      )
        .bind(id)
        .all();
      return json(results || []);
    }
    if (method === 'POST') {
      const ticket = await env.DB.prepare(`SELECT * FROM tickets WHERE id = ?`).bind(id).first();
      if (!ticket) return fail('Ticket non trovato.', 404);
      if (!userCanEdit(ticket, me))
        return fail(
          'Puoi aggiungere allegati solo alle tue segnalazioni, prima che vengano prese in carico.',
          403
        );

      const filename = clean(body.filename, 160);
      const mime = clean(body.mime, 120) || 'application/octet-stream';
      const estensione = (filename || '').split('.').pop().toLowerCase();
      const dati = typeof body.data === 'string' ? body.data : '';
      if (!filename || !dati) return fail('Allegato incompleto.', 400);
      // .cbi (tracciati bancari CBI) non ha un tipo MIME standard: si riconosce dall'estensione
      if (!MIME_AMMESSI.includes(mime) && estensione !== 'cbi')
        return fail('Tipo di file non ammesso: usa immagini, PDF, testo o documenti Office.', 400);

      // lunghezza base64 -> byte reali, senza decodificare
      const size = Math.floor((dati.length * 3) / 4);
      if (size > MAX_ALLEGATO)
        return fail(
          `File troppo grande (${Math.round(size / 1024)} KB). Il limite è ${Math.round(
            MAX_ALLEGATO / 1024
          )} KB per file.`,
          400
        );

      const quanti = await env.DB.prepare(
        `SELECT COUNT(*) AS c FROM attachments WHERE ticket_id = ?`
      )
        .bind(id)
        .first();
      if (quanti.c >= MAX_ALLEGATI_PER_TICKET)
        return fail(`Massimo ${MAX_ALLEGATI_PER_TICKET} allegati per segnalazione.`, 400);

      await env.DB.prepare(
        `INSERT INTO attachments (ticket_id, user_id, filename, mime, size, data)
         VALUES (?, ?, ?, ?, ?, ?)`
      )
        .bind(id, me.id, filename, mime, size, dati)
        .run();
      await env.DB.prepare(`UPDATE tickets SET updated_at = datetime('now') WHERE id = ?`)
        .bind(id)
        .run();
      await addSystemNote(env, id, me.id, `${me.full_name} ha allegato «${filename}».`);
      return json({ ok: true }, 201);
    }
  }

  const fileMatch = path.match(/^\/attachments\/(\d+)$/);
  if (fileMatch) {
    const id = Number(fileMatch[1]);
    const row = await env.DB.prepare(`SELECT * FROM attachments WHERE id = ?`).bind(id).first();
    if (!row) return fail('Allegato non trovato.', 404);

    if (method === 'GET') {
      const binario = Uint8Array.from(atob(row.data), (c) => c.charCodeAt(0));
      const inline = row.mime.startsWith('image/') || row.mime === 'application/pdf';
      return new Response(binario, {
        headers: {
          'content-type': row.mime,
          'content-disposition': `${inline ? 'inline' : 'attachment'}; filename="${row.filename.replace(
            /"/g,
            ''
          )}"`,
          'cache-control': 'private, max-age=3600',
        },
      });
    }

    if (method === 'DELETE') {
      if (!isAdmin(me) && row.user_id !== me.id)
        return fail('Puoi togliere solo gli allegati che hai caricato tu.', 403);
      await env.DB.prepare(`DELETE FROM attachments WHERE id = ?`).bind(id).run();
      await addSystemNote(
        env,
        row.ticket_id,
        me.id,
        `${me.full_name} ha rimosso l'allegato «${row.filename}».`
      );
      return json({ ok: true });
    }
  }

  /* ---- aree del wizard ---- */
  if (path === '/areas' && method === 'GET') {
    const { results } = await env.DB.prepare(
      `SELECT id, name, position FROM areas ORDER BY position, id`
    ).all();
    return json(results || []);
  }

  if (path === '/areas' && method === 'POST') {
    if (!isAdmin(me)) return fail('Riservato agli admin.', 403);
    const name = clean(body.name, 100);
    if (!name) return fail('Scrivi un nome per la voce.', 400);
    if (name.toLowerCase() === 'altro')
      return fail('«Altro» è già presente in automatico in fondo all\u2019elenco.', 400);
    const doppio = await env.DB.prepare(`SELECT id FROM areas WHERE lower(name) = lower(?)`)
      .bind(name)
      .first();
    if (doppio) return fail('Esiste già una voce con questo nome.', 400);
    const max = await env.DB.prepare(`SELECT COALESCE(MAX(position),0) AS m FROM areas`).first();
    await env.DB.prepare(`INSERT INTO areas (name, position) VALUES (?, ?)`)
      .bind(name, max.m + 1)
      .run();
    const { results } = await env.DB.prepare(
      `SELECT id, name, position FROM areas ORDER BY position, id`
    ).all();
    return json(results || [], 201);
  }

  const areaMatch = path.match(/^\/areas\/(\d+)$/);
  if (areaMatch) {
    if (!isAdmin(me)) return fail('Riservato agli admin.', 403);
    const id = Number(areaMatch[1]);
    const riga = await env.DB.prepare(`SELECT * FROM areas WHERE id = ?`).bind(id).first();
    if (!riga) return fail('Voce non trovata.', 404);

    if (method === 'PATCH') {
      if (body.name !== undefined) {
        const name = clean(body.name, 100);
        if (!name) return fail('Il nome non può restare vuoto.', 400);
        if (name.toLowerCase() === 'altro')
          return fail('«Altro» è riservato e già presente in fondo all\u2019elenco.', 400);
        const doppio = await env.DB.prepare(
          `SELECT id FROM areas WHERE lower(name) = lower(?) AND id <> ?`
        )
          .bind(name, id)
          .first();
        if (doppio) return fail('Esiste già una voce con questo nome.', 400);
        await env.DB.prepare(`UPDATE areas SET name = ? WHERE id = ?`).bind(name, id).run();
      }
      if (body.direzione === 'su' || body.direzione === 'giu') {
        const { results } = await env.DB.prepare(
          `SELECT id, position FROM areas ORDER BY position, id`
        ).all();
        const idx = results.findIndex((r) => r.id === id);
        const vicino = body.direzione === 'su' ? idx - 1 : idx + 1;
        if (idx !== -1 && vicino >= 0 && vicino < results.length) {
          const a = results[idx],
            b = results[vicino];
          await env.DB.prepare(`UPDATE areas SET position = ? WHERE id = ?`)
            .bind(b.position, a.id)
            .run();
          await env.DB.prepare(`UPDATE areas SET position = ? WHERE id = ?`)
            .bind(a.position, b.id)
            .run();
        }
      }
      const { results } = await env.DB.prepare(
        `SELECT id, name, position FROM areas ORDER BY position, id`
      ).all();
      return json(results || []);
    }

    if (method === 'DELETE') {
      await env.DB.prepare(`DELETE FROM areas WHERE id = ?`).bind(id).run();
      const { results } = await env.DB.prepare(
        `SELECT id, name, position FROM areas ORDER BY position, id`
      ).all();
      return json(results || []);
    }
  }

  /* ---- tag (per il tracciamento rapido, ma disponibili su qualunque ticket) ---- */
  if (path === '/tags' && method === 'GET') {
    const { results } = await env.DB.prepare(
      `SELECT id, name, position FROM tags ORDER BY position, id`
    ).all();
    return json(results || []);
  }

  if (path === '/tags' && method === 'POST') {
    if (!isAdmin(me)) return fail('Riservato agli admin.', 403);
    const name = clean(body.name, 60);
    if (!name) return fail('Scrivi un nome per il tag.', 400);
    const doppio = await env.DB.prepare(`SELECT id FROM tags WHERE lower(name) = lower(?)`)
      .bind(name)
      .first();
    if (doppio) return fail('Esiste già un tag con questo nome.', 400);
    const max = await env.DB.prepare(`SELECT COALESCE(MAX(position),0) AS m FROM tags`).first();
    await env.DB.prepare(`INSERT INTO tags (name, position) VALUES (?, ?)`)
      .bind(name, max.m + 1)
      .run();
    const { results } = await env.DB.prepare(
      `SELECT id, name, position FROM tags ORDER BY position, id`
    ).all();
    return json(results || [], 201);
  }

  const tagMatch = path.match(/^\/tags\/(\d+)$/);
  if (tagMatch) {
    if (!isAdmin(me)) return fail('Riservato agli admin.', 403);
    const id = Number(tagMatch[1]);
    const riga = await env.DB.prepare(`SELECT * FROM tags WHERE id = ?`).bind(id).first();
    if (!riga) return fail('Tag non trovato.', 404);

    if (method === 'PATCH') {
      if (body.name !== undefined) {
        const name = clean(body.name, 60);
        if (!name) return fail('Il nome non può restare vuoto.', 400);
        const doppio = await env.DB.prepare(
          `SELECT id FROM tags WHERE lower(name) = lower(?) AND id <> ?`
        )
          .bind(name, id)
          .first();
        if (doppio) return fail('Esiste già un tag con questo nome.', 400);
        await env.DB.prepare(`UPDATE tags SET name = ? WHERE id = ?`).bind(name, id).run();
      }
      if (body.direzione === 'su' || body.direzione === 'giu') {
        const { results } = await env.DB.prepare(
          `SELECT id, position FROM tags ORDER BY position, id`
        ).all();
        const idx = results.findIndex((r) => r.id === id);
        const vicino = body.direzione === 'su' ? idx - 1 : idx + 1;
        if (idx !== -1 && vicino >= 0 && vicino < results.length) {
          const a = results[idx],
            b = results[vicino];
          await env.DB.prepare(`UPDATE tags SET position = ? WHERE id = ?`)
            .bind(b.position, a.id)
            .run();
          await env.DB.prepare(`UPDATE tags SET position = ? WHERE id = ?`)
            .bind(a.position, b.id)
            .run();
        }
      }
      const { results } = await env.DB.prepare(
        `SELECT id, name, position FROM tags ORDER BY position, id`
      ).all();
      return json(results || []);
    }

    if (method === 'DELETE') {
      await env.DB.prepare(`DELETE FROM tags WHERE id = ?`).bind(id).run();
      const { results } = await env.DB.prepare(
        `SELECT id, name, position FROM tags ORDER BY position, id`
      ).all();
      return json(results || []);
    }
  }

  /* ---- impostazioni: valori singoli (es. tag della segnalazione rapida) ---- */
  if (path === '/app-settings' && method === 'GET') {
    const { results } = await env.DB.prepare(`SELECT key, value FROM app_settings`).all();
    const obj = {};
    (results || []).forEach((r) => {
      obj[r.key] = r.value;
    });
    return json(obj);
  }

  const appSettingMatch = path.match(/^\/app-settings\/([a-z_]+)$/);
  if (appSettingMatch && method === 'PATCH') {
    if (!isAdmin(me)) return fail('Riservato agli admin.', 403);
    const key = appSettingMatch[1];
    const value = clean(body.value, 40) ?? '';
    await env.DB.prepare(
      `INSERT INTO app_settings (key, value) VALUES (?, ?)
       ON CONFLICT(key) DO UPDATE SET value = excluded.value`
    )
      .bind(key, value)
      .run();
    const { results } = await env.DB.prepare(`SELECT key, value FROM app_settings`).all();
    const obj = {};
    (results || []).forEach((r) => {
      obj[r.key] = r.value;
    });
    return json(obj);
  }

  /* ---- impostazioni: mappatura priority/severity per DevOps ---- */
  if (path === '/severity-settings' && method === 'GET') {
    const { results } = await env.DB.prepare(
      `SELECT severity, priority, csv_severity FROM severity_settings`
    ).all();
    const ordine = ['bloccante', 'alta', 'media', 'bassa'];
    const ordinati = (results || []).sort((a, b) => ordine.indexOf(a.severity) - ordine.indexOf(b.severity));
    return json(ordinati);
  }

  const sevSettingsMatch = path.match(/^\/severity-settings\/(bloccante|alta|media|bassa)$/);
  if (sevSettingsMatch && method === 'PATCH') {
    if (!isAdmin(me)) return fail('Riservato agli admin.', 403);
    const severity = sevSettingsMatch[1];
    const priority = Number(body.priority);
    const csvSeverity = clean(body.csv_severity, 60);
    if (!Number.isInteger(priority) || priority < 1 || priority > 4)
      return fail('La priority deve essere un numero tra 1 e 4.', 400);
    if (!csvSeverity) return fail('Scrivi il testo della severity per il CSV.', 400);
    await env.DB.prepare(
      `UPDATE severity_settings SET priority = ?, csv_severity = ? WHERE severity = ?`
    )
      .bind(priority, csvSeverity, severity)
      .run();
    const { results } = await env.DB.prepare(
      `SELECT severity, priority, csv_severity FROM severity_settings`
    ).all();
    const ordine = ['bloccante', 'alta', 'media', 'bassa'];
    return json((results || []).sort((a, b) => ordine.indexOf(a.severity) - ordine.indexOf(b.severity)));
  }

  /* ---- utenti (solo admin, tranne la lista ridotta) ---- */
  if (path === '/users' && method === 'GET') {
    if (isAdmin(me)) {
      const { results } = await env.DB.prepare(
        `SELECT id, username, full_name, email, role, active, must_change_password,
                (password_hash IS NULL) AS on_default_password, created_at
           FROM users ORDER BY full_name`
      ).all();
      return json(results || []);
    }
    const { results } = await env.DB.prepare(
      `SELECT id, full_name FROM users WHERE active = 1 ORDER BY full_name`
    ).all();
    return json(results || []);
  }

  if (path === '/users' && method === 'POST') {
    if (!isAdmin(me)) return fail('Riservato agli admin.', 403);
    const username = clean(body.username, 60)?.toLowerCase();
    const fullName = clean(body.full_name, 120);
    const role = body.role === 'admin' ? 'admin' : 'user';
    if (!username || !/^[a-z0-9._-]{3,}$/.test(username))
      return fail('Username non valido: usa lettere, numeri, punto, trattino.', 400);
    if (!fullName) return fail('Inserisci nome e cognome.', 400);
    const exists = await env.DB.prepare(`SELECT id FROM users WHERE lower(username) = ?`)
      .bind(username)
      .first();
    if (exists) return fail('Username già in uso.', 400);

    await env.DB.prepare(
      `INSERT INTO users (username, full_name, email, role) VALUES (?, ?, ?, ?)`
    )
      .bind(username, fullName, clean(body.email, 160), role)
      .run();
    return json({ ok: true }, 201);
  }

  const userMatch = path.match(/^\/users\/(\d+)$/);
  if (userMatch && method === 'PATCH') {
    if (!isAdmin(me)) return fail('Riservato agli admin.', 403);
    const id = Number(userMatch[1]);
    const fields = [];
    const values = [];
    if (body.username !== undefined) {
      const username = clean(body.username, 60)?.toLowerCase();
      if (!username || !/^[a-z0-9._-]{3,}$/.test(username))
        return fail('Username non valido: usa lettere, numeri, punto, trattino.', 400);
      const taken = await env.DB.prepare(
        `SELECT id FROM users WHERE lower(username) = ? AND id <> ?`
      )
        .bind(username, id)
        .first();
      if (taken) return fail('Username già in uso.', 400);
      fields.push('username = ?');
      values.push(username);
    }
    if (body.full_name !== undefined) {
      const fullName = clean(body.full_name, 120);
      if (!fullName) return fail('Il nome non può restare vuoto.', 400);
      fields.push('full_name = ?');
      values.push(fullName);
    }
    if (body.email !== undefined) {
      fields.push('email = ?');
      values.push(clean(body.email, 160));
    }
    if (body.role === 'admin' || body.role === 'user') {
      if (id === me.id && body.role !== 'admin')
        return fail('Non puoi togliere a te stesso i permessi di admin.', 400);
      fields.push('role = ?');
      values.push(body.role);
    }
    if (body.active !== undefined) {
      if (id === me.id && !body.active) return fail('Non puoi disattivare il tuo utente.', 400);
      fields.push('active = ?');
      values.push(body.active ? 1 : 0);
    }
    if (!fields.length) return fail('Niente da aggiornare.', 400);
    await env.DB.prepare(`UPDATE users SET ${fields.join(', ')} WHERE id = ?`)
      .bind(...values, id)
      .run();
    return json({ ok: true });
  }

  const resetMatch = path.match(/^\/users\/(\d+)\/reset-password$/);
  if (resetMatch && method === 'POST') {
    if (!isAdmin(me)) return fail('Riservato agli admin.', 403);
    const id = Number(resetMatch[1]);
    await env.DB.prepare(
      `UPDATE users SET password_hash = NULL, password_salt = NULL, must_change_password = 1 WHERE id = ?`
    )
      .bind(id)
      .run();
    await env.DB.prepare(`DELETE FROM sessions WHERE user_id = ?`).bind(id).run();
    return json({ ok: true });
  }

  return fail('Endpoint non trovato.', 404);
}

/* ---------------------------------------------------------- entry */

const PAGINA = `<!DOCTYPE html>
<html lang="it">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<title>Sebach Plus · Bug &amp; CR</title>
<link rel="icon" href="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 32 32'%3E%3Cpath fill='%23D4112D' d='M16 28C6 21 2 16 2 11a7 7 0 0 1 14-2 7 7 0 0 1 14 2c0 5-4 10-14 17z'/%3E%3C/svg%3E">
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Barlow+Semi+Condensed:wght@500;600;700&family=Inter:wght@400;500;600&display=swap" rel="stylesheet">
<style>
:root{
  --rosso:#D4112D; --rosso-scuro:#A80D23; --rosso-vivo:#F0243F;
  --nero:#121216;
  --inchiostro:#16161B; --grigio:#6A6F78; --bordo:#E1E3E8;
  --carta:#F4F5F7; --bianco:#fff;
  --nuovo:#4A5568; --aperto:#B4650F; --approvato:#17915A; --respinto:#A80D23;
  --raggio:10px;
  --display:"Barlow Semi Condensed",-apple-system,"Segoe UI",sans-serif;
  --testo:"Inter",-apple-system,"Segoe UI",Roboto,sans-serif;
  --mono:ui-monospace,SFMono-Regular,"Cascadia Mono",Consolas,monospace;
}
*{box-sizing:border-box}
html,body{margin:0;height:100%}
body{font-family:var(--testo);color:var(--inchiostro);background:var(--carta);font-size:14px;line-height:1.5}
h1,h2,h3,.disp{font-family:var(--display);letter-spacing:.01em;margin:0}
button{font-family:inherit;font-size:14px;cursor:pointer}
input,select,textarea{font-family:inherit;font-size:14px;color:inherit}
a{color:var(--rosso)}
.hidden{display:none !important}
:focus-visible{outline:2px solid var(--rosso-vivo);outline-offset:2px}

/* ---------- controlli ---------- */
.btn{border:1px solid var(--bordo);background:var(--bianco);color:var(--inchiostro);
  padding:8px 14px;border-radius:var(--raggio);font-weight:500;transition:.15s}
.btn:hover{border-color:var(--rosso);color:var(--rosso)}
.btn.primario{background:var(--rosso);border-color:var(--rosso);color:#fff}
.btn.primario:hover{background:var(--nero);border-color:var(--nero);color:#fff}
.btn.pieno{width:100%;justify-content:center;padding:11px}
.btn.pericolo{color:var(--respinto);border-color:#EFC3C9}
.btn.pericolo:hover{background:var(--respinto);color:#fff;border-color:var(--respinto)}
.btn:disabled{opacity:.45;cursor:not-allowed}
.btn.mini{padding:5px 10px;font-size:12.5px}
.campo{display:block;margin-bottom:14px}
.campo>span{display:block;font-weight:600;margin-bottom:5px;font-size:13px}
.campo .aiuto{display:block;font-weight:400;color:var(--grigio);font-size:12.5px;margin-bottom:6px}
input[type=text],input[type=password],input[type=email],select,textarea{
  width:100%;padding:9px 11px;border:1px solid var(--bordo);border-radius:8px;background:#fff}
input:focus,select:focus,textarea:focus{border-color:var(--rosso);outline:none;box-shadow:0 0 0 3px rgba(212,17,45,.14)}
textarea{resize:vertical;min-height:96px}
.errore{color:var(--respinto);font-size:13px;margin-top:8px;min-height:18px}

/* ---------- login ---------- */
#login-view{display:grid;grid-template-columns:1.1fr 1fr;height:100vh}
.login-lato{position:relative;overflow:hidden;background:var(--nero);color:#fff;padding:56px;
  display:flex;flex-direction:column;justify-content:space-between}
.login-lato>*{position:relative;z-index:2}
.login-lato h1{font-size:clamp(38px,5vw,64px);line-height:.98;font-weight:700;text-transform:uppercase;max-width:11ch}
.login-lato h1 em{font-style:normal;color:var(--rosso-vivo)}
.login-form{display:flex;align-items:center;justify-content:center;padding:32px}
.login-form .box{width:min(360px,100%)}

/* sfondo animato: griglia in deriva, aloni rossi, scia diagonale */
.sfondo{position:absolute;inset:0;z-index:1;overflow:hidden}
.sfondo .griglia{position:absolute;inset:-50%;
  background-image:linear-gradient(rgba(255,255,255,.055) 1px,transparent 1px),
                   linear-gradient(90deg,rgba(255,255,255,.055) 1px,transparent 1px);
  background-size:46px 46px;
  mask-image:radial-gradient(ellipse at 30% 40%,#000 25%,transparent 72%);
  -webkit-mask-image:radial-gradient(ellipse at 30% 40%,#000 25%,transparent 72%);
  animation:deriva 26s linear infinite}
@keyframes deriva{to{transform:translate3d(46px,46px,0)}}

.sfondo .alone{position:absolute;border-radius:50%;filter:blur(70px);will-change:transform,opacity}
.sfondo .a1{width:46vw;height:46vw;left:-8vw;top:-10vw;background:rgba(212,17,45,.55);
  animation:vaga1 19s ease-in-out infinite}
.sfondo .a2{width:34vw;height:34vw;right:-6vw;bottom:-8vw;background:rgba(240,36,63,.34);
  animation:vaga2 23s ease-in-out infinite}
@keyframes vaga1{
  0%,100%{transform:translate3d(0,0,0) scale(1);opacity:.85}
  50%{transform:translate3d(9vw,7vh,0) scale(1.16);opacity:.6}}
@keyframes vaga2{
  0%,100%{transform:translate3d(0,0,0) scale(1.08);opacity:.55}
  50%{transform:translate3d(-7vw,-6vh,0) scale(.9);opacity:.85}}

.sfondo .scia{position:absolute;top:-60%;left:-30%;width:55%;height:220%;
  background:linear-gradient(100deg,transparent,rgba(255,255,255,.07) 45%,transparent);
  transform:rotate(14deg);animation:passa 9s ease-in-out infinite}
@keyframes passa{
  0%{transform:translateX(-40%) rotate(14deg);opacity:0}
  18%{opacity:1}
  60%,100%{transform:translateX(230%) rotate(14deg);opacity:0}}

/* impulso che corre lungo il bordo destro del pannello */
.sfondo .filo{position:absolute;top:0;right:0;width:2px;height:100%;
  background:linear-gradient(180deg,transparent,var(--rosso-vivo),transparent);
  background-size:100% 34%;background-repeat:no-repeat;animation:scorri 6.5s linear infinite}
@keyframes scorri{0%{background-position:0 -40%}100%{background-position:0 140%}}

.logo{display:block;height:44px;width:auto;max-width:100%;flex:0 0 auto;align-self:flex-start;object-fit:contain}
.logo.piccolo{height:26px;align-self:center}
@media(max-width:820px){
  #login-view{grid-template-columns:1fr}
  .login-lato{padding:32px;min-height:250px}
  .logo{height:34px}
}
@media(prefers-reduced-motion:reduce){
  .sfondo .griglia,.sfondo .alone,.sfondo .scia,.sfondo .filo{animation:none}
}

/* ---------- header ---------- */
header.app{background:var(--nero);color:#fff;padding:0 20px;display:flex;align-items:center;gap:22px;height:56px;position:sticky;top:0;z-index:30}
nav.tabs{display:flex;gap:2px;margin-left:auto}
nav.tabs button{background:transparent;border:0;color:#9C9CA8;padding:8px 14px;border-radius:8px;font-weight:600}
nav.tabs button.on,nav.tabs button:hover{background:rgba(255,255,255,.12);color:#fff}
.chip-utente{display:flex;align-items:center;gap:9px;padding-left:18px;border-left:1px solid rgba(255,255,255,.2);color:#fff}
.avatar{width:30px;height:30px;border-radius:50%;background:var(--rosso);color:#fff;display:grid;place-items:center;
  font-family:var(--display);font-weight:700;font-size:14px}
.ruolo{font-size:11px;text-transform:uppercase;letter-spacing:.06em;color:#9C9CA8}

@media(max-width:700px){
  header.app{gap:12px;padding:0 12px}
  header.app>span.disp{display:none}
  .chip-utente{padding-left:10px}
  .chip-utente>div:nth-child(2){display:none}
  main{padding:14px}
  .barra input[type=text]{width:100%}
  .spinta{margin-left:0;width:100%}
}

/* ---------- layout ---------- */
main{padding:22px;max-width:1760px;margin:0 auto}
.titolo-pagina{display:flex;align-items:baseline;gap:14px;margin-bottom:16px;flex-wrap:wrap}
.titolo-pagina h2{font-size:30px;font-weight:700;text-transform:uppercase}
.titolo-pagina .conteggio{color:var(--grigio);font-size:13px}
.barra{display:flex;gap:8px;flex-wrap:wrap;align-items:center;margin-bottom:14px}
.barra input[type=text]{width:230px}
.barra select{width:auto;min-width:130px}
.spinta{margin-left:auto;display:flex;gap:8px;flex-wrap:wrap}
.check-inline{display:inline-flex;align-items:center;gap:7px;background:#fff;border:1px solid var(--bordo);
  padding:8px 12px;border-radius:var(--raggio);white-space:nowrap}

/* ---------- tabella ---------- */
.tabella-box{background:#fff;border:1px solid var(--bordo);border-radius:12px;overflow:auto}
table{width:100%;border-collapse:collapse;min-width:920px}
th{font-family:var(--display);font-size:13px;text-transform:uppercase;letter-spacing:.05em;color:var(--grigio);
  text-align:left;padding:11px 12px;border-bottom:1px solid var(--bordo);background:#F8FAFC;white-space:nowrap;cursor:pointer;user-select:none;position:sticky;top:0}
th:hover{color:var(--rosso)}
th .freccia{opacity:.35;font-size:10px}
th.attiva .freccia{opacity:1;color:var(--rosso)}
td{padding:11px 12px;border-bottom:1px solid #EEF2F6;vertical-align:middle}
tbody tr{cursor:pointer}
tbody tr:hover{background:#FFF7F8}
.codice{font-family:var(--mono);font-size:12.5px;font-weight:600;color:var(--rosso);white-space:nowrap}
.tit-cella{font-weight:500;max-width:420px}
.vuoto{padding:52px;text-align:center;color:var(--grigio)}

/* ---------- badge ---------- */
.badge{display:inline-flex;align-items:center;gap:6px;font-family:var(--display);font-weight:600;font-size:12.5px;
  text-transform:uppercase;letter-spacing:.04em;padding:3px 9px;border-radius:999px;border:1px solid;white-space:nowrap}
.b-nuovo{color:#39414D;border-color:#D8DDE4;background:#F1F3F6}
.b-preso_in_carico{color:#1F4E8C;border-color:#C9D9F2;background:#EEF4FC}
.b-aperto{color:#8A5310;border-color:#F2DDB6;background:#FDF5E7}
.b-approvato{color:#0B5A72;border-color:#B6DCE8;background:#EAF6FA}
.b-risolto{color:#0E6B41;border-color:#B9E5CE;background:#EAF9F1}
.b-respinto{color:#7E0A1A;border-color:#EFC3C9;background:#FCEAED}
.b-sospesa{color:#5B4B8A;border-color:#DCD3F0;background:#F1EDFA}
.tipo{font-family:var(--display);font-weight:700;font-size:12px;letter-spacing:.06em;padding:2px 8px;border-radius:5px}
.t-BUG{background:#FBE0E4;color:var(--rosso-scuro)}
.t-CR{background:#EDEFF3;color:#39414D}
.grav{font-size:12.5px;font-weight:500}
.g-bloccante{color:var(--rosso-scuro);font-weight:600}
.g-alta{color:#B4650F}
.g-media{color:var(--grigio)}
.g-bassa{color:#94A3B1}

/* ---------- drawer ---------- */
.velo{position:fixed;inset:0;background:rgba(9,25,42,.45);z-index:40;display:flex;justify-content:flex-end}
.drawer{width:min(560px,100%);background:#fff;height:100%;display:flex;flex-direction:column;box-shadow:-8px 0 30px rgba(0,0,0,.18)}
.drawer header{padding:16px 20px;border-bottom:1px solid var(--bordo);display:flex;gap:12px;align-items:flex-start}
.drawer header h3{font-size:19px;font-weight:600;line-height:1.25}
.drawer .corpo{padding:20px;overflow:auto;flex:1}
.chiudi{margin-left:auto;background:none;border:0;font-size:24px;line-height:1;color:var(--grigio);padding:0 4px}
.chiudi:hover{color:var(--inchiostro)}

/* rail di stato = elemento firma */
.rail{display:flex;align-items:center;margin:4px 0 22px}
.rail .tappa{flex:1;text-align:center;position:relative;font-family:var(--display);font-size:12px;white-space:nowrap;
  text-transform:uppercase;letter-spacing:.05em;color:#A8B4C0}
.rail .tappa::before{content:"";display:block;width:11px;height:11px;border-radius:50%;background:#DDE5EE;margin:0 auto 7px;position:relative;z-index:2}
.rail .tappa::after{content:"";position:absolute;top:5px;left:-50%;width:100%;height:2px;background:#DDE5EE;z-index:1}
.rail .tappa:first-child::after{display:none}
.rail .tappa.fatta{color:var(--rosso)}
.rail .tappa.fatta::before{background:var(--rosso)}
.rail .tappa.fatta::after{background:var(--rosso)}
.rail .tappa.ko{color:var(--respinto)}
.rail .tappa.ko::before{background:var(--respinto)}
.rail .tappa.ko::after{background:var(--respinto)}
.rail .tappa.pausa{color:#5B4B8A}
.rail .tappa.pausa::before{background:#5B4B8A}
.rail .tappa.pausa::after{background:#5B4B8A}

.dett{border-top:1px solid #EEF2F6;padding:11px 0;display:grid;grid-template-columns:150px 1fr;gap:12px}
.dett dt{font-family:var(--display);font-size:12.5px;text-transform:uppercase;letter-spacing:.05em;color:var(--grigio)}
.dett dd{margin:0;white-space:pre-wrap;word-break:break-word}
.riquadro{background:#F8FAFC;border:1px solid var(--bordo);border-radius:10px;padding:14px;margin:16px 0}
.riquadro.ko{background:#FCEAED;border-color:#EFC3C9}
.riquadro h4{font-family:var(--display);text-transform:uppercase;font-size:13px;letter-spacing:.05em;margin:0 0 6px;color:var(--grigio)}
.riquadro.ko h4{color:#7E0A1A}

/* chat note */
.chat{display:flex;flex-direction:column;gap:10px;margin:10px 0 14px}
.msg{max-width:82%;padding:9px 12px;border-radius:12px;background:#F1F5F9;border:1px solid var(--bordo)}
.msg .meta{font-size:11.5px;color:var(--grigio);margin-bottom:3px}
.msg .testo{white-space:pre-wrap;word-break:break-word}
.msg.mio{align-self:flex-end;background:#FDECEF;border-color:#F6C9D1}
.msg.sistema{align-self:center;max-width:100%;background:transparent;border:0;text-align:center;
  color:var(--grigio);font-size:12.5px;font-style:italic}
.invio{display:flex;gap:8px;align-items:flex-end}
.invio textarea{min-height:44px;height:44px}

/* ---------- wizard ---------- */
.modale{position:fixed;inset:0;background:rgba(9,25,42,.5);z-index:50;display:grid;place-items:center;padding:16px}
.wiz{background:#fff;border-radius:14px;width:min(940px,100%);max-height:92vh;display:grid;grid-template-columns:1fr 300px;overflow:hidden}
.wiz-main{padding:26px 30px;display:flex;flex-direction:column;min-height:520px}
.wiz-anteprima{background:#F8FAFC;border-left:1px solid var(--bordo);padding:22px;overflow:auto;font-size:13px}
.wiz-anteprima h4{font-family:var(--display);text-transform:uppercase;font-size:12.5px;letter-spacing:.06em;color:var(--grigio);margin:0 0 10px}
.wiz-anteprima .riga{margin-bottom:11px}
.wiz-anteprima .et{font-size:11.5px;color:var(--grigio);text-transform:uppercase;letter-spacing:.04em}
.wiz-anteprima .vl{word-break:break-word}
.wiz-anteprima .vl.manca{color:#B4BFCA;font-style:italic}
.passi{display:flex;gap:4px;margin-bottom:22px}
.passi i{height:4px;flex:1;background:#E3E9F0;border-radius:2px}
.passi i.on{background:var(--rosso)}
.domanda{font-family:var(--display);font-size:27px;font-weight:600;line-height:1.15;margin-bottom:6px}
.sotto{color:var(--grigio);margin-bottom:18px}
.contenuto{flex:1}
.wiz-piede{display:flex;gap:10px;align-items:center;padding-top:18px;border-top:1px solid var(--bordo);margin-top:18px}
.wiz-piede .conta{color:var(--grigio);font-size:12.5px}
.wiz-piede .dx{margin-left:auto;display:flex;gap:8px}
.scelte{display:flex;flex-direction:column;gap:9px}
.scelta{display:flex;gap:11px;align-items:flex-start;padding:13px 15px;border:1px solid var(--bordo);border-radius:10px;cursor:pointer;background:#fff}
.scelta:hover{border-color:var(--rosso);background:#FFF8F9}
.scelta.sel{border-color:var(--rosso);background:#FDECEF;box-shadow:0 0 0 1px var(--rosso) inset}
.scelta input{margin-top:3px}
.scelta b{display:block;font-weight:600}
.scelta small{color:var(--grigio)}
.nota-cr{margin-top:14px;background:#FDECEF;border:1px solid #F6C9D1;border-radius:10px;padding:12px;font-size:13px}
@media(max-width:860px){.wiz{grid-template-columns:1fr}.wiz-anteprima{display:none}.wiz-main{padding:20px;min-height:0}.domanda{font-size:22px}}

/* ---------- utenti ---------- */
.griglia-utenti{display:grid;grid-template-columns:1fr 330px;gap:20px;align-items:start}
@media(max-width:960px){.griglia-utenti{grid-template-columns:1fr}}
.scheda{background:#fff;border:1px solid var(--bordo);border-radius:12px;padding:20px}
.scheda h3{font-size:17px;font-weight:600;margin-bottom:14px}
.pill{font-size:11.5px;padding:2px 8px;border-radius:999px;border:1px solid var(--bordo);color:var(--grigio)}
.pill.warn{background:#FDF5E7;border-color:#F2DDB6;color:#8A5310}

/* ---------- toast ---------- */
#toast{position:fixed;bottom:22px;left:50%;transform:translateX(-50%) translateY(160px);opacity:0;pointer-events:none;
  background:var(--inchiostro);color:#fff;padding:12px 20px;border-radius:10px;z-index:90;transition:.25s;max-width:90vw}
#toast.on{transform:translateX(-50%) translateY(0);opacity:1;pointer-events:auto}
#toast.ko{background:var(--respinto)}
@media(prefers-reduced-motion:reduce){*{transition:none !important;animation:none !important}}
</style>
</head>
<body>

<!-- =============== LOGIN =============== -->
<section id="login-view" class="hidden">
  <div class="login-lato">
    <div class="sfondo" aria-hidden="true">
      <span class="griglia"></span>
      <span class="alone a1"></span>
      <span class="alone a2"></span>
      <span class="scia"></span>
      <span class="filo"></span>
    </div>
    <img class="logo" src="data:image/png;base64,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" alt="Sebach">
    <div>
      <h1>Bug &amp;<br><em>Change</em><br>Request</h1>
    </div>
    <div style="color:#71717E;font-size:12.5px">Uso interno · Sebach S.p.A.</div>
  </div>
  <div class="login-form">
    <div class="box">
      <h2 class="disp" style="font-size:26px;text-transform:uppercase">Accedi</h2>
      <p style="color:var(--grigio);margin:6px 0 22px">Usa l'utenza che ti ha assegnato l'amministratore.</p>
      <label class="campo"><span>Utente</span>
        <input type="text" id="lg-user" autocomplete="username" placeholder="nome.cognome"></label>
      <label class="campo"><span>Password</span>
        <input type="password" id="lg-pass" autocomplete="current-password"></label>
      <div class="errore" id="lg-err"></div>
      <button class="btn primario pieno" id="lg-btn">Entra</button>
    </div>
  </div>
</section>

<!-- =============== CAMBIO PASSWORD =============== -->
<section id="pwd-view" class="hidden" style="display:grid;place-items:center;height:100vh;padding:20px">
  <div style="width:min(400px,100%);background:#fff;border:1px solid var(--bordo);border-radius:14px;padding:28px">
    <h2 class="disp" style="font-size:24px;text-transform:uppercase">Cambia password</h2>
    <p style="color:var(--grigio);margin:6px 0 20px">Prima di continuare scegli una password personale. Minimo 8 caratteri, almeno una lettera e un numero.</p>
    <label class="campo"><span>Password attuale</span><input type="password" id="pw-old" autocomplete="current-password"></label>
    <label class="campo"><span>Nuova password</span><input type="password" id="pw-new" autocomplete="new-password"></label>
    <label class="campo"><span>Ripeti la nuova password</span><input type="password" id="pw-new2" autocomplete="new-password"></label>
    <div class="errore" id="pw-err"></div>
    <button class="btn primario pieno" id="pw-btn">Salva e continua</button>
    <button class="btn pieno" style="margin-top:8px" id="pw-esci">Esci</button>
  </div>
</section>

<!-- =============== APP =============== -->
<div id="app-view" class="hidden">
  <header class="app">
    <img class="logo piccolo" src="data:image/png;base64,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" alt="Sebach">
    <span class="disp" style="font-size:13px;text-transform:uppercase;letter-spacing:.09em;color:#9C9CA8">Plus · Bug &amp; CR</span>
    <nav class="tabs">
      <button data-tab="tickets" class="on">Segnalazioni</button>
      <button data-tab="report">Report</button>
      <button data-tab="users" id="tab-utenti" class="hidden">Utenti</button>
      <button data-tab="settings" id="tab-impostazioni" class="hidden">Impostazioni</button>
    </nav>
    <div class="chip-utente">
      <div class="avatar" id="me-avatar">–</div>
      <div style="line-height:1.2">
        <div id="me-nome" style="font-weight:600"></div>
        <div class="ruolo" id="me-ruolo"></div>
      </div>
      <button class="btn mini" id="btn-esci" style="margin-left:6px;background:transparent;color:#9C9CA8;border-color:rgba(255,255,255,.25)">Esci</button>
    </div>
  </header>

  <main>
    <!-- ---- lista ticket ---- -->
    <section id="view-tickets">
      <div class="titolo-pagina">
        <h2>Segnalazioni</h2>
        <span class="conteggio" id="conteggio"></span>
      </div>

      <div class="barra">
        <input type="text" id="f-testo" placeholder="Cerca in titolo, codice, testo…">
        <select id="f-tipo"><option value="">Tipo: tutti</option><option value="BUG">Solo bug</option><option value="CR">Solo CR</option></select>
        <select id="f-stato"><option value="">Stato: tutti</option><option value="nuovo">Nuovo</option><option value="preso_in_carico">Preso in carico</option><option value="aperto">Aperto</option><option value="approvato">Approvato</option><option value="sospesa">Sospesa</option><option value="risolto">Risolto</option><option value="respinto">Respinto</option></select>
        <select id="f-grav"><option value="">Gravità: tutte</option><option value="bloccante">Bloccante</option><option value="alta">Alta</option><option value="media">Media</option><option value="bassa">Bassa</option></select>
        <select id="f-autore"><option value="">Autore: tutti</option></select>
        <select id="f-tag"><option value="">Tag: tutti</option></select>
        <label class="check-inline"><input type="checkbox" id="f-miei"> Solo le mie</label>
        <div class="spinta">
          <button class="btn" id="btn-csv">CSV</button>
          <button class="btn" id="btn-xlsx">XLSX</button>
          <button class="btn hidden" id="btn-devops">CSV per DevOps</button>
          <button class="btn hidden" id="btn-importa-devops">Importa ID DevOps</button>
          <button class="btn hidden" id="btn-risolvi-devops">Segna risolti (DevOps)</button>
          <input type="file" id="imp-devops-file" accept=".csv,text/csv" style="display:none">
          <button class="btn primario" id="btn-nuovo">+ Nuova segnalazione</button>
        </div>
      </div>

      <div class="tabella-box">
        <table>
          <thead><tr>
            <th data-sort="code">Codice <span class="freccia">▼</span></th>
            <th data-sort="type">Tipo <span class="freccia">▼</span></th>
            <th data-sort="title">Titolo <span class="freccia">▼</span></th>
            <th data-sort="area">Area <span class="freccia">▼</span></th>
            <th data-sort="tag">Tag <span class="freccia">▼</span></th>
            <th data-sort="status">Stato <span class="freccia">▼</span></th>
            <th data-sort="severity">Gravità <span class="freccia">▼</span></th>
            <th data-sort="author_name">Aperto da <span class="freccia">▼</span></th>
            <th data-sort="created_at">Data <span class="freccia">▼</span></th>
            <th data-sort="devops_id">DevOps <span class="freccia">▼</span></th>
          </tr></thead>
          <tbody id="righe"></tbody>
        </table>
        <div class="vuoto hidden" id="lista-vuota">Nessuna segnalazione con questi filtri.</div>
      </div>
    </section>

    <!-- ---- report ---- -->
    <section id="view-report" class="hidden">
      <div class="titolo-pagina">
        <h2>Report</h2>
        <select id="r-periodo" style="width:auto">
          <option value="90">Ultimi 3 mesi</option>
          <option value="180">Ultimi 6 mesi</option>
          <option value="365" selected>Ultimi 12 mesi</option>
          <option value="0">Tutto lo storico</option>
        </select>
      </div>
      <div id="report-corpo"></div>
    </section>

    <!-- ---- utenti ---- -->
    <section id="view-users" class="hidden">
      <div class="titolo-pagina"><h2>Utenti e permessi</h2></div>
      <div class="griglia-utenti">
        <div class="scheda" style="padding:0;overflow:auto">
          <table style="min-width:640px">
            <thead><tr><th style="cursor:default">Nome</th><th style="cursor:default">Utente</th><th style="cursor:default">Ruolo</th><th style="cursor:default">Stato</th><th style="cursor:default">Azioni</th></tr></thead>
            <tbody id="righe-utenti"></tbody>
          </table>
        </div>
        <div class="scheda">
          <h3>Nuovo utente</h3>
          <label class="campo"><span>Nome e cognome</span><input type="text" id="nu-nome" placeholder="Mario Rossi"></label>
          <label class="campo"><span>Utente</span><span class="aiuto">Formato: nome.cognome, tutto minuscolo</span><input type="text" id="nu-user" placeholder="mario.rossi"></label>
          <label class="campo"><span>Email (facoltativa)</span><input type="email" id="nu-mail"></label>
          <label class="campo"><span>Ruolo</span><select id="nu-ruolo"><option value="user">Utente</option><option value="admin">Admin</option></select></label>
          <div class="errore" id="nu-err"></div>
          <button class="btn primario pieno" id="nu-btn">Crea utente</button>
          <p style="color:var(--grigio);font-size:12.5px;margin-top:12px">Il nuovo utente entra con la password di default e la deve cambiare al primo accesso.</p>
        </div>
      </div>
    </section>

    <!-- ---- impostazioni ---- -->
    <section id="view-settings" class="hidden">
      <div class="titolo-pagina"><h2>Impostazioni</h2></div>

      <!-- elenco delle impostazioni disponibili -->
      <div id="impostazioni-hub">
        <div class="scheda" style="max-width:560px;margin-bottom:14px">
          <div style="display:flex;align-items:center;gap:16px">
            <div style="flex:1">
              <h3 style="margin-bottom:4px">Menu del wizard</h3>
              <p style="color:var(--grigio);font-size:13px;margin:0">
                Le voci tra cui un utente sceglie quando apre una segnalazione e indica in che menu si trova.
              </p>
            </div>
            <button class="btn" id="imp-apri-aree">Gestisci</button>
          </div>
        </div>
        <div class="scheda" style="max-width:560px">
          <div style="display:flex;align-items:center;gap:16px">
            <div style="flex:1">
              <h3 style="margin-bottom:4px">Priority e severity per DevOps</h3>
              <p style="color:var(--grigio);font-size:13px;margin:0">
                A quale priority e severity di Azure DevOps corrisponde ogni gravità, nel CSV di export.
              </p>
            </div>
            <button class="btn" id="imp-apri-devops">Gestisci</button>
          </div>
        </div>
        <div class="scheda" style="max-width:560px;margin-top:14px">
          <div style="display:flex;align-items:center;gap:16px">
            <div style="flex:1">
              <h3 style="margin-bottom:4px">Tag</h3>
              <p style="color:var(--grigio);font-size:13px;margin:0">
                L'elenco dei tag che si possono assegnare a una segnalazione, per poi filtrarle.
              </p>
            </div>
            <button class="btn" id="imp-apri-tags">Gestisci</button>
          </div>
        </div>
      </div>

      <!-- tag: sotto-pagina -->
      <div id="impostazioni-tags" class="hidden">
        <button class="btn mini" id="imp-torna-tags" style="margin-bottom:16px">← Impostazioni</button>
        <div class="griglia-utenti">
          <div class="scheda">
            <h3>Tag</h3>
            <p style="color:var(--grigio);font-size:13px;margin:-6px 0 16px">
              I tag che si possono assegnare a una segnalazione — dalla «Segnalazione rapida» o dal
              pannello amministratore di qualunque ticket — per poi filtrarle in elenco.
            </p>
            <div id="righe-tags"></div>
            <div style="display:flex;gap:8px;margin-top:14px">
              <input type="text" id="tg-nome" placeholder="Nome del nuovo tag" style="flex:1">
              <button class="btn primario" id="tg-btn">Aggiungi</button>
            </div>
            <div class="errore" id="tg-err"></div>
          </div>
          <div class="scheda">
            <p style="color:var(--grigio);font-size:13px;margin:0">
              Rinominare o togliere un tag non tocca le segnalazioni che lo hanno già: restano con il
              testo di allora. Cambia solo l'elenco tra cui scegliere da qui in avanti.
            </p>
          </div>
        </div>
      </div>

      <!-- priority/severity: sotto-pagina -->
      <div id="impostazioni-devops" class="hidden">
        <button class="btn mini" id="imp-torna-devops" style="margin-bottom:16px">← Impostazioni</button>
        <div class="griglia-utenti">
          <div class="scheda">
            <h3>Priority e severity per DevOps</h3>
            <p style="color:var(--grigio);font-size:13px;margin:-6px 0 16px">
              Quando esporti il CSV per DevOps, ogni segnalazione riceve la priority e la severity qui
              indicate in base alla sua gravità. Il testo della severity va scritto come lo vuole Azure
              DevOps, per esempio «2 - High».
            </p>
            <div id="righe-devops"></div>
            <div class="errore" id="dv-err"></div>
          </div>
          <div class="scheda">
            <p style="color:var(--grigio);font-size:13px;margin:0">
              Per un singolo bug puoi forzare priority e severity indipendentemente da questa
              mappatura: la trovi nel dettaglio della segnalazione, tra le azioni amministratore.
              Quando è attiva, l'export usa quei valori e ignora questa tabella.
            </p>
          </div>
        </div>
      </div>

      <!-- menu del wizard: sotto-pagina -->
      <div id="impostazioni-aree" class="hidden">
        <button class="btn mini" id="imp-torna" style="margin-bottom:16px">← Impostazioni</button>
        <div class="griglia-utenti">
          <div class="scheda">
            <h3>Menu del wizard</h3>
            <p style="color:var(--grigio);font-size:13px;margin:-6px 0 16px">
              Le voci che compaiono quando un utente apre una segnalazione e sceglie in che menu si trova.
              «Altro» è sempre in fondo e non si può togliere: è il modo per digitare un menu non in elenco.
            </p>
            <div id="righe-aree"></div>
            <div style="display:flex;gap:8px;margin-top:14px">
              <input type="text" id="ar-nome" placeholder="Nome della nuova voce" style="flex:1">
              <button class="btn primario" id="ar-btn">Aggiungi</button>
            </div>
            <div class="errore" id="ar-err"></div>
          </div>
          <div class="scheda">
            <p style="color:var(--grigio);font-size:13px;margin:0">
              Rinominare o togliere una voce non tocca le segnalazioni già aperte: restano con il testo
              di allora. Cambia solo l'elenco che vedranno da qui in avanti.
            </p>
          </div>
        </div>
      </div>
    </section>

  </main>
</div>

<div id="drawer-host"></div>
<div id="wizard-host"></div>
<div id="toast"></div>

<script>
/* ============================================================
   Stato e utilità
   ============================================================ */
const S = { me:null, tickets:[], users:[], aree:[], tags:[], severitySettings:[], appSettings:{}, sort:{key:'code',dir:'desc'}, apertoId:null };

const $ = (s,r=document)=>r.querySelector(s);
const $$ = (s,r=document)=>[...r.querySelectorAll(s)];
const esc = (s)=>String(s??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));

function toast(msg, ko=false){
  const t=$('#toast'); t.textContent=msg; t.className = ko?'on ko':'on';
  clearTimeout(t._h); t._h=setTimeout(()=>t.className='',3200);
}

async function api(path, opts={}){
  const r = await fetch('/api'+path, {
    headers:{'content-type':'application/json'},
    ...opts,
    body: opts.body ? JSON.stringify(opts.body) : undefined
  });
  const data = await r.json().catch(()=>({}));
  if(!r.ok){
    if(r.status===401 && S.me){ S.me=null; mostraLogin(); }
    throw new Error(data.error || 'Errore imprevisto.');
  }
  return data;
}

const dataIt = (s)=>{
  if(!s) return '';
  const d = new Date(s.replace(' ','T')+'Z');
  return d.toLocaleDateString('it-IT',{day:'2-digit',month:'2-digit',year:'numeric'});
};
const dataOraIt = (s)=>{
  if(!s) return '';
  const d = new Date(s.replace(' ','T')+'Z');
  return d.toLocaleString('it-IT',{day:'2-digit',month:'2-digit',year:'numeric',hour:'2-digit',minute:'2-digit'});
};
const iniziali = (n)=>String(n||'').split(' ').filter(Boolean).slice(0,2).map(p=>p[0]).join('').toUpperCase();

const ET_STATO = {nuovo:'Nuovo', preso_in_carico:'Preso in carico', aperto:'Aperto', approvato:'Approvato', risolto:'Risolto', respinto:'Respinto', sospesa:'Sospesa'};
const ET_GRAV  = {bloccante:'Bloccante', alta:'Alta', media:'Media', bassa:'Bassa'};
const ET_PRO   = {
  anche_su_pro:'Provato su Sebach Pro: stesso errore anche lì',
  solo_su_plus:'Provato su Sebach Pro: lì funziona correttamente',
  non_applicabile:'Non provabile: la funzione esiste solo su Sebach Plus'
};
// le voci fisse dei menu vengono caricate da /api/areas; "Altro" e' sempre l'ultima e non e' modificabile
const listaAree = ()=> [...S.aree.map(a=>a.name), 'Altro'];

/* ============================================================
   Login / sessione
   ============================================================ */
function mostraLogin(){ $('#login-view').classList.remove('hidden'); $('#app-view').classList.add('hidden'); $('#pwd-view').classList.add('hidden'); }
function mostraCambioPwd(){ $('#pwd-view').classList.remove('hidden'); $('#login-view').classList.add('hidden'); $('#app-view').classList.add('hidden'); }
function mostraApp(){ $('#app-view').classList.remove('hidden'); $('#login-view').classList.add('hidden'); $('#pwd-view').classList.add('hidden'); }

$('#lg-btn').onclick = async ()=>{
  const u=$('#lg-user').value.trim(), p=$('#lg-pass').value;
  $('#lg-err').textContent='';
  if(!u||!p){ $('#lg-err').textContent='Inserisci utente e password.'; return; }
  $('#lg-btn').disabled=true;
  try{
    S.me = await api('/auth/login',{method:'POST',body:{username:u,password:p}});
    $('#lg-pass').value='';
    if(S.me.must_change_password) mostraCambioPwd(); else await avvia();
  }catch(e){ $('#lg-err').textContent=e.message; }
  finally{ $('#lg-btn').disabled=false; }
};
$$('#lg-user,#lg-pass').forEach(i=>i.addEventListener('keydown',e=>{ if(e.key==='Enter') $('#lg-btn').click(); }));

$('#pw-btn').onclick = async ()=>{
  const o=$('#pw-old').value, n=$('#pw-new').value, n2=$('#pw-new2').value;
  $('#pw-err').textContent='';
  if(n!==n2){ $('#pw-err').textContent='Le due nuove password non coincidono.'; return; }
  $('#pw-btn').disabled=true;
  try{
    await api('/auth/change-password',{method:'POST',body:{current:o,next:n}});
    $('#pw-old').value=$('#pw-new').value=$('#pw-new2').value='';
    toast('Password aggiornata.');
    S.me = await api('/auth/me');
    await avvia();
  }catch(e){ $('#pw-err').textContent=e.message; }
  finally{ $('#pw-btn').disabled=false; }
};
$('#pw-esci').onclick = esci;
$('#btn-esci').onclick = esci;
async function esci(){ try{ await api('/auth/logout',{method:'POST'}); }catch(e){} S.me=null; mostraLogin(); }

/* ============================================================
   Avvio
   ============================================================ */
async function avvia(){
  mostraApp();
  $('#me-nome').textContent = S.me.full_name;
  $('#me-ruolo').textContent = S.me.role==='admin' ? 'Amministratore' : 'Utente';
  $('#me-avatar').textContent = iniziali(S.me.full_name);
  $('#tab-utenti').classList.toggle('hidden', S.me.role!=='admin');
  $('#tab-impostazioni').classList.toggle('hidden', S.me.role!=='admin');
  $('#btn-devops').classList.toggle('hidden', S.me.role!=='admin');
  $('#btn-importa-devops').classList.toggle('hidden', S.me.role!=='admin');
  $('#btn-risolvi-devops').classList.toggle('hidden', S.me.role!=='admin');
  await caricaAree();
  await caricaTags();
  await caricaTicket();
  if(S.me.role==='admin'){ await caricaUtenti(); await caricaSeveritySettings(); await caricaAppSettings(); }
}

async function caricaAppSettings(){
  S.appSettings = await api('/app-settings');
}

async function caricaSeveritySettings(){
  S.severitySettings = await api('/severity-settings');
  disegnaSeveritySettings();
}

async function caricaAree(){
  S.aree = await api('/areas');
  disegnaAree();
}

async function caricaTags(){
  S.tags = await api('/tags');
  disegnaTags();
  aggiornaFiltroTag();
}

function aggiornaFiltroTag(){
  const sel = $('#f-tag');
  if(!sel) return;
  const val = sel.value;
  sel.innerHTML = '<option value="">Tag: tutti</option>' + S.tags.map(t=>\`<option>\${esc(t.name)}</option>\`).join('');
  sel.value = val;
}

$$('nav.tabs button').forEach(b=>b.onclick=()=>{
  $$('nav.tabs button').forEach(x=>x.classList.remove('on'));
  b.classList.add('on');
  $('#view-tickets').classList.toggle('hidden', b.dataset.tab!=='tickets');
  $('#view-report').classList.toggle('hidden', b.dataset.tab!=='report');
  $('#view-users').classList.toggle('hidden', b.dataset.tab!=='users');
  $('#view-settings').classList.toggle('hidden', b.dataset.tab!=='settings');
  if(b.dataset.tab==='report') disegnaReport();
  if(b.dataset.tab==='settings') mostraImpostazioniHub();
});
$('#r-periodo').onchange = disegnaReport;

/* ============================================================
   Lista ticket: filtri, ordinamento, render
   ============================================================ */
async function caricaTicket(){
  S.tickets = await api('/tickets');
  const autori = [...new Set(S.tickets.map(t=>t.author_name))].sort();
  const sel = $('#f-autore'), val = sel.value;
  sel.innerHTML = '<option value="">Autore: tutti</option>' + autori.map(a=>\`<option>\${esc(a)}</option>\`).join('');
  sel.value = val;
  render();
}

function filtrati(){
  const q = $('#f-testo').value.trim().toLowerCase();
  const tipo=$('#f-tipo').value, stato=$('#f-stato').value, grav=$('#f-grav').value, autore=$('#f-autore').value, tag=$('#f-tag').value;
  const miei=$('#f-miei').checked;
  let out = S.tickets.filter(t=>{
    if(tipo && t.type!==tipo) return false;
    if(stato && t.status!==stato) return false;
    if(grav && t.severity!==grav) return false;
    if(autore && t.author_name!==autore) return false;
    if(tag && t.tag!==tag) return false;
    if(miei && t.created_by!==S.me.id) return false;
    if(q){
      const blob = [t.code,t.title,t.area,t.operation,t.doc_number,t.error_text,t.expected,t.devops_id,t.author_name,t.tag]
        .join(' ').toLowerCase();
      if(!blob.includes(q)) return false;
    }
    return true;
  });
  const {key,dir} = S.sort, sgn = dir==='asc'?1:-1;
  const ordGrav = {bloccante:0,alta:1,media:2,bassa:3};
  const ordStato = {nuovo:0,preso_in_carico:1,aperto:2,approvato:3,sospesa:4,risolto:5,respinto:6};
  out.sort((a,b)=>{
    let x=a[key], y=b[key];
    if(key==='severity'){ x=ordGrav[x]; y=ordGrav[y]; }
    else if(key==='status'){ x=ordStato[x]; y=ordStato[y]; }
    else if(key==='code'){ x=a.id; y=b.id; }
    else { x=String(x??'').toLowerCase(); y=String(y??'').toLowerCase(); }
    return x<y ? -1*sgn : x>y ? 1*sgn : 0;
  });
  return out;
}

function render(){
  const righe = filtrati();
  $('#conteggio').textContent = \`\${righe.length} di \${S.tickets.length} · \${S.tickets.filter(t=>t.status==='nuovo'||t.status==='preso_in_carico').length} da valutare\`;
  $('#lista-vuota').classList.toggle('hidden', righe.length>0);
  $('#righe').innerHTML = righe.map(t=>\`
    <tr data-id="\${t.id}">
      <td class="codice">\${esc(t.code||'—')}</td>
      <td><span class="tipo t-\${t.type}">\${t.type}</span></td>
      <td class="tit-cella">\${esc(t.title)}\${t.notes_count?\` <span style="color:var(--grigio);font-size:12px">· \${t.notes_count} note</span>\`:''}</td>
      <td>\${esc(t.area||'—')}</td>
      <td>\${t.tag?\`<span class="pill">\${esc(t.tag)}</span>\`:'—'}</td>
      <td><span class="badge b-\${t.status}">\${ET_STATO[t.status]}</span></td>
      <td class="grav g-\${t.severity}">\${ET_GRAV[t.severity]}</td>
      <td>\${esc(t.author_name)}</td>
      <td style="white-space:nowrap">\${dataIt(t.created_at)}</td>
      <td class="codice">\${esc(t.devops_id||'—')}</td>
    </tr>\`).join('');
  $$('#righe tr').forEach(tr=>tr.onclick=()=>apriTicket(Number(tr.dataset.id)));
  $$('th[data-sort]').forEach(th=>{
    th.classList.toggle('attiva', th.dataset.sort===S.sort.key);
    th.querySelector('.freccia').textContent = (th.dataset.sort===S.sort.key && S.sort.dir==='asc') ? '▲' : '▼';
  });
}

$$('#f-testo,#f-tipo,#f-stato,#f-grav,#f-autore,#f-tag,#f-miei').forEach(el=>el.addEventListener('input',render));
$$('th[data-sort]').forEach(th=>th.onclick=()=>{
  const k=th.dataset.sort;
  S.sort = (S.sort.key===k) ? {key:k,dir:S.sort.dir==='asc'?'desc':'asc'} : {key:k,dir:'asc'};
  render();
});

/* ============================================================
   Dettaglio ticket
   ============================================================ */
const ORDINE_STATO = ['nuovo','preso_in_carico','aperto','risolto'];

/** Barra di avanzamento: il percorso normale, oppure il ramo che finisce in Respinto. */
function rail(stato){
  if(stato==='respinto'){
    return \`<div class="tappa fatta">Nuovo</div>
            <div class="tappa fatta">Aperto</div>
            <div class="tappa ko">Respinto</div>\`;
  }
  if(stato==='sospesa'){
    return \`<div class="tappa fatta">Nuovo</div>
            <div class="tappa fatta">Aperto</div>
            <div class="tappa pausa">Sospesa</div>\`;
  }
  // "approvato" è uno stato storico non più raggiungibile: si mostra come "Aperto" completato
  const idx = ORDINE_STATO.indexOf(stato==='approvato' ? 'aperto' : stato);
  return ORDINE_STATO.map((st,i)=>
    \`<div class="tappa \${i<=idx?'fatta':''}">\${ET_STATO[st]}</div>\`).join('');
}

async function apriTicket(id){
  const t = await api('/tickets/'+id);
  S.apertoId = id;
  const admin = S.me.role==='admin';
  const mio = t.created_by===S.me.id;
  const modificabile = admin || (mio && (t.status==='nuovo'||t.status==='preso_in_carico'||t.status==='respinto'));

  $('#drawer-host').innerHTML = \`
  <div class="velo" id="velo">
    <aside class="drawer" role="dialog" aria-label="Dettaglio segnalazione">
      <header>
        <div>
          <div style="display:flex;gap:9px;align-items:center;margin-bottom:5px">
            <span class="codice">\${esc(t.code||'—')}</span>
            <span class="tipo t-\${t.type}">\${t.type}</span>
            <span class="badge b-\${t.status}">\${ET_STATO[t.status]}</span>
          </div>
          <h3>\${esc(t.title)}</h3>
        </div>
        <button class="chiudi" id="dw-chiudi" aria-label="Chiudi">×</button>
      </header>
      <div class="corpo">
        <div class="rail">\${rail(t.status)}</div>

        \${t.status==='respinto' ? \`<div class="riquadro ko"><h4>Motivo del rifiuto</h4><div>\${esc(t.reject_reason||'')}</div></div>\`:''}
        \${t.devops_id ? \`<div class="riquadro"><h4>Azure DevOps</h4><div class="codice" style="font-size:14px">#\${esc(t.devops_id)}</div></div>\`:''}

        <dl style="margin:0">
          <div class="dett"><dt>Area / menu</dt><dd>\${esc(t.area||'—')}</dd></div>
          \${t.tag?\`<div class="dett"><dt>Tag</dt><dd><span class="pill">\${esc(t.tag)}</span></dd></div>\`:''}
          <div class="dett"><dt>Cosa stavi facendo</dt><dd>\${esc(t.operation||'—')}</dd></div>
          <div class="dett"><dt>N° documento</dt><dd>\${esc(t.doc_number||'—')}</dd></div>
          <div class="dett"><dt>Errore riscontrato</dt><dd>\${t.no_error_message?'<span class="pill warn">nessun messaggio a video</span><br>':''}\${esc(t.error_text||'—')}</dd></div>
          \${t.expected?\`<div class="dett"><dt>Risultato atteso</dt><dd>\${esc(t.expected)}</dd></div>\`:''}
          <div class="dett"><dt>Su Sebach Pro</dt><dd>\${esc(ET_PRO[t.pro_check]||'—')}</dd></div>
          <div class="dett"><dt>Gravità</dt><dd class="grav g-\${t.severity}">\${ET_GRAV[t.severity]}</dd></div>
          <div class="dett"><dt>Aperta da</dt><dd>\${esc(t.author_name)} · \${dataOraIt(t.created_at)}</dd></div>
          \${t.status_by_name?\`<div class="dett"><dt>Ultima azione</dt><dd>\${esc(t.status_by_name)} · \${dataOraIt(t.status_at)}</dd></div>\`:''}
        </dl>

        \${modificabile ? \`<div style="margin-top:16px"><button class="btn" id="dw-modifica">Modifica i dati</button></div>\`:''}

        \${admin ? \`
        <div class="riquadro" style="margin-top:22px">
          <h4>Azioni amministratore</h4>
          <label class="campo" style="margin-bottom:10px"><span>ID Azure DevOps</span>
            <input type="text" id="ad-devops" value="\${esc(t.devops_id||'')}" placeholder="es. 12987"></label>
          <label class="campo" style="margin-bottom:10px"><span>Tipo</span>
            <select id="ad-tipo">
              <option value="BUG" \${t.type==='BUG'?'selected':''}>Bug</option>
              <option value="CR" \${t.type==='CR'?'selected':''}>Change Request</option>
            </select></label>
          <label class="campo" style="margin-bottom:10px"><span>Tag</span>
            <select id="ad-tag">
              <option value="" \${!t.tag?'selected':''}>Nessuno</option>
              \${S.tags.map(tg=>\`<option \${t.tag===tg.name?'selected':''}>\${esc(tg.name)}</option>\`).join('')}
            </select></label>
          \${(t.status==='nuovo'||t.status==='preso_in_carico') ? \`
          <label class="check-inline" style="margin-bottom:10px">
            <input type="checkbox" id="ad-forza-devops" \${t.devops_override?'checked':''}>
            Forza priority/severity per questo bug</label>
          <div id="ad-devops-forzati" class="\${t.devops_override?'':'hidden'}" style="margin-bottom:10px">
            <div style="display:flex;gap:8px">
              <label class="campo" style="flex:none"><span>Priority</span>
                <select id="ad-forza-priority" style="width:auto">
                  \${[1,2,3,4].map(n=>\`<option value="\${n}" \${t.devops_priority===n?'selected':''}>\${n}</option>\`).join('')}
                </select></label>
              <label class="campo" style="flex:1"><span>Severity</span>
                <input type="text" id="ad-forza-severity" value="\${esc(t.devops_severity||'')}" placeholder="es. 2 - High"></label>
            </div>
            <span class="aiuto">Con questo attivo, l'export CSV per DevOps usa questi valori invece della mappatura automatica per gravità.</span>
          </div>\` : (t.devops_override ? \`
          <div style="margin-bottom:10px">
            <span class="aiuto">Priority/severity forzate a suo tempo: \${t.devops_priority ?? '—'} / \${esc(t.devops_severity||'—')}.
            Non modificabili ora che il bug è \${ET_STATO[t.status].toLowerCase()}.</span>
          </div>\` : '')}
          <div style="margin-bottom:10px"><button class="btn mini" id="ad-salva-devops">Salva modifiche</button></div>
          <div style="display:flex;gap:8px;flex-wrap:wrap">
            <button class="btn" id="ad-apri">Segna come aperto</button>
            <button class="btn primario" id="ad-risolvi">Segna come risolto</button>
            \${t.type==='CR' ? \`<button class="btn" id="ad-sospendi">Sospendi</button>\`:''}
            \${t.status==='sospesa' ? \`<button class="btn primario" id="ad-riprendi">Riprendi</button>\`:''}
            <button class="btn pericolo" id="ad-respingi">Respingi</button>
          </div>
          <div id="ad-motivo" class="hidden" style="margin-top:12px">
            <label class="campo"><span>Motivazione del rifiuto</span>
              <span class="aiuto">La legge chi ha aperto la segnalazione. Sii esplicito sul perché.</span>
              <textarea id="ad-motivo-testo" placeholder="es. comportamento corretto: la ritenuta non si applica ai clienti extra UE"></textarea></label>
            <button class="btn pericolo" id="ad-conferma-rifiuto">Conferma il rifiuto</button>
          </div>
          <div class="errore" id="ad-err"></div>
          <div style="border-top:1px solid var(--bordo);margin-top:16px;padding-top:14px">
            <button class="btn pericolo" id="ad-elimina">Elimina la segnalazione</button>
            <p style="color:var(--grigio);font-size:12.5px;margin:8px 0 0">
              Sparisce insieme alle sue note e non si recupera. Se è solo da scartare, respingila: resta la traccia.</p>
          </div>
        </div>\`:''}

        <div style="display:flex;align-items:center;margin:26px 0 8px">
          <h4 class="disp" style="text-transform:uppercase;font-size:13px;letter-spacing:.06em;color:var(--grigio);margin:0">Allegati</h4>
          \${modificabile ? \`
          <input type="file" id="dw-file" multiple style="display:none"
            accept="image/*,application/pdf,.txt,.csv,.xlsx,.xls,.docx,.doc,.msg,.eml,.cbi">
          <button class="btn mini" id="dw-aggiungi-file" style="margin-left:auto">+ Aggiungi</button>\`:''}
        </div>
        <div id="allegati"></div>
        <div class="errore" id="all-err"></div>

        <h4 class="disp" style="text-transform:uppercase;font-size:13px;letter-spacing:.06em;color:var(--grigio);margin:26px 0 4px">Note e storico</h4>
        <div class="chat" id="chat"></div>
        <div class="invio">
          <textarea id="nota-testo" placeholder="Scrivi una nota…"></textarea>
          <button class="btn primario" id="nota-invia">Invia</button>
        </div>
      </div>
    </aside>
  </div>\`;

  $('#velo').onclick = (e)=>{ if(e.target.id==='velo') chiudiDrawer(); };
  $('#dw-chiudi').onclick = chiudiDrawer;
  if(modificabile) $('#dw-modifica').onclick = ()=>apriWizard(t);

  if(admin){
    const devops = ()=>$('#ad-devops').value.trim();
    const forzaCheck = $('#ad-forza-devops');
    const forzaBox = $('#ad-devops-forzati');
    if(forzaCheck) forzaCheck.onchange = ()=> forzaBox.classList.toggle('hidden', !forzaCheck.checked);

    const salvaCampiAdmin = async ()=>{
      const patch = {};
      if($('#ad-tipo').value!==t.type) patch.type = $('#ad-tipo').value;
      if($('#ad-tag').value!==(t.tag||'')) patch.tag = $('#ad-tag').value;
      if(devops()!==(t.devops_id||'')) patch.devops_id = devops();
      if(forzaCheck){
        const forzato = forzaCheck.checked;
        if(forzato !== !!t.devops_override) patch.devops_override = forzato;
        if(forzato){
          const priorita = Number($('#ad-forza-priority').value);
          const severita = $('#ad-forza-severity').value.trim();
          if(!severita) throw new Error('Scrivi la severity da usare per questo bug, oppure disattiva il forzatura.');
          if(priorita!==t.devops_priority) patch.devops_priority = priorita;
          if(severita!==(t.devops_severity||'')) patch.devops_severity = severita;
        }
      }
      if(Object.keys(patch).length) await api('/tickets/'+t.id,{method:'PATCH',body:patch});
    };

    if($('#ad-salva-devops')) $('#ad-salva-devops').onclick = async ()=>{
      $('#ad-err').textContent='';
      try{ await salvaCampiAdmin(); toast('Impostazioni salvate.'); await caricaTicket(); await apriTicket(t.id); }
      catch(e){ $('#ad-err').textContent = e.message; }
    };

    const cambiaStato = async (status, extra={})=>{
      $('#ad-err').textContent='';
      try{
        await salvaCampiAdmin();
        await api(\`/tickets/\${t.id}/status\`,{method:'POST',body:{status, devops_id:devops(), ...extra}});
        toast('Segnalazione aggiornata.');
        await caricaTicket(); await apriTicket(t.id);
      }catch(e){ $('#ad-err').textContent=e.message; }
    };
    $('#ad-apri').onclick = ()=>cambiaStato('aperto');
    $('#ad-risolvi').onclick = ()=>cambiaStato('risolto');
    if($('#ad-sospendi')) $('#ad-sospendi').onclick = ()=>cambiaStato('sospesa');
    if($('#ad-riprendi')) $('#ad-riprendi').onclick = ()=>cambiaStato(t.devops_id ? 'aperto' : 'nuovo');
    $('#ad-respingi').onclick = ()=>{ $('#ad-motivo').classList.remove('hidden'); $('#ad-motivo-testo').focus(); };
    $('#ad-conferma-rifiuto').onclick = ()=>cambiaStato('respinto',{reject_reason:$('#ad-motivo-testo').value.trim()});
    $('#ad-elimina').onclick = async ()=>{
      $('#ad-err').textContent='';
      const conferma = prompt(\`Per eliminare definitivamente \${t.code} scrivi il suo codice qui sotto.\`);
      if(conferma===null) return;
      if(conferma.trim().toUpperCase() !== (t.code||'').toUpperCase()){
        $('#ad-err').textContent = 'Codice non corrispondente: la segnalazione non è stata eliminata.';
        return;
      }
      try{
        await api('/tickets/'+t.id,{method:'DELETE'});
        chiudiDrawer();
        toast(\`Segnalazione \${t.code} eliminata.\`);
        await caricaTicket();
      }catch(e){ $('#ad-err').textContent = e.message; }
    };
  }

  await caricaAllegati(t.id);
  if(modificabile){
    $('#dw-aggiungi-file').onclick = ()=>$('#dw-file').click();
    $('#dw-file').onchange = async ()=>{
      const input = $('#dw-file');
      $('#all-err').textContent = '';
      for(const file of [...input.files]){
        try{
          const pronto = await preparaFile(file);
          await api(\`/tickets/\${t.id}/attachments\`,{method:'POST',body:pronto});
        }catch(e){ $('#all-err').textContent = e.message; }
      }
      input.value = '';
      await caricaAllegati(t.id);
      await caricaNote(t.id);
      await caricaTicket();
    };
  }

  await caricaNote(t.id);
  $('#nota-invia').onclick = async ()=>{
    const testo = $('#nota-testo').value.trim();
    if(!testo) return;
    await api(\`/tickets/\${t.id}/notes\`,{method:'POST',body:{body:testo}});
    $('#nota-testo').value='';
    await caricaNote(t.id);
    await caricaTicket();
  };
  $('#nota-testo').addEventListener('keydown',e=>{
    if(e.key==='Enter' && (e.ctrlKey||e.metaKey)) $('#nota-invia').click();
  });
}

function chiudiDrawer(){ $('#drawer-host').innerHTML=''; S.apertoId=null; }
document.addEventListener('keydown',e=>{ if(e.key==='Escape'){ chiudiDrawer(); chiudiWizard(); } });

async function caricaAllegati(id){
  const box = $('#allegati');
  if(!box) return;
  const lista = await api(\`/tickets/\${id}/attachments\`);
  if(!lista.length){
    box.innerHTML = '<div style="color:var(--grigio);font-size:13px">Nessun allegato.</div>';
    return;
  }
  box.innerHTML = lista.map(a=>{
    const mio = a.user_id===S.me.id || S.me.role==='admin';
    const anteprima = a.mime.startsWith('image/')
      ? \`<a href="/api/attachments/\${a.id}" target="_blank" rel="noopener">
           <img src="/api/attachments/\${a.id}" alt="\${esc(a.filename)}" loading="lazy"
                style="width:100%;max-height:220px;object-fit:cover;border-radius:8px;display:block;margin-bottom:8px"></a>\`
      : '';
    return \`<div style="border:1px solid var(--bordo);border-radius:10px;padding:10px 12px;margin-bottom:10px">
      \${anteprima}
      <div style="display:flex;align-items:center;gap:10px">
        <span style="font-size:17px">\${iconaFile(a.mime)}</span>
        <a href="/api/attachments/\${a.id}" target="_blank" rel="noopener"
           style="flex:1;word-break:break-all;font-weight:500">\${esc(a.filename)}</a>
        <span style="color:var(--grigio);font-size:12.5px;white-space:nowrap">\${pesoLeggibile(a.size)}</span>
        \${mio?\`<button class="btn mini" data-elimina-all="\${a.id}">Togli</button>\`:''}
      </div>
      <div style="color:var(--grigio);font-size:12px;margin-top:5px">\${esc(a.author_name)} · \${dataOraIt(a.created_at)}</div>
    </div>\`;
  }).join('');

  $$('[data-elimina-all]', box).forEach(b=>b.onclick=async()=>{
    if(!confirm('Rimuovo questo allegato?')) return;
    try{
      await api('/attachments/'+b.dataset.eliminaAll,{method:'DELETE'});
      await caricaAllegati(id); await caricaNote(id); await caricaTicket();
    }catch(e){ $('#all-err').textContent = e.message; }
  });
}

async function caricaNote(id){
  const note = await api(\`/tickets/\${id}/notes\`);
  const box = $('#chat');
  if(!box) return;
  box.innerHTML = note.length ? note.map(n=>{
    if(n.system) return \`<div class="msg sistema">\${esc(n.body)} · \${dataOraIt(n.created_at)}</div>\`;
    const mio = n.user_id===S.me.id;
    return \`<div class="msg \${mio?'mio':''}">
      <div class="meta">\${esc(n.author_name)} · \${dataOraIt(n.created_at)}</div>
      <div class="testo">\${esc(n.body)}</div></div>\`;
  }).join('') : \`<div style="color:var(--grigio);font-size:13px">Nessuna nota. Scrivi qui gli aggiornamenti invece di mandarli per mail.</div>\`;
  box.scrollTop = box.scrollHeight;
}

/* ============================================================
   Wizard guidato
   ============================================================ */
const MAX_ALLEGATI = 6;
const MAX_BYTE = 1200000;
const LATO_MAX_IMMAGINE = 1600;

/** Rimpicciolisce le immagini prima dell'invio, lascia intatti gli altri file. */
async function preparaFile(file){
  if(!file.type.startsWith('image/') || file.type==='image/gif'){
    if(file.size > MAX_BYTE) throw new Error(\`«\${file.name}» pesa \${Math.round(file.size/1024)} KB, oltre il limite.\`);
    return { filename:file.name, mime:file.type||'application/octet-stream', data: await base64Di(file) };
  }
  const bitmap = await createImageBitmap(file);
  const scala = Math.min(1, LATO_MAX_IMMAGINE/Math.max(bitmap.width, bitmap.height));
  const c = document.createElement('canvas');
  c.width = Math.round(bitmap.width*scala);
  c.height = Math.round(bitmap.height*scala);
  c.getContext('2d').drawImage(bitmap, 0, 0, c.width, c.height);
  let qualita = 0.85, dataUrl;
  do {
    dataUrl = c.toDataURL('image/jpeg', qualita);
    qualita -= 0.12;
  } while (dataUrl.length*0.75 > MAX_BYTE && qualita > 0.3);
  if(dataUrl.length*0.75 > MAX_BYTE) throw new Error(\`«\${file.name}» resta troppo pesante anche dopo la compressione.\`);
  const nome = file.name.replace(/\\.(png|webp|bmp|heic|heif)$/i, '.jpg');
  return { filename:nome, mime:'image/jpeg', data: dataUrl.split(',')[1] };
}

function base64Di(file){
  return new Promise((ok, ko)=>{
    const r = new FileReader();
    r.onload = ()=>ok(String(r.result).split(',')[1]);
    r.onerror = ()=>ko(new Error('Non riesco a leggere il file.'));
    r.readAsDataURL(file);
  });
}

const pesoLeggibile = (b)=> b>=1048576 ? (b/1048576).toFixed(1)+' MB' : Math.max(1,Math.round(b/1024))+' KB';
const iconaFile = (mime)=> mime.startsWith('image/') ? '🖼' : mime==='application/pdf' ? '📄' : '📎';

let W = null;

function apriWizard(esistente=null){
  W = {
    passo: 0,
    id: esistente ? esistente.id : null,
    file: [],
    d: esistente ? {
      title:esistente.title||'', area:esistente.area||'', area_libera:'',
      operation:esistente.operation||'', doc_number:esistente.doc_number||'',
      doc_na: !esistente.doc_number, error_text:esistente.error_text||'',
      no_error_message: !!esistente.no_error_message,
      pro_check:esistente.pro_check||'',
      severity:esistente.severity||'',
      type:esistente.type||'BUG',
      devops_priority:esistente.devops_priority ? String(esistente.devops_priority) : ''
    } : {
      title:'', area:'', area_libera:'', operation:'', doc_number:'', doc_na:false,
      error_text:'', no_error_message:false, pro_check:'', severity:'',
      type:'BUG', devops_priority:''
    }
  };
  disegnaWizard();
}
function chiudiWizard(){ $('#wizard-host').innerHTML=''; W=null; }

const PASSI = [
  {
    dom:'Che cosa non funziona?',
    sub:'Una riga sola, come la diresti a un collega. Serve a riconoscere la segnalazione nella lista.',
    campo:'title',
    html:d=>\`<label class="campo"><span>Titolo</span>
      <span class="aiuto">Esempio: «Errore su emissione di una fattura»</span>
      <input type="text" id="w-title" maxlength="200" value="\${esc(d.title)}" placeholder="Errore su emissione di una fattura"></label>\`,
    leggi:d=>{ d.title = $('#w-title').value.trim(); },
    valida:d=> d.title.length<8 ? 'Scrivi un titolo di almeno 8 caratteri: deve far capire il problema.' : null
  },
  {
    dom:'In che menu ti trovi?',
    sub:'Scegli la voce di Sebach Plus da cui parte il problema.',
    campo:'area',
    html:d=>{ const aree = listaAree(); return \`<label class="campo"><span>Menu / sezione</span>
      <select id="w-area">
        <option value="">— scegli —</option>
        \${aree.map(a=>\`<option \${d.area===a||(a==='Altro'&&d.area&&!aree.includes(d.area))?'selected':''}>\${esc(a)}</option>\`).join('')}
      </select></label>
      <label class="campo" id="w-area-box" style="display:none"><span>Percorso esatto (facoltativo)</span>
      <span class="aiuto">Esempio: Fatturazione → Fatturazione automatica</span>
      <input type="text" id="w-area-libera" value="\${esc(aree.includes(d.area)?d.area_libera:d.area)}" placeholder="Fatturazione → Fatturazione automatica"></label>\`; },
    leggi:d=>{
      const sel = $('#w-area').value, libero = $('#w-area-libera').value.trim();
      d.area_libera = libero;
      d.area = (sel==='Altro' && libero) ? libero : (libero && sel ? \`\${sel} → \${libero}\` : sel);
    },
    valida:d=> !d.area ? 'Seleziona il menu in cui ti trovi.' : null
  },
  {
    dom:'Che cosa stavi facendo?',
    sub:'L’operazione precisa, non quella generica. Se è una fattura, di che tipo.',
    campo:'operation',
    html:d=>\`<label class="campo"><span>Operazione</span>
      <span class="aiuto">Esempio: «emissione fattura differita da DDT per un cliente con ritenuta»</span>
      <textarea id="w-op" maxlength="300" placeholder="Stavo emettendo una fattura…">\${esc(d.operation)}</textarea></label>\`,
    leggi:d=>{ d.operation = $('#w-op').value.trim(); },
    valida:d=> d.operation.length<10 ? 'Aggiungi qualche parola in più: cosa stavi facendo esattamente?' : null
  },
  {
    dom:'Su quale documento?',
    sub:'Il numero serve a ritrovare il caso nel database. Senza, la verifica è molto più lenta.',
    campo:'doc_number',
    html:d=>\`<label class="campo"><span>Numero documento</span>
      <span class="aiuto">Fattura, preventivo, ordine, contratto: quello che stavi trattando.</span>
      <input type="text" id="w-doc" maxlength="80" value="\${esc(d.doc_number)}" placeholder="es. FT/2026/001234"></label>
      <label class="check-inline"><input type="checkbox" id="w-doc-na" \${d.doc_na?'checked':''}> Non c’è un documento di riferimento</label>\`,
    leggi:d=>{ d.doc_na = $('#w-doc-na').checked; d.doc_number = d.doc_na ? '' : $('#w-doc').value.trim(); },
    valida:d=> (!d.doc_na && !d.doc_number) ? 'Inserisci il numero del documento, oppure spunta che non ce n’è uno.' : null
  },
  {
    dom:'Che errore ti dà?',
    sub:'Se compare un messaggio a video, copialo parola per parola. Se non compare nulla, scrivi cosa succede al posto suo.',
    campo:'error_text',
    html:d=>\`<label class="campo"><span>Errore riscontrato</span>
      <textarea id="w-err" maxlength="4000" style="min-height:150px" placeholder="Compare il messaggio «…» / la schermata resta bianca / il totale calcolato è sbagliato di …">\${esc(d.error_text)}</textarea></label>
      <label class="check-inline"><input type="checkbox" id="w-no-err" \${d.no_error_message?'checked':''}> Non è comparso nessun messaggio di errore a video</label>
      <div id="w-no-err-nota" class="\${d.no_error_message?'':'hidden'}" style="margin-top:8px">
        <span class="aiuto">Va bene anche lasciarlo vuoto: basta la spunta qui sopra.</span>
      </div>\`,
    leggi:d=>{ d.error_text = $('#w-err').value.trim(); d.no_error_message = $('#w-no-err').checked; },
    valida:d=>{
      if(d.no_error_message) return null;
      if(!d.error_text) return 'Scrivi almeno qualche parola su cosa succede.';
      if(d.error_text.length<15) return 'Descrivi cosa succede con almeno una frase completa, anche se non compare un messaggio.';
      return null;
    }
  },
  {
    dom:'Che tipo di segnalazione è?',
    sub:'Bug: qualcosa che si è rotto o non funziona come dovrebbe. Change Request: una modifica a un comportamento che c’è già, o una funzione mai prevista.',
    campo:'type',
    html:d=>\`<label class="campo"><span>Tipo</span>
      <select id="w-tipo">
        <option value="BUG" \${d.type!=='CR'?'selected':''}>Bug</option>
        <option value="CR" \${d.type==='CR'?'selected':''}>Change Request</option>
      </select></label>\`,
    leggi:d=>{ d.type = $('#w-tipo').value === 'CR' ? 'CR' : 'BUG'; },
    valida:()=>null
  },
  {
    dom:'Riesci comunque a lavorare?',
    sub:'Serve a decidere l’ordine con cui vengono lavorate le segnalazioni.',
    campo:'severity',
    html:d=>\`<div class="scelte">
      \${[['bloccante','No, sono fermo','Non riesco a completare l’operazione in nessun modo.'],
         ['alta','Sì, ma con un giro strano','Ci arrivo solo con un’alternativa scomoda o rifacendo il lavoro.'],
         ['media','Sì, ma è sbagliato qualcosa','Lavoro lo stesso, però il risultato non è corretto.'],
         ['bassa','Sì, è solo un fastidio','Testo sbagliato, colonna storta, cose che non bloccano nulla.']]
        .map(([v,t,s])=>\`<label class="scelta \${d.severity===v?'sel':''}">
          <input type="radio" name="w-sev" value="\${v}" \${d.severity===v?'checked':''}>
          <span><b>\${t}</b><small>\${s}</small></span></label>\`).join('')}
      </div>\`,
    leggi:d=>{ const r=$('input[name=w-sev]:checked'); d.severity = r?r.value:''; },
    valida:d=> !d.severity ? 'Scegli quanto ti blocca.' : null
  },
  {
    dom:'Quale priorità vuoi dare?',
    sub:'Da 1 a 4, dove 1 è la più urgente. Puoi cambiarla finché la segnalazione è Nuova.',
    campo:'devops_priority',
    html:d=>\`<label class="campo"><span>Priorità</span>
      <select id="w-priorita">
        <option value="">— scegli —</option>
        \${[1,2,3,4].map(n=>\`<option value="\${n}" \${d.devops_priority===String(n)?'selected':''}>\${n}</option>\`).join('')}
      </select></label>\`,
    leggi:d=>{ d.devops_priority = $('#w-priorita').value; },
    valida:d=> !d.devops_priority ? 'Scegli una priorità da 1 a 4.' : null
  },
  {
    dom:'Vuoi allegare qualcosa?',
    sub:'Facoltativo, ma uno screenshot della schermata con l’errore vale più di mezza pagina di descrizione.',
    campo:null,
    html:d=>\`<div>
        <input type="file" id="w-file" multiple style="display:none"
          accept="image/*,application/pdf,.txt,.csv,.xlsx,.xls,.docx,.doc,.msg,.eml,.cbi">
        <button class="btn" id="w-sfoglia" type="button">Scegli i file…</button>
        <span style="color:var(--grigio);font-size:12.5px;margin-left:10px">
          Massimo \${MAX_ALLEGATI} file, \${Math.round(MAX_BYTE/1024)} KB l’uno. Le immagini vengono rimpicciolite in automatico.</span>
        <div id="w-lista-file" style="margin-top:16px"></div>
      </div>\`,
    leggi:()=>{},
    valida:()=>null
  },
  {
    dom:'Controlla e invia',
    sub:'Questo è quello che vedrà chi prende in carico la segnalazione. Se qualcosa non torna, torna indietro e correggilo.',
    campo:null,
    html:d=>\`<div class="riquadro">
        <h4>\${d.type==='CR'?'Change Request':'Bug'} · \${ET_GRAV[d.severity]||''} · priorità \${esc(d.devops_priority)||'—'}</h4>
        <div style="font-weight:600;font-size:16px;margin-bottom:10px">\${esc(d.title)}</div>
        <div style="white-space:pre-wrap">\${esc(descrizioneCompleta(d))}</div>
      </div>
      <p style="color:var(--grigio)">Dopo l'invio la segnalazione resta modificabile finché un amministratore non la prende in carico.</p>\`,
    leggi:()=>{}, valida:()=>null
  }
];

function descrizioneCompleta(d){
  return [
    \`Menu: \${d.area||'—'}\`,
    \`Operazione: \${d.operation||'—'}\`,
    \`Documento: \${d.doc_number||'nessun documento di riferimento'}\`,
    \`\`,
    \`Errore riscontrato:\`,
    ...(d.no_error_message ? ['(nessun messaggio di errore a video)'] : []),
    d.error_text||'—',
    \`\`,
    ...(d.pro_check ? [\`Verifica su Sebach Pro: \${ET_PRO[d.pro_check]||'—'}\`] : [])
  ].join('\\n');
}

function disegnaWizard(){
  const p = PASSI[W.passo], d = W.d;
  const ultimo = W.passo===PASSI.length-1;
  $('#wizard-host').innerHTML = \`
  <div class="modale" id="wiz-velo">
    <div class="wiz" role="dialog" aria-label="Nuova segnalazione">
      <div class="wiz-main">
        <div style="display:flex;align-items:center;margin-bottom:14px">
          <span class="disp" style="text-transform:uppercase;letter-spacing:.07em;font-size:13px;color:var(--grigio)">
            \${W.id?'Modifica segnalazione':'Nuova segnalazione'}</span>
          <button class="chiudi" id="wiz-chiudi" style="margin-left:auto" aria-label="Chiudi">×</button>
        </div>
        <div class="passi">\${PASSI.map((_,i)=>\`<i class="\${i<=W.passo?'on':''}"></i>\`).join('')}</div>
        <div class="contenuto">
          <div class="domanda">\${p.dom}</div>
          <div class="sotto">\${p.sub}</div>
          \${p.html(d)}
          <div class="errore" id="wiz-err"></div>
        </div>
        <div class="wiz-piede">
          <span class="conta">Passo \${W.passo+1} di \${PASSI.length}</span>
          <div class="dx">
            \${W.passo>0?'<button class="btn" id="wiz-indietro">Indietro</button>':''}
            <button class="btn primario" id="wiz-avanti">\${ultimo?(W.id?'Salva le modifiche':'Invia la segnalazione'):'Avanti'}</button>
          </div>
        </div>
      </div>
      <aside class="wiz-anteprima">
        <h4>Anteprima</h4>
        <div class="riga"><div class="et">Titolo</div><div class="vl \${d.title?'':'manca'}">\${esc(d.title)||'da compilare'}</div></div>
        <div class="riga"><div class="et">Menu</div><div class="vl \${d.area?'':'manca'}">\${esc(d.area)||'da compilare'}</div></div>
        <div class="riga"><div class="et">Operazione</div><div class="vl \${d.operation?'':'manca'}">\${esc(d.operation)||'da compilare'}</div></div>
        <div class="riga"><div class="et">Documento</div><div class="vl \${d.doc_number||d.doc_na?'':'manca'}">\${esc(d.doc_number)||(d.doc_na?'nessuno':'da compilare')}</div></div>
        <div class="riga"><div class="et">Errore</div><div class="vl \${(!d.error_text && !d.no_error_message)?'manca':''}">\${d.error_text?esc(d.error_text):(d.no_error_message?'—':'da compilare')}\${d.no_error_message?' <span style="color:var(--grigio)">(nessun messaggio a video)</span>':''}</div></div>
        <div class="riga"><div class="et">Gravità</div><div class="vl \${d.severity?'':'manca'}">\${ET_GRAV[d.severity]||'da compilare'}</div></div>
        <div class="riga"><div class="et">Priorità</div><div class="vl \${d.devops_priority?'':'manca'}">\${esc(d.devops_priority)||'da compilare'}</div></div>
        <div class="riga"><div class="et">Allegati</div><div class="vl \${W.file.length?'':'manca'}">\${W.file.length?W.file.length+(W.file.length===1?' file':' file'):'nessuno'}</div></div>
        <div class="riga" style="margin-top:16px;padding-top:14px;border-top:1px solid var(--bordo)">
          <div class="et">Tipo</div>
          <div class="vl"><span class="tipo t-\${d.type==='CR'?'CR':'BUG'}">\${d.type==='CR'?'CR':'BUG'}</span></div>
        </div>
      </aside>
    </div>
  </div>\`;

  $('#wiz-chiudi').onclick = ()=>{ if(confirm('Chiudere senza salvare?')) chiudiWizard(); };
  if(W.passo>0) $('#wiz-indietro').onclick = ()=>{ p.leggi(W.d); W.passo--; disegnaWizard(); };
  $('#wiz-avanti').onclick = avanti;

  // comportamenti specifici
  const areaSel = $('#w-area');
  if(areaSel){
    const box = $('#w-area-box');
    const agg = ()=>{ box.style.display = areaSel.value ? 'block':'none'; };
    agg(); areaSel.onchange = agg;
  }
  const sfoglia = $('#w-sfoglia');
  if(sfoglia){
    const input = $('#w-file');
    const lista = $('#w-lista-file');
    const disegnaFile = ()=>{
      lista.innerHTML = W.file.length ? W.file.map((f,i)=>\`
        <div style="display:flex;align-items:center;gap:10px;border:1px solid var(--bordo);
                    border-radius:10px;padding:9px 12px;margin-bottom:8px">
          <span style="font-size:17px">\${iconaFile(f.mime)}</span>
          <span style="flex:1;word-break:break-all">\${esc(f.filename)}</span>
          <span style="color:var(--grigio);font-size:12.5px;white-space:nowrap">\${pesoLeggibile(f.data.length*0.75)}</span>
          <button class="btn mini" data-togli="\${i}" type="button">Togli</button>
        </div>\`).join('')
        : '<div style="color:var(--grigio);font-size:13px">Nessun allegato. Puoi anche procedere così.</div>';
      $$('[data-togli]', lista).forEach(b=>b.onclick=()=>{ W.file.splice(Number(b.dataset.togli),1); disegnaFile(); });
    };
    disegnaFile();
    sfoglia.onclick = ()=>input.click();
    input.onchange = async ()=>{
      $('#wiz-err').textContent = '';
      for(const file of [...input.files]){
        if(W.file.length >= MAX_ALLEGATI){ $('#wiz-err').textContent = \`Massimo \${MAX_ALLEGATI} allegati.\`; break; }
        try{ W.file.push(await preparaFile(file)); }
        catch(e){ $('#wiz-err').textContent = e.message; }
      }
      input.value = '';
      disegnaFile();
    };
  }

  const docNa = $('#w-doc-na');
  if(docNa){
    const agg = ()=>{ $('#w-doc').disabled = docNa.checked; };
    agg(); docNa.onchange = agg;
  }
  const noErrCk = $('#w-no-err');
  if(noErrCk){
    noErrCk.onchange = ()=> $('#w-no-err-nota')?.classList.toggle('hidden', !noErrCk.checked);
  }
  const evidenzia = ()=>$$('.scelta').forEach(s=>s.classList.toggle('sel', s.querySelector('input').checked));
  $$('input[name=w-pro]').forEach(r=>r.onchange=()=>{
    evidenzia();
    $('#w-nota-cr').classList.toggle('hidden', r.value!=='anche_su_pro');
  });
  $$('input[name=w-sev]').forEach(r=>r.onchange=evidenzia);
  const primo = $('.contenuto input:not([type=checkbox]):not([type=radio]), .contenuto textarea, .contenuto select');
  if(primo) primo.focus();
}

async function avanti(){
  const p = PASSI[W.passo];
  p.leggi(W.d);
  const err = p.valida(W.d);
  if(err){ $('#wiz-err').textContent = err; return; }
  if(W.passo < PASSI.length-1){ W.passo++; disegnaWizard(); return; }

  const body = {
    title:W.d.title, area:W.d.area, operation:W.d.operation, doc_number:W.d.doc_number,
    error_text:W.d.error_text, no_error_message:W.d.no_error_message, pro_check:W.d.pro_check, severity:W.d.severity,
    type:W.d.type, devops_priority:W.d.devops_priority
  };
  $('#wiz-avanti').disabled = true;
  try{
    if(W.id){
      await api('/tickets/'+W.id,{method:'PATCH',body});
      toast('Segnalazione aggiornata.');
      const id = W.id; chiudiWizard(); await caricaTicket(); await apriTicket(id);
    }else{
      const nuovo = await api('/tickets',{method:'POST',body});
      const falliti = [];
      for(const f of W.file){
        try{ await api(\`/tickets/\${nuovo.id}/attachments\`,{method:'POST',body:f}); }
        catch(e){ falliti.push(f.filename); }
      }
      toast(falliti.length
        ? \`Segnalazione \${nuovo.code} registrata, ma non ho caricato: \${falliti.join(', ')}\`
        : \`Segnalazione \${nuovo.code} registrata.\`, falliti.length>0);
      chiudiWizard(); await caricaTicket(); await apriTicket(nuovo.id);
    }
  }catch(e){
    $('#wiz-err').textContent = e.message;
    $('#wiz-avanti').disabled = false;
  }
}
$('#btn-nuovo').onclick = ()=>apriSegnalazioneRapida();

/* ============================================================
   Nuova segnalazione: solo titolo, descrizione e allegati.
   Il resto (tipo, area, gravità) lo ricava l'Ufficio IT.
   ============================================================ */
function apriSegnalazioneRapida(){
  const file = [];
  $('#wizard-host').innerHTML = \`
  <div class="modale" id="sr-velo">
    <div style="background:#fff;border-radius:14px;width:min(560px,100%);padding:26px;max-height:92vh;overflow:auto">
      <div style="display:flex;align-items:center;margin-bottom:6px">
        <h3 class="disp" style="font-size:22px;text-transform:uppercase">Nuova segnalazione</h3>
        <button class="chiudi" id="sr-chiudi" style="margin-left:auto" aria-label="Chiudi">×</button>
      </div>
      <p style="color:var(--grigio);font-size:13px;margin:0 0 16px">
        Scrivi cosa succede con parole tue e allega uno screenshot se puoi. Al resto pensiamo noi.
      </p>
      <label class="campo"><span>Titolo</span>
        <input type="text" id="sr-titolo" maxlength="200" placeholder="Es. Errore quando emetto una fattura"></label>
      <label class="campo"><span>Descrizione</span>
        <textarea id="sr-descrizione" style="min-height:150px" placeholder="Cosa stavi facendo, in che schermata, con quale documento o cliente, e cosa è successo."></textarea></label>
      <div class="campo"><span>Allegati</span>
        <div id="sr-drop" style="border:1.5px dashed var(--bordo);border-radius:10px;padding:14px;text-align:center;color:var(--grigio);font-size:13px;cursor:pointer">
          Trascina qui i file, <u>sfoglia</u>, oppure incolla uno screenshot con Ctrl+V
        </div>
        <input type="file" id="sr-file" multiple style="display:none"
          accept="image/*,application/pdf,.txt,.csv,.xlsx,.xls,.docx,.doc,.msg,.eml">
        <div id="sr-lista" style="margin-top:8px"></div>
      </div>
      <div class="errore" id="sr-err"></div>
      <div style="display:flex;gap:8px">
        <button class="btn" id="sr-annulla" style="flex:1">Annulla</button>
        <button class="btn primario" id="sr-crea" style="flex:1">Invia segnalazione</button>
      </div>
    </div>
  </div>\`;
  const chiudi = ()=>{ document.removeEventListener('paste', incolla); $('#wizard-host').innerHTML=''; };
  $('#sr-chiudi').onclick = chiudi;
  $('#sr-annulla').onclick = chiudi;
  $('#sr-velo').onclick = (e)=>{ if(e.target.id==='sr-velo') chiudi(); };
  $('#sr-titolo').focus();

  const disegna = ()=>{
    $('#sr-lista').innerHTML = file.map((f,i)=>\`
      <div style="display:flex;align-items:center;gap:10px;border:1px solid var(--bordo);border-radius:10px;padding:8px 12px;margin-bottom:6px">
        <span style="font-size:17px">\${iconaFile(f.mime)}</span>
        <span style="flex:1;word-break:break-all;font-size:13px">\${esc(f.filename)}</span>
        <span style="color:var(--grigio);font-size:12px;white-space:nowrap">\${pesoLeggibile(f.data.length*0.75)}</span>
        <button class="btn mini" data-togli="\${i}" type="button">Togli</button>
      </div>\`).join('');
    $$('[data-togli]', $('#sr-lista')).forEach(b=>b.onclick=()=>{ file.splice(Number(b.dataset.togli),1); disegna(); });
  };
  const aggiungi = async (lista)=>{
    $('#sr-err').textContent = '';
    for(const f of lista){
      if(file.length >= MAX_ALLEGATI){ $('#sr-err').textContent = \`Massimo \${MAX_ALLEGATI} allegati.\`; break; }
      try{
        const pronto = await preparaFile(f);
        if(/^image\.(jpg|png)$/i.test(pronto.filename)) pronto.filename = \`screenshot-\${new Date().toISOString().slice(0,19).replace(/[:T]/g,'-')}.jpg\`;
        file.push(pronto);
      }catch(e){ $('#sr-err').textContent = e.message; }
    }
    disegna();
  };
  const drop = $('#sr-drop'), input = $('#sr-file');
  drop.onclick = ()=>input.click();
  input.onchange = async ()=>{ await aggiungi([...input.files]); input.value=''; };
  drop.ondragover = (e)=>{ e.preventDefault(); drop.style.borderColor='var(--rosso)'; };
  drop.ondragleave = ()=>{ drop.style.borderColor=''; };
  drop.ondrop = (e)=>{ e.preventDefault(); drop.style.borderColor=''; aggiungi([...e.dataTransfer.files]); };
  function incolla(e){
    const f = [...(e.clipboardData?.files||[])];
    if(f.length){ e.preventDefault(); aggiungi(f); }
  }
  document.addEventListener('paste', incolla);

  $('#sr-crea').onclick = async ()=>{
    $('#sr-err').textContent = '';
    const titolo = $('#sr-titolo').value.trim();
    const descrizione = $('#sr-descrizione').value.trim();
    if(titolo.length<8){ $('#sr-err').textContent = 'Il titolo deve avere almeno 8 caratteri.'; return; }
    if(descrizione.length<15){ $('#sr-err').textContent = 'La descrizione deve avere almeno 15 caratteri.'; return; }
    $('#sr-crea').disabled = true;
    try{
      const nuovo = await api('/tickets',{method:'POST',body:{
        title:titolo, area:'Da classificare', error_text:descrizione,
        pro_check:'non_verificato', severity:'media'
      }});
      const falliti = [];
      for(const f of file){
        try{ await api(\`/tickets/\${nuovo.id}/attachments\`,{method:'POST',body:f}); }
        catch(e){ falliti.push(f.filename); }
      }
      toast(falliti.length
        ? \`Segnalazione \${nuovo.code} inviata, ma non ho caricato: \${falliti.join(', ')}\`
        : \`Segnalazione \${nuovo.code} inviata. Grazie!\`, falliti.length>0);
      chiudi();
      await caricaTicket();
      await apriTicket(nuovo.id);
    }catch(e){
      $('#sr-err').textContent = e.message;
      $('#sr-crea').disabled = false;
    }
  };
  $('#sr-descrizione').addEventListener('keydown', e=>{
    if(e.key==='Enter' && (e.ctrlKey||e.metaKey)) $('#sr-crea').click();
  });
}

/* ============================================================
   Utenti
   ============================================================ */
async function caricaUtenti(){
  S.users = await api('/users');
  $('#righe-utenti').innerHTML = S.users.map(u=>\`
    <tr>
      <td style="font-weight:500">\${esc(u.full_name)}\${u.id===S.me.id?' <span class="pill">tu</span>':''}
          \${u.email?\`<div style="color:var(--grigio);font-size:12.5px">\${esc(u.email)}</div>\`:''}</td>
      <td class="codice">\${esc(u.username)}</td>
      <td>\${u.role==='admin'?'<span class="badge b-aperto">Admin</span>':'<span class="badge b-nuovo">Utente</span>'}</td>
      <td>\${u.active?'<span class="pill">attivo</span>':'<span class="pill">disattivato</span>'}
          \${u.on_default_password?'<span class="pill warn">password default</span>':''}</td>
      <td style="white-space:nowrap">
        <button class="btn mini" data-modifica="\${u.id}">Modifica</button>
        <button class="btn mini" data-reset="\${u.id}">Reset password</button>
        \${u.id!==S.me.id?\`<button class="btn mini" data-attiva="\${u.id}" data-val="\${u.active?0:1}">\${u.active?'Disattiva':'Riattiva'}</button>\`:''}
      </td>
    </tr>\`).join('');

  $$('[data-modifica]').forEach(b=>b.onclick=()=>apriModificaUtente(Number(b.dataset.modifica)));
  $$('[data-reset]').forEach(b=>b.onclick=async()=>{
    if(!confirm('Riporti la password di questo utente a quella di default? Verrà disconnesso subito.')) return;
    try{ await api(\`/users/\${b.dataset.reset}/reset-password\`,{method:'POST'}); toast('Password riportata a quella di default.'); await caricaUtenti(); }
    catch(e){ toast(e.message,true); }
  });
  $$('[data-attiva]').forEach(b=>b.onclick=async()=>{
    try{ await api('/users/'+b.dataset.attiva,{method:'PATCH',body:{active:b.dataset.val==='1'}}); await caricaUtenti(); }
    catch(e){ toast(e.message,true); }
  });
}

function apriModificaUtente(id){
  const u = S.users.find(x=>x.id===id);
  if(!u) return;
  const io = u.id===S.me.id;
  $('#wizard-host').innerHTML = \`
  <div class="modale" id="mu-velo">
    <div style="background:#fff;border-radius:14px;width:min(420px,100%);padding:26px;max-height:92vh;overflow:auto">
      <div style="display:flex;align-items:center;margin-bottom:16px">
        <h3 class="disp" style="font-size:22px;text-transform:uppercase">Modifica utente</h3>
        <button class="chiudi" id="mu-chiudi" style="margin-left:auto" aria-label="Chiudi">×</button>
      </div>
      <label class="campo"><span>Nome e cognome</span>
        <input type="text" id="mu-nome" value="\${esc(u.full_name)}"></label>
      <label class="campo"><span>Utente</span>
        <span class="aiuto">È il nome con cui accede. Cambiandolo dovrà usare il nuovo.</span>
        <input type="text" id="mu-user" value="\${esc(u.username)}"></label>
      <label class="campo"><span>Email</span>
        <input type="email" id="mu-mail" value="\${esc(u.email||'')}"></label>
      <label class="campo"><span>Ruolo</span>
        <select id="mu-ruolo" \${io?'disabled':''}>
          <option value="user" \${u.role==='user'?'selected':''}>Utente</option>
          <option value="admin" \${u.role==='admin'?'selected':''}>Admin</option>
        </select>
        \${io?'<span class="aiuto" style="margin:6px 0 0">Non puoi togliere i permessi a te stesso.</span>':''}</label>
      <label class="campo"><span>Stato</span>
        <select id="mu-attivo" \${io?'disabled':''}>
          <option value="1" \${u.active?'selected':''}>Attivo</option>
          <option value="0" \${u.active?'':'selected'}>Disattivato</option>
        </select></label>
      <div class="errore" id="mu-err"></div>
      <div style="display:flex;gap:8px">
        <button class="btn" id="mu-annulla" style="flex:1">Annulla</button>
        <button class="btn primario" id="mu-salva" style="flex:1">Salva</button>
      </div>
    </div>
  </div>\`;

  const chiudi = ()=>{ $('#wizard-host').innerHTML=''; };
  $('#mu-chiudi').onclick = chiudi;
  $('#mu-annulla').onclick = chiudi;
  $('#mu-velo').onclick = (e)=>{ if(e.target.id==='mu-velo') chiudi(); };
  $('#mu-nome').focus();

  $('#mu-salva').onclick = async ()=>{
    $('#mu-err').textContent='';
    const body = {
      full_name: $('#mu-nome').value.trim(),
      username: $('#mu-user').value.trim(),
      email: $('#mu-mail').value.trim()
    };
    if(!io){ body.role = $('#mu-ruolo').value; body.active = $('#mu-attivo').value==='1'; }
    $('#mu-salva').disabled = true;
    try{
      await api('/users/'+id,{method:'PATCH',body});
      chiudi();
      toast('Utente aggiornato.');
      await caricaUtenti();
      await caricaTicket();
    }catch(e){
      $('#mu-err').textContent = e.message;
      $('#mu-salva').disabled = false;
    }
  };
}

$('#nu-btn').onclick = async ()=>{
  $('#nu-err').textContent='';
  try{
    await api('/users',{method:'POST',body:{
      full_name:$('#nu-nome').value.trim(), username:$('#nu-user').value.trim(),
      email:$('#nu-mail').value.trim(), role:$('#nu-ruolo').value }});
    $('#nu-nome').value=$('#nu-user').value=$('#nu-mail').value='';
    toast('Utente creato.');
    await caricaUtenti();
  }catch(e){ $('#nu-err').textContent=e.message; }
};

/* ============================================================
   Impostazioni: hub e navigazione fra le sotto-pagine
   ============================================================ */
function mostraImpostazioniHub(){
  $('#impostazioni-hub')?.classList.remove('hidden');
  $('#impostazioni-aree')?.classList.add('hidden');
  $('#impostazioni-devops')?.classList.add('hidden');
  $('#impostazioni-tags')?.classList.add('hidden');
}
function mostraImpostazioniAree(){
  $('#impostazioni-hub')?.classList.add('hidden');
  $('#impostazioni-aree')?.classList.remove('hidden');
  $('#impostazioni-devops')?.classList.add('hidden');
  $('#impostazioni-tags')?.classList.add('hidden');
  disegnaAree();
}
function mostraImpostazioniDevops(){
  $('#impostazioni-hub')?.classList.add('hidden');
  $('#impostazioni-aree')?.classList.add('hidden');
  $('#impostazioni-devops')?.classList.remove('hidden');
  $('#impostazioni-tags')?.classList.add('hidden');
  disegnaSeveritySettings();
}
function mostraImpostazioniTags(){
  $('#impostazioni-hub')?.classList.add('hidden');
  $('#impostazioni-aree')?.classList.add('hidden');
  $('#impostazioni-devops')?.classList.add('hidden');
  $('#impostazioni-tags')?.classList.remove('hidden');
  disegnaTags();
}
$('#imp-apri-aree').onclick = mostraImpostazioniAree;
$('#imp-torna').onclick = mostraImpostazioniHub;
$('#imp-apri-devops').onclick = mostraImpostazioniDevops;
$('#imp-torna-devops').onclick = mostraImpostazioniHub;
$('#imp-apri-tags').onclick = mostraImpostazioniTags;
$('#imp-torna-tags').onclick = mostraImpostazioniHub;

/* ============================================================
   Impostazioni: menu del wizard
   ============================================================ */
function disegnaAree(){
  const box = $('#righe-aree');
  if(!box) return;
  box.innerHTML = S.aree.map((a,i)=>\`
    <div style="display:flex;align-items:center;gap:8px;border:1px solid var(--bordo);
                border-radius:10px;padding:9px 11px;margin-bottom:8px">
      <div style="display:flex;flex-direction:column;gap:1px">
        <button class="btn mini" data-su="\${a.id}" \${i===0?'disabled':''} title="Sposta su" style="padding:1px 7px">▲</button>
        <button class="btn mini" data-giu="\${a.id}" \${i===S.aree.length-1?'disabled':''} title="Sposta giù" style="padding:1px 7px">▼</button>
      </div>
      <input type="text" value="\${esc(a.name)}" data-rinomina="\${a.id}" style="flex:1;border:0;padding:4px 2px;background:transparent">
      <button class="btn mini" data-togli-area="\${a.id}">Elimina</button>
    </div>\`).join('') + \`
    <div style="display:flex;align-items:center;gap:8px;border:1px dashed var(--bordo);
                border-radius:10px;padding:9px 11px;color:var(--grigio);font-size:13px">
      <span style="flex:1">Altro</span><span class="pill">fisso</span>
    </div>\`;

  $$('[data-su]', box).forEach(b=>b.onclick=()=>spostaArea(b.dataset.su,'su'));
  $$('[data-giu]', box).forEach(b=>b.onclick=()=>spostaArea(b.dataset.giu,'giu'));
  $$('[data-togli-area]', box).forEach(b=>b.onclick=()=>eliminaArea(b.dataset.togliArea));
  $$('[data-rinomina]', box).forEach(inp=>{
    inp.addEventListener('change', ()=>rinominaArea(inp.dataset.rinomina, inp.value.trim(), inp));
    inp.addEventListener('keydown', e=>{ if(e.key==='Enter') inp.blur(); });
  });
}

async function spostaArea(id, direzione){
  $('#ar-err').textContent='';
  try{ S.aree = await api('/areas/'+id,{method:'PATCH',body:{direzione}}); disegnaAree(); }
  catch(e){ $('#ar-err').textContent = e.message; }
}

async function rinominaArea(id, nome, campo){
  $('#ar-err').textContent='';
  if(!nome){ disegnaAree(); return; }
  try{ S.aree = await api('/areas/'+id,{method:'PATCH',body:{name:nome}}); disegnaAree(); }
  catch(e){ $('#ar-err').textContent = e.message; campo.value = S.aree.find(a=>String(a.id)===String(id))?.name || ''; }
}

async function eliminaArea(id){
  if(!confirm('Tolgo questa voce dall\\u2019elenco? Le segnalazioni già aperte non cambiano.')) return;
  $('#ar-err').textContent='';
  try{ S.aree = await api('/areas/'+id,{method:'DELETE'}); disegnaAree(); }
  catch(e){ $('#ar-err').textContent = e.message; }
}

$('#ar-btn').onclick = async ()=>{
  $('#ar-err').textContent='';
  const nome = $('#ar-nome').value.trim();
  if(!nome) return;
  try{
    S.aree = await api('/areas',{method:'POST',body:{name:nome}});
    $('#ar-nome').value='';
    disegnaAree();
  }catch(e){ $('#ar-err').textContent = e.message; }
};
$('#ar-nome').addEventListener('keydown', e=>{ if(e.key==='Enter') $('#ar-btn').click(); });

/* ============================================================
   Impostazioni: priority e severity per DevOps
   ============================================================ */
function disegnaSeveritySettings(){
  const box = $('#righe-devops');
  if(!box) return;
  box.innerHTML = S.severitySettings.map(r=>\`
    <div style="display:flex;align-items:center;gap:10px;border:1px solid var(--bordo);
                border-radius:10px;padding:9px 11px;margin-bottom:8px">
      <span class="grav g-\${r.severity}" style="width:80px;flex:none">\${ET_GRAV[r.severity]}</span>
      <label style="display:flex;align-items:center;gap:6px;font-size:12.5px;color:var(--grigio)">
        Priority
        <select data-sev-priority="\${r.severity}" style="width:auto;padding:5px 8px">
          \${[1,2,3,4].map(n=>\`<option value="\${n}" \${r.priority===n?'selected':''}>\${n}</option>\`).join('')}
        </select>
      </label>
      <input type="text" data-sev-testo="\${r.severity}" value="\${esc(r.csv_severity)}"
             style="flex:1;border:1px solid var(--bordo);border-radius:8px;padding:6px 9px" placeholder="es. 2 - High">
    </div>\`).join('');

  $$('[data-sev-priority]', box).forEach(sel=>sel.onchange=()=>salvaSeveritySetting(sel.dataset.sevPriority));
  $$('[data-sev-testo]', box).forEach(inp=>{
    inp.addEventListener('change', ()=>salvaSeveritySetting(inp.dataset.sevTesto));
    inp.addEventListener('keydown', e=>{ if(e.key==='Enter') inp.blur(); });
  });
}

async function salvaSeveritySetting(severity){
  $('#dv-err').textContent='';
  const priority = Number($(\`[data-sev-priority="\${severity}"]\`).value);
  const csv_severity = $(\`[data-sev-testo="\${severity}"]\`).value.trim();
  if(!csv_severity){ $('#dv-err').textContent = 'Il testo della severity non può restare vuoto.'; disegnaSeveritySettings(); return; }
  try{
    S.severitySettings = await api('/severity-settings/'+severity,{method:'PATCH',body:{priority, csv_severity}});
    disegnaSeveritySettings();
  }catch(e){ $('#dv-err').textContent = e.message; disegnaSeveritySettings(); }
}

/* ============================================================
   Impostazioni: tag della segnalazione rapida
   ============================================================ */
function disegnaTags(){
  const box = $('#righe-tags');
  if(!box) return;
  box.innerHTML = S.tags.map((tg,i)=>\`
    <div style="display:flex;align-items:center;gap:8px;border:1px solid var(--bordo);
                border-radius:10px;padding:9px 11px;margin-bottom:8px">
      <div style="display:flex;flex-direction:column;gap:1px">
        <button class="btn mini" data-su-tag="\${tg.id}" \${i===0?'disabled':''} title="Sposta su" style="padding:1px 7px">▲</button>
        <button class="btn mini" data-giu-tag="\${tg.id}" \${i===S.tags.length-1?'disabled':''} title="Sposta giù" style="padding:1px 7px">▼</button>
      </div>
      <input type="text" value="\${esc(tg.name)}" data-rinomina-tag="\${tg.id}" style="flex:1;border:0;padding:4px 2px;background:transparent">
      <button class="btn mini" data-togli-tag="\${tg.id}">Elimina</button>
    </div>\`).join('') || '<div style="color:var(--grigio);font-size:13px">Nessun tag ancora. Aggiungine uno qui sotto.</div>';

  $$('[data-su-tag]', box).forEach(b=>b.onclick=()=>spostaTag(b.dataset.suTag,'su'));
  $$('[data-giu-tag]', box).forEach(b=>b.onclick=()=>spostaTag(b.dataset.giuTag,'giu'));
  $$('[data-togli-tag]', box).forEach(b=>b.onclick=()=>eliminaTag(b.dataset.togliTag));
  $$('[data-rinomina-tag]', box).forEach(inp=>{
    inp.addEventListener('change', ()=>rinominaTag(inp.dataset.rinominaTag, inp.value.trim(), inp));
    inp.addEventListener('keydown', e=>{ if(e.key==='Enter') inp.blur(); });
  });
}

async function spostaTag(id, direzione){
  $('#tg-err').textContent='';
  try{ S.tags = await api('/tags/'+id,{method:'PATCH',body:{direzione}}); disegnaTags(); aggiornaFiltroTag(); }
  catch(e){ $('#tg-err').textContent = e.message; }
}

async function rinominaTag(id, nome, campo){
  $('#tg-err').textContent='';
  if(!nome){ disegnaTags(); return; }
  try{ S.tags = await api('/tags/'+id,{method:'PATCH',body:{name:nome}}); disegnaTags(); aggiornaFiltroTag(); }
  catch(e){ $('#tg-err').textContent = e.message; campo.value = S.tags.find(t=>String(t.id)===String(id))?.name || ''; }
}

async function eliminaTag(id){
  if(!confirm('Tolgo questo tag dall\\u2019elenco? Le segnalazioni che lo hanno già non cambiano.')) return;
  $('#tg-err').textContent='';
  try{ S.tags = await api('/tags/'+id,{method:'DELETE'}); disegnaTags(); aggiornaFiltroTag(); }
  catch(e){ $('#tg-err').textContent = e.message; }
}

$('#tg-btn').onclick = async ()=>{
  $('#tg-err').textContent='';
  const nome = $('#tg-nome').value.trim();
  if(!nome) return;
  try{
    S.tags = await api('/tags',{method:'POST',body:{name:nome}});
    $('#tg-nome').value='';
    disegnaTags();
    aggiornaFiltroTag();
  }catch(e){ $('#tg-err').textContent = e.message; }
};
$('#tg-nome').addEventListener('keydown', e=>{ if(e.key==='Enter') $('#tg-btn').click(); });


/* ============================================================
   Report
   ============================================================ */
const COLORI_GRAV = {bloccante:'#A80D23', alta:'#D4112D', media:'#E8804F', bassa:'#C9CDD4'};
const COLORI_STATO = {nuovo:'#4A5568', preso_in_carico:'#1F4E8C', aperto:'#B4650F', approvato:'#0B5A72', risolto:'#17915A', respinto:'#A80D23', sospesa:'#5B4B8A'};
const COLORI_SERIE = ['#D4112D','#A80D23','#F0243F','#E8804F','#4A5568','#8A9099','#C9CDD4'];

const giorniFra = (a,b)=> (new Date(b.replace(' ','T')+'Z') - new Date(a.replace(' ','T')+'Z'))/86400000;
const giornoDi = (s)=> s.slice(0,10);
const nomeGiorno = (g)=>{
  const [a,m,gg] = g.split('-').map(Number);
  return new Date(a, m-1, gg).toLocaleDateString('it-IT',{day:'2-digit',month:'short'});
};

/** Anello: fette proporzionali disegnate come archi SVG. */
function anello(voci, dimensione=180){
  const totale = voci.reduce((t,v)=>t+v.valore,0);
  if(!totale) return '<div style="color:var(--grigio);font-size:13px">Nessun dato.</div>';
  const r = dimensione/2, raggio = r-6, spessore = 26;
  let angolo = -Math.PI/2, archi = '';
  voci.forEach(v=>{
    if(!v.valore) return;
    const delta = (v.valore/totale)*Math.PI*2;
    const fine = angolo+delta;
    const punto = (ang,rr)=>[r+rr*Math.cos(ang), r+rr*Math.sin(ang)];
    const [x1,y1] = punto(angolo, raggio), [x2,y2] = punto(fine, raggio);
    const [x3,y3] = punto(fine, raggio-spessore), [x4,y4] = punto(angolo, raggio-spessore);
    const grande = delta > Math.PI ? 1 : 0;
    archi += \`<path d="M\${x1} \${y1} A\${raggio} \${raggio} 0 \${grande} 1 \${x2} \${y2}
                       L\${x3} \${y3} A\${raggio-spessore} \${raggio-spessore} 0 \${grande} 0 \${x4} \${y4} Z"
                    fill="\${v.colore}"><title>\${v.etichetta}: \${v.valore}</title></path>\`;
    angolo = fine;
  });
  const legenda = voci.filter(v=>v.valore).map(v=>\`
    <div style="display:flex;align-items:center;gap:8px;margin-bottom:7px;font-size:13px">
      <span style="width:11px;height:11px;border-radius:3px;background:\${v.colore};flex:none"></span>
      <span style="flex:1">\${v.etichetta}</span>
      <b>\${v.valore}</b>
      <span style="color:var(--grigio);width:44px;text-align:right">\${Math.round(v.valore/totale*100)}%</span>
    </div>\`).join('');
  return \`<div style="display:flex;gap:22px;align-items:center;flex-wrap:wrap">
    <svg viewBox="0 0 \${dimensione} \${dimensione}" style="width:\${dimensione}px;height:\${dimensione}px;flex:none">
      \${archi}
      <text x="\${r}" y="\${r-2}" text-anchor="middle" style="font:600 26px var(--display);fill:var(--inchiostro)">\${totale}</text>
      <text x="\${r}" y="\${r+16}" text-anchor="middle" style="font:500 11px var(--testo);fill:var(--grigio);text-transform:uppercase">totale</text>
    </svg>
    <div style="flex:1;min-width:180px">\${legenda}</div>
  </div>\`;
}

/** Barre orizzontali, per classifiche tipo aree o autori. */
function barre(voci){
  if(!voci.length) return '<div style="color:var(--grigio);font-size:13px">Nessun dato.</div>';
  const massimo = Math.max(...voci.map(v=>v.valore));
  return voci.map(v=>\`
    <div style="margin-bottom:11px">
      <div style="display:flex;font-size:13px;margin-bottom:4px">
        <span style="flex:1;word-break:break-word">\${v.etichetta}</span><b>\${v.valore}</b></div>
      <div style="height:8px;background:#EDEFF3;border-radius:4px;overflow:hidden">
        <div style="height:100%;width:\${Math.round(v.valore/massimo*100)}%;background:\${v.colore||'var(--rosso)'};border-radius:4px"></div>
      </div>
    </div>\`).join('');
}

/**
 * Riconduce il testo salvato nel campo "area" alla voce del menu da cui è nato.
 * Il wizard salva "Fatturazione" (voce scelta), "Fatturazione → dettaglio" (voce + testo
 * libero) o un testo interamente libero se l'utente ha scelto "Altro". Per il report serve
 * la categoria, non la frase intera: qui si prende la parte prima della freccia e, se non
 * corrisponde a nessuna voce nota del menu, finisce sotto "Altro".
 */
function categoriaArea(valoreArea){
  if(!valoreArea) return 'Altro';
  const base = valoreArea.split(' → ')[0].trim();
  const nomiNoti = S.aree.map(a=>a.name);
  return nomiNoti.includes(base) ? base : 'Altro';
}

function raggruppaPerCategoriaArea(ticket){
  const map = {};
  ticket.forEach(t=>{ const k = categoriaArea(t.area); map[k] = (map[k]||0)+1; });
  return Object.entries(map).map(([chiave,valore])=>({chiave,valore})).sort((a,b)=>b.valore-a.valore);
}

/** Andamento mensile: colonne affiancate bug/CR con media di riferimento. */
/** Andamento mensile: una linea per i bug, una per le Change Request. */
/** Curva morbida (Catmull-Rom -> Bezier) attraverso una serie di punti [x,y]. */
function curvaMorbida(punti){
  if(!punti.length) return '';
  if(punti.length===1) return \`M\${punti[0][0].toFixed(1)} \${punti[0][1].toFixed(1)}\`;
  if(punti.length===2) return \`M\${punti[0][0].toFixed(1)} \${punti[0][1].toFixed(1)} L\${punti[1][0].toFixed(1)} \${punti[1][1].toFixed(1)}\`;
  let d = \`M\${punti[0][0].toFixed(1)} \${punti[0][1].toFixed(1)}\`;
  for(let i=0;i<punti.length-1;i++){
    const p0 = punti[Math.max(0,i-1)], p1 = punti[i], p2 = punti[i+1], p3 = punti[Math.min(punti.length-1,i+2)];
    const c1x = p1[0] + (p2[0]-p0[0])/6, c1y = p1[1] + (p2[1]-p0[1])/6;
    const c2x = p2[0] - (p3[0]-p1[0])/6, c2y = p2[1] - (p3[1]-p1[1])/6;
    d += \` C\${c1x.toFixed(1)} \${c1y.toFixed(1)} \${c2x.toFixed(1)} \${c2y.toFixed(1)} \${p2[0].toFixed(1)} \${p2[1].toFixed(1)}\`;
  }
  return d;
}

/** Andamento mensile in stile "grafico di borsa": curva morbida, piccola, con area sfumata. */
function andamentoGiornaliero(giorni){
  if(!giorni.length) return '<div style="color:var(--grigio);font-size:13px">Nessun dato.</div>';
  const L=760, H=96, sotto=20, sinistra=26;
  const massimo = Math.max(1, ...giorni.map(g=>Math.max(g.bug, g.cr)));
  const passo = (L-sinistra)/giorni.length;
  const y = (v)=> (H-sotto) - (v/massimo)*(H-sotto-10);
  const x = (i)=> sinistra + passo*i + passo/2;
  const base = y(0);

  const puntiSerie = (chiave)=> giorni.map((g,i)=>[x(i), y(g[chiave])]);
  const linea = (chiave)=> curvaMorbida(puntiSerie(chiave));
  const area = (chiave, idGrad)=>{
    const p = puntiSerie(chiave);
    return \`<path d="\${linea(chiave)} L\${p[p.length-1][0].toFixed(1)} \${base.toFixed(1)} L\${p[0][0].toFixed(1)} \${base.toFixed(1)} Z" fill="url(#\${idGrad})" stroke="none"/>\`;
  };
  // con tanti giorni i pallini diventano solo rumore: li mostro solo su periodi corti
  const puntini = (chiave, colore, etichetta)=>
    giorni.length>62 ? '' : giorni.map((g,i)=>\`<circle cx="\${x(i).toFixed(1)}" cy="\${y(g[chiave]).toFixed(1)}" r="2.5" fill="\${colore}">
      <title>\${nomeGiorno(g.giorno)}: \${g[chiave]} \${etichetta}</title></circle>\`).join('');

  // etichette diradate in automatico: punto a circa 10-12 etichette visibili, qualunque sia il periodo
  const passoEtichette = Math.max(1, Math.ceil(giorni.length/12));
  let etichette = '';
  giorni.forEach((g,i)=>{
    if(i % passoEtichette === 0)
      etichette += \`<text x="\${x(i).toFixed(1)}" y="\${H-6}" text-anchor="middle"
                      style="font:500 10px var(--testo);fill:var(--grigio)">\${nomeGiorno(g.giorno)}</text>\`;
  });

  return \`<svg viewBox="0 0 \${L} \${H}" style="width:100%;height:auto">
    <defs>
      <linearGradient id="gCr" x1="0" y1="0" x2="0" y2="1">
        <stop offset="0%" stop-color="#4A5568" stop-opacity=".22"/>
        <stop offset="100%" stop-color="#4A5568" stop-opacity="0"/>
      </linearGradient>
      <linearGradient id="gBug" x1="0" y1="0" x2="0" y2="1">
        <stop offset="0%" stop-color="var(--rosso)" stop-opacity=".22"/>
        <stop offset="100%" stop-color="var(--rosso)" stop-opacity="0"/>
      </linearGradient>
    </defs>
    <line x1="\${sinistra}" y1="\${base}" x2="\${L}" y2="\${base}" stroke="#EEF1F5"/>
    \${area('cr','gCr')}\${area('bug','gBug')}
    <path d="\${linea('cr')}" fill="none" stroke="#4A5568" stroke-width="2" stroke-linejoin="round" stroke-linecap="round"/>
    <path d="\${linea('bug')}" fill="none" stroke="var(--rosso)" stroke-width="2" stroke-linejoin="round" stroke-linecap="round"/>
    \${puntini('cr','#4A5568','CR')}
    \${puntini('bug','var(--rosso)','bug')}
    \${etichette}
  </svg>

  <div style="display:flex;gap:18px;font-size:13px;margin-top:6px">
    <span style="display:flex;align-items:center;gap:7px"><span style="width:16px;height:3px;border-radius:2px;background:var(--rosso)"></span>Bug</span>
    <span style="display:flex;align-items:center;gap:7px"><span style="width:16px;height:3px;border-radius:2px;background:#4A5568"></span>Change Request</span>
  </div>\`;
}

function disegnaReport(){
  const giorni = Number($('#r-periodo').value);
  const soglia = giorni ? new Date(Date.now()-giorni*86400000).toISOString().slice(0,10) : '0000-00-00';
  const dati = S.tickets.filter(t=>t.created_at.slice(0,10) >= soglia);

  if(!dati.length){
    $('#report-corpo').innerHTML = '<div class="scheda"><p style="color:var(--grigio);margin:0">Nessuna segnalazione nel periodo scelto.</p></div>';
    return;
  }

  // --- indicatori ---
  const aperte = dati.filter(t=>['nuovo','preso_in_carico','aperto','approvato','sospesa'].includes(t.status)).length;
  const daValutare = dati.filter(t=>t.status==='nuovo'||t.status==='preso_in_carico').length;
  const inLavorazione = dati.filter(t=>t.status==='approvato').length;
  const risolte = dati.filter(t=>t.status==='risolto').length;
  // "chiuse" = quelle con un esito definitivo, quindi risolte o respinte
  const chiuse = dati.filter(t=>t.status==='risolto'||t.status==='respinto');
  const presiInCarico = dati.filter(t=>t.status_at && t.status!=='nuovo');
  const mediaPresa = presiInCarico.length
    ? presiInCarico.reduce((t,x)=>t+giorniFra(x.created_at,x.status_at),0)/presiInCarico.length : null;
  const mediaChiusura = chiuse.length
    ? chiuse.reduce((t,x)=>t+giorniFra(x.created_at,x.status_at||x.updated_at),0)/chiuse.length : null;

  const primaData = dati.reduce((m,t)=>t.created_at<m?t.created_at:m, dati[0].created_at);
  const settimane = Math.max(1, giorniFra(primaData, new Date().toISOString().slice(0,19).replace('T',' '))/7);
  const perSettimana = dati.length/settimane;
  const tassoRifiuto = dati.length
    ? Math.round(dati.filter(t=>t.status==='respinto').length/dati.length*100) : 0;

  // --- serie giornaliera ---
  const mappaGiorni = {};
  dati.forEach(t=>{
    const g = giornoDi(t.created_at);
    mappaGiorni[g] = mappaGiorni[g] || {giorno:g, bug:0, cr:0};
    if(t.type==='CR') mappaGiorni[g].cr++; else mappaGiorni[g].bug++;
  });
  // riempio anche i giorni senza segnalazioni, altrimenti il grafico mente
  const chiaviG = Object.keys(mappaGiorni).sort();
  const serieGiorni = [];
  if(chiaviG.length){
    const cursore = new Date(chiaviG[0]+'T00:00:00Z');
    const fineIntervallo = new Date(chiaviG[chiaviG.length-1]+'T00:00:00Z');
    while(cursore <= fineIntervallo){
      const k = cursore.toISOString().slice(0,10);
      serieGiorni.push(mappaGiorni[k] || {giorno:k, bug:0, cr:0});
      cursore.setUTCDate(cursore.getUTCDate()+1);
    }
  }

  const conta = (chiave, ordine)=>{
    const map = {};
    dati.forEach(t=>{ const k = t[chiave]||'—'; map[k] = (map[k]||0)+1; });
    const voci = Object.entries(map).map(([k,v])=>({chiave:k, valore:v}));
    return ordine ? voci.sort((a,b)=>ordine.indexOf(a.chiave)-ordine.indexOf(b.chiave))
                  : voci.sort((a,b)=>b.valore-a.valore);
  };

  const perGravita = conta('severity',['bloccante','alta','media','bassa'])
    .map(v=>({etichetta:ET_GRAV[v.chiave]||v.chiave, valore:v.valore, colore:COLORI_GRAV[v.chiave]||'#C9CDD4'}));
  const perStato = conta('status',['nuovo','preso_in_carico','aperto','approvato','sospesa','risolto','respinto'])
    .map(v=>({etichetta:ET_STATO[v.chiave]||v.chiave, valore:v.valore, colore:COLORI_STATO[v.chiave]||'#C9CDD4'}));
  const perTipo = conta('type').map((v,i)=>({etichetta:v.chiave==='CR'?'Change Request':'Bug', valore:v.valore,
    colore:v.chiave==='CR'?'#4A5568':'#D4112D'}));
  const perArea = raggruppaPerCategoriaArea(dati).slice(0,8)
    .map((v,i)=>({etichetta:v.chiave, valore:v.valore, colore:COLORI_SERIE[i%COLORI_SERIE.length]}));
  const perAutore = conta('author_name').map((v,i)=>({etichetta:v.chiave, valore:v.valore, colore:COLORI_SERIE[i%COLORI_SERIE.length]}));

  const kpi = (etichetta, valore, nota)=>\`
    <div class="scheda" style="padding:16px 18px">
      <div style="font-family:var(--display);text-transform:uppercase;font-size:12px;letter-spacing:.06em;color:var(--grigio)">\${etichetta}</div>
      <div style="font-family:var(--display);font-size:34px;font-weight:700;line-height:1.15">\${valore}</div>
      <div style="color:var(--grigio);font-size:12.5px">\${nota}</div>
    </div>\`;

  $('#report-corpo').innerHTML = \`
    <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(178px,1fr));gap:14px;margin-bottom:20px">
      \${kpi('Segnalazioni', dati.length, \`\${perSettimana.toFixed(1)} a settimana in media\`)}
      \${kpi('Ancora aperte', aperte, \`\${daValutare} da valutare, \${inLavorazione} in lavorazione\`)}
      \${kpi('Risolte', risolte, \`\${dati.length?Math.round(risolte/dati.length*100):0}% del totale\`)}
      \${kpi('Presa in carico', mediaPresa===null?'—':mediaPresa.toFixed(1)+' gg', 'dall’apertura al primo intervento')}
      \${kpi('Chiusura', mediaChiusura===null?'—':mediaChiusura.toFixed(1)+' gg', 'dall’apertura a risolta o respinta')}
      \${kpi('Respinte', tassoRifiuto+'%', 'sul totale delle segnalazioni')}
    </div>

    <div class="scheda" style="margin-bottom:20px">
      <h3>Aperture per giorno</h3>
      \${andamentoGiornaliero(serieGiorni)}
    </div>

    <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(330px,1fr));gap:20px">
      <div class="scheda"><h3>Per gravità</h3>\${anello(perGravita)}</div>
      <div class="scheda"><h3>Per stato</h3>\${anello(perStato)}</div>
      <div class="scheda"><h3>Bug e Change Request</h3>\${anello(perTipo)}</div>
      <div class="scheda"><h3>Aree più colpite</h3>\${barre(perArea)}</div>
      <div class="scheda"><h3>Chi apre le segnalazioni</h3>\${barre(perAutore)}</div>
    </div>\`;
}

/* ============================================================
   Export
   ============================================================ */
function colonne(t){
  return {
    'Codice':t.code||'', 'Tipo':t.type, 'Titolo':t.title, 'Area':t.area||'', 'Tag':t.tag||'',
    'Operazione':t.operation||'', 'N. documento':t.doc_number||'',
    'Errore riscontrato':t.error_text||'', 'Messaggio a video':t.no_error_message?'No':'Sì',
    'Su Sebach Pro':ET_PRO[t.pro_check]||'', 'Gravità':ET_GRAV[t.severity]||'',
    'Stato':ET_STATO[t.status]||'', 'ID DevOps':t.devops_id||'',
    'Motivo rifiuto':t.reject_reason||'', 'Aperto da':t.author_name,
    'Data apertura':dataOraIt(t.created_at), 'Ultimo aggiornamento':dataOraIt(t.updated_at)
  };
}
const oggi = ()=>new Date().toISOString().slice(0,10);

function scarica(nome, contenuto, mime){
  const blob = contenuto instanceof Blob ? contenuto : new Blob([contenuto],{type:mime});
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob); a.download = nome; a.click();
  setTimeout(()=>URL.revokeObjectURL(a.href), 2000);
}

function versoCsv(righe, sep=';'){
  if(!righe.length) return '';
  const intest = Object.keys(righe[0]);
  const cella = v=>{
    const s = String(v??'');
    // le virgolette servono solo se il valore contiene il separatore, virgolette o un a-capo:
    // un numero nudo (es. una priority) resta senza, così un importatore
    // esterno lo legge come numero e non come testo
    const serve = s.includes(sep) || s.includes('"') || s.includes('\\n') || s.includes('\\r');
    return serve ? \`"\${s.replace(/"/g,'""')}"\` : s;
  };
  return '\\uFEFF' + [intest.join(sep), ...righe.map(r=>intest.map(k=>cella(r[k])).join(sep))].join('\\r\\n');
}

$('#btn-csv').onclick = ()=>{
  const righe = filtrati().map(colonne);
  if(!righe.length) return toast('Non c’è niente da esportare con questi filtri.', true);
  scarica(\`segnalazioni-sebachplus-\${oggi()}.csv\`, versoCsv(righe), 'text/csv;charset=utf-8');
};

$('#btn-xlsx').onclick = async ()=>{
  const righe = filtrati().map(colonne);
  if(!righe.length) return toast('Non c’è niente da esportare con questi filtri.', true);
  try{
    if(!window.XLSX){
      await new Promise((ok,ko)=>{
        const s=document.createElement('script');
        s.src='https://cdn.sheetjs.com/xlsx-0.20.3/package/dist/xlsx.full.min.js';
        s.onload=ok; s.onerror=ko; document.head.appendChild(s);
      });
    }
    const ws = XLSX.utils.json_to_sheet(righe);
    ws['!cols'] = Object.keys(righe[0]).map(k=>({wch: Math.min(50, Math.max(k.length+2, 16))}));
    const wb = XLSX.utils.book_new();
    XLSX.utils.book_append_sheet(wb, ws, 'Segnalazioni');
    XLSX.writeFile(wb, \`segnalazioni-sebachplus-\${oggi()}.xlsx\`);
  }catch(e){
    toast('XLSX non disponibile (libreria non raggiungibile), scarico il CSV.', true);
    scarica(\`segnalazioni-sebachplus-\${oggi()}.csv\`, versoCsv(righe), 'text/csv;charset=utf-8');
  }
};

$('#btn-devops').onclick = ()=>{
  const sel = filtrati().filter(t=>t.status==='nuovo'||t.status==='preso_in_carico');
  if(!sel.length) return toast('Non ci sono segnalazioni Nuove da esportare con questi filtri.', true);
  const mappa = {};
  S.severitySettings.forEach(r=>{ mappa[r.severity] = r; });
  const righe = sel.map(t=>{
    const forzato = !!t.devops_override && t.devops_priority && t.devops_severity;
    const m = mappa[t.severity];
    return {
      'Work Item Type': t.type==='CR' ? 'User Story' : 'Bug',
      'Title': \`[\${t.code}] \${t.title}\`,
      'Repro Steps': descrizioneCompleta({
        area:t.area, operation:t.operation, doc_number:t.doc_number,
        error_text:t.error_text, no_error_message:t.no_error_message, pro_check:t.pro_check
      }).replace(/\\n/g,'<br>'),
      'priority': forzato ? t.devops_priority : (m?.priority ?? 3),
      'severity': forzato ? t.devops_severity : (m?.csv_severity ?? '3 - Medium'),
      'Story Points': ''
    };
  });
  scarica(\`Upload_Devops_\${oggi()}.csv\`, versoCsv(righe, ','), 'text/csv;charset=utf-8');
};

/* ============================================================
   Import ID DevOps: legge il CSV esportato da Azure DevOps dopo
   l'import, riconosce il codice dal titolo ([BUG-0007] ...) e
   abbina l'ID reale alla segnalazione corrispondente.
   ============================================================ */

/** Parser CSV minimale ma corretto: gestisce virgolette, virgole e a-capo dentro i campi. */
function analizzaCsv(testo){
  const righe = []; let riga = [], campo = '', dentro = false;
  for(let i=0;i<testo.length;i++){
    const c = testo[i];
    if(dentro){
      if(c==='"'){ if(testo[i+1]==='"'){ campo+='"'; i++; } else dentro=false; }
      else campo += c;
    } else if(c==='"') dentro = true;
    else if(c===','){ riga.push(campo); campo=''; }
    else if(c==='\\r'){ /* ignorato, gestito da \\n */ }
    else if(c==='\\n'){ riga.push(campo); righe.push(riga); riga=[]; campo=''; }
    else campo += c;
  }
  if(campo.length || riga.length){ riga.push(campo); righe.push(riga); }
  if(!righe.length) return [];
  const intestazioni = righe[0].map(h=>h.trim());
  return righe.slice(1)
    .filter(r=>r.some(v=>v.trim()!==''))
    .map(r=>{ const o={}; intestazioni.forEach((h,i)=>o[h]=(r[i]??'').trim()); return o; });
}

function leggiTestoFile(file){
  return new Promise((ok,ko)=>{
    const r = new FileReader();
    r.onload = ()=>ok(String(r.result));
    r.onerror = ()=>ko(new Error('Non riesco a leggere il file.'));
    r.readAsText(file, 'utf-8');
  });
}

function esitoRigaImport(r){
  if(!r.ticket) return {testo:'Non trovata tra le segnalazioni', azione:null};
  if(!r.id) return {testo:'Riga senza ID DevOps', azione:null};
  if(r.ticket.devops_id){
    return { testo: r.ticket.devops_id===r.id ? 'Già aggiornata' : 'Ha già un altro ID: non toccata', azione:null };
  }
  if(r.ticket.status==='nuovo'||r.ticket.status==='preso_in_carico') return {testo:'Verrà aperta con questo ID', azione:'apri'};
  return {testo:'ID assegnato (stato invariato)', azione:'patch'};
}

$('#btn-importa-devops').onclick = ()=> $('#imp-devops-file').click();
$('#imp-devops-file').onchange = async ()=>{
  const file = $('#imp-devops-file').files[0];
  $('#imp-devops-file').value = '';
  if(!file) return;
  let testo;
  try{ testo = await leggiTestoFile(file); }
  catch(e){ return toast(e.message, true); }
  if(testo.charCodeAt(0)===0xFEFF) testo = testo.slice(1);

  const righeCsv = analizzaCsv(testo);
  if(!righeCsv.length) return toast('Il file sembra vuoto o non leggibile.', true);

  const intestazioni = Object.keys(righeCsv[0]);
  const colId = intestazioni.find(h=>h.trim().toLowerCase()==='id')
             || intestazioni.find(h=>h.trim().toLowerCase()==='work item id');
  const colTitle = intestazioni.find(h=>h.trim().toLowerCase()==='title');
  if(!colId || !colTitle)
    return toast('Il CSV deve avere le colonne «ID» e «Title»: esportalo da Azure DevOps così com\\u2019è.', true);

  const risultati = righeCsv.map(r=>{
    const titolo = r[colTitle] || '';
    const id = (r[colId]||'').trim();
    const m = titolo.match(/^\\[(BUG|CR)-(\\d+)\\]/i);
    const codice = m ? \`\${m[1].toUpperCase()}-\${m[2]}\` : null;
    const ticket = codice ? S.tickets.find(t=>t.code && t.code.toUpperCase()===codice) : null;
    return { titolo, id, codice, ticket };
  }).filter(r=>r.codice);

  if(!risultati.length)
    return toast('Nessuna riga con un titolo che inizia per «[BUG-…]» o «[CR-…]».', true);

  apriAnteprimaImportDevops(risultati);
};

function apriAnteprimaImportDevops(risultati){
  const conAzione = risultati.filter(r=>esitoRigaImport(r).azione);
  $('#wizard-host').innerHTML = \`
  <div class="modale" id="imp-devops-velo">
    <div style="background:#fff;border-radius:14px;width:min(680px,100%);padding:26px;max-height:90vh;display:flex;flex-direction:column">
      <div style="display:flex;align-items:center;margin-bottom:6px">
        <h3 class="disp" style="font-size:22px;text-transform:uppercase">Importa ID DevOps</h3>
        <button class="chiudi" id="imp-devops-chiudi" style="margin-left:auto">×</button>
      </div>
      <p style="color:var(--grigio);font-size:13px;margin:0 0 14px">
        \${risultati.length} righe con un codice riconoscibile, \${conAzione.length} da aggiornare.
      </p>
      <div style="overflow:auto;border:1px solid var(--bordo);border-radius:10px;flex:1">
        <table style="width:100%;border-collapse:collapse;font-size:13px">
          <thead><tr style="background:#F8FAFC">
            <th style="padding:8px 10px;text-align:left;cursor:default">Codice</th>
            <th style="padding:8px 10px;text-align:left;cursor:default">ID DevOps</th>
            <th style="padding:8px 10px;text-align:left;cursor:default">Esito</th>
          </tr></thead>
          <tbody>\${risultati.map(r=>{
            const e = esitoRigaImport(r);
            return \`<tr style="border-top:1px solid #EEF2F6">
              <td class="codice" style="padding:7px 10px">\${esc(r.codice)}</td>
              <td class="codice" style="padding:7px 10px">\${esc(r.id)||'—'}</td>
              <td style="padding:7px 10px;\${e.azione?'':'color:var(--grigio)'}">\${e.testo}</td>
            </tr>\`;
          }).join('')}</tbody>
        </table>
      </div>
      <div class="errore" id="imp-devops-err"></div>
      <div style="display:flex;gap:8px;margin-top:16px">
        <button class="btn" id="imp-devops-annulla" style="flex:1">Annulla</button>
        <button class="btn primario" id="imp-devops-conferma" style="flex:1" \${conAzione.length?'':'disabled'}>
          Conferma import\${conAzione.length?\` (\${conAzione.length})\`:''}</button>
      </div>
    </div>
  </div>\`;

  const chiudi = ()=>{ $('#wizard-host').innerHTML=''; };
  $('#imp-devops-chiudi').onclick = chiudi;
  $('#imp-devops-annulla').onclick = chiudi;
  $('#imp-devops-velo').onclick = (e)=>{ if(e.target.id==='imp-devops-velo') chiudi(); };

  $('#imp-devops-conferma').onclick = async ()=>{
    $('#imp-devops-err').textContent = '';
    $('#imp-devops-conferma').disabled = true;
    let aperti=0, aggiornati=0, falliti=0;
    for(const r of risultati){
      const e = esitoRigaImport(r);
      if(!e.azione) continue;
      try{
        if(e.azione==='apri'){
          await api(\`/tickets/\${r.ticket.id}/status\`,{method:'POST',body:{status:'aperto', devops_id:r.id}});
          aperti++;
        } else {
          await api(\`/tickets/\${r.ticket.id}\`,{method:'PATCH',body:{devops_id:r.id}});
          aggiornati++;
        }
      }catch(err){ falliti++; }
    }
    chiudi();
    const pezzi = [];
    if(aperti) pezzi.push(\`\${aperti} portate in Aperto\`);
    if(aggiornati) pezzi.push(\`\${aggiornati} con l\\u2019ID assegnato\`);
    if(falliti) pezzi.push(\`\${falliti} non riuscite\`);
    toast(pezzi.length ? pezzi.join(', ')+'.' : 'Niente da aggiornare.', falliti>0);
    await caricaTicket();
  };
}

/* ============================================================
   Segna come risolti in blocco, incollando gli ID DevOps
   ricevuti via mail una volta passati in produzione.
   ============================================================ */
function apriRisolviDaDevops(){
  $('#wizard-host').innerHTML = \`
  <div class="modale" id="rv-velo">
    <div style="background:#fff;border-radius:14px;width:min(560px,100%);padding:26px;max-height:90vh;overflow:auto">
      <div style="display:flex;align-items:center;margin-bottom:6px">
        <h3 class="disp" style="font-size:22px;text-transform:uppercase">Segna risolti da DevOps</h3>
        <button class="chiudi" id="rv-chiudi">×</button>
      </div>
      <p style="color:var(--grigio);font-size:13px;margin:0 0 14px">
        Incolla qui l'elenco degli ID DevOps passati in produzione, così come li hai ricevuti —
        uno per riga, separati da virgole, o l'intero testo della mail: i numeri vengono riconosciuti da soli.
      </p>
      <textarea id="rv-testo" style="min-height:140px" placeholder="es. 13205, 13210, 13226&#10;oppure uno per riga"></textarea>
      <div class="errore" id="rv-err"></div>
      <div style="display:flex;gap:8px;margin-top:14px">
        <button class="btn" id="rv-annulla" style="flex:1">Annulla</button>
        <button class="btn primario" id="rv-continua" style="flex:1">Continua</button>
      </div>
    </div>
  </div>\`;
  const chiudi = ()=>{ $('#wizard-host').innerHTML=''; };
  $('#rv-chiudi').onclick = chiudi;
  $('#rv-annulla').onclick = chiudi;
  $('#rv-velo').onclick = (e)=>{ if(e.target.id==='rv-velo') chiudi(); };
  $('#rv-testo').focus();

  $('#rv-continua').onclick = ()=>{
    const testo = $('#rv-testo').value;
    const id_trovati = [...new Set((testo.match(/\\d{4,}/g)||[]))];
    if(!id_trovati.length){ $('#rv-err').textContent = 'Non trovo nessun numero nel testo incollato.'; return; }

    const risultati = id_trovati.map(id=>{
      const ticket = S.tickets.find(t=>t.devops_id === id);
      return { id, ticket };
    });
    apriAnteprimaRisolviDevops(risultati);
  };
}

function esitoRigaRisolvi(r){
  if(!r.ticket) return {testo:'Nessuna segnalazione con questo ID', azione:false};
  if(r.ticket.status==='risolto') return {testo:'Già risolta', azione:false};
  if(r.ticket.status==='respinto') return {testo:'Era stata respinta: da controllare a mano', azione:false};
  return {testo:\`Verrà segnata come risolta (oggi: \${ET_STATO[r.ticket.status]})\`, azione:true};
}

function apriAnteprimaRisolviDevops(risultati){
  const conAzione = risultati.filter(r=>esitoRigaRisolvi(r).azione);
  $('#wizard-host').innerHTML = \`
  <div class="modale" id="rv-velo">
    <div style="background:#fff;border-radius:14px;width:min(640px,100%);padding:26px;max-height:90vh;display:flex;flex-direction:column">
      <div style="display:flex;align-items:center;margin-bottom:6px">
        <h3 class="disp" style="font-size:22px;text-transform:uppercase">Segna risolti da DevOps</h3>
        <button class="chiudi" id="rv-chiudi">×</button>
      </div>
      <p style="color:var(--grigio);font-size:13px;margin:0 0 14px">
        \${risultati.length} ID riconosciuti, \${conAzione.length} da segnare come risolte.
      </p>
      <div style="overflow:auto;border:1px solid var(--bordo);border-radius:10px;flex:1">
        <table style="width:100%;border-collapse:collapse;font-size:13px">
          <thead><tr style="background:#F8FAFC">
            <th style="padding:8px 10px;text-align:left;cursor:default">ID DevOps</th>
            <th style="padding:8px 10px;text-align:left;cursor:default">Segnalazione</th>
            <th style="padding:8px 10px;text-align:left;cursor:default">Esito</th>
          </tr></thead>
          <tbody>\${risultati.map(r=>{
            const e = esitoRigaRisolvi(r);
            return \`<tr style="border-top:1px solid #EEF2F6">
              <td class="codice" style="padding:7px 10px">\${esc(r.id)}</td>
              <td style="padding:7px 10px">\${r.ticket ? \`<span class="codice">\${esc(r.ticket.code)}</span> \${esc(r.ticket.title)}\` : '—'}</td>
              <td style="padding:7px 10px;\${e.azione?'':'color:var(--grigio)'}">\${e.testo}</td>
            </tr>\`;
          }).join('')}</tbody>
        </table>
      </div>
      <div class="errore" id="rv-err"></div>
      <div style="display:flex;gap:8px;margin-top:16px">
        <button class="btn" id="rv-indietro" style="flex:1">Indietro</button>
        <button class="btn primario" id="rv-conferma" style="flex:1" \${conAzione.length?'':'disabled'}>
          Conferma\${conAzione.length?\` (\${conAzione.length})\`:''}</button>
      </div>
    </div>
  </div>\`;

  const chiudi = ()=>{ $('#wizard-host').innerHTML=''; };
  $('#rv-chiudi').onclick = chiudi;
  $('#rv-indietro').onclick = apriRisolviDaDevops;
  $('#rv-velo').onclick = (e)=>{ if(e.target.id==='rv-velo') chiudi(); };

  $('#rv-conferma').onclick = async ()=>{
    $('#rv-err').textContent = '';
    $('#rv-conferma').disabled = true;
    let risolte=0, falliti=0;
    for(const r of risultati){
      if(!esitoRigaRisolvi(r).azione) continue;
      try{
        await api(\`/tickets/\${r.ticket.id}/status\`,{method:'POST',body:{status:'risolto'}});
        risolte++;
      }catch(err){ falliti++; }
    }
    chiudi();
    const pezzi = [];
    if(risolte) pezzi.push(\`\${risolte} segnate come risolte\`);
    if(falliti) pezzi.push(\`\${falliti} non riuscite\`);
    toast(pezzi.length ? pezzi.join(', ')+'.' : 'Niente da aggiornare.', falliti>0);
    await caricaTicket();
  };
}

$('#btn-risolvi-devops').onclick = apriRisolviDaDevops;

/* ============================================================
   Bootstrap
   ============================================================ */
(async function(){
  try{
    S.me = await api('/auth/me');
    if(S.me.must_change_password) mostraCambioPwd(); else await avvia();
  }catch(e){ mostraLogin(); }
})();
</script>
</body>
</html>
`;

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    if (url.pathname.startsWith('/api/')) {
      try {
        return await handleApi(request, env, url);
      } catch (err) {
        console.error(err);
        return fail('Errore interno: ' + err.message, 500);
      }
    }
    return new Response(PAGINA, {
      headers: {
        'content-type': 'text/html; charset=utf-8',
        'cache-control': 'no-store',
      },
    });
  },
};
