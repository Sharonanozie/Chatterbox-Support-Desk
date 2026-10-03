// Chatterbox — public webpage evidence fetcher
// Includes basic SSRF protection, redirect validation, size limits and HTML text extraction.

const dns = require('node:dns/promises');
const net = require('node:net');

const MAX_BYTES = 800000;
const MAX_REDIRECTS = 3;
const TIMEOUT_MS = 10000;

function json(res, status, body) {
  res.status(status).setHeader(
    'Content-Type',
    'application/json; charset=utf-8'
  );
  res.setHeader('Cache-Control', 'no-store');
  return res.end(JSON.stringify(body));
}

function privateIp(ip) {
  const v = net.isIP(ip);

  if (v === 4) {
    const [a, b, c] = ip.split('.').map(Number);

    return (
      a === 10 ||
      a === 127 ||
      a === 0 ||
      a >= 224 ||
      (a === 169 && b === 254) ||
      (a === 172 && b >= 16 && b <= 31) ||
      (a === 192 && b === 168) ||
      (a === 100 && b >= 64 && b <= 127)
    );
  }

  if (v === 6) {
    const x = ip.toLowerCase();

    return (
      x === '::1' ||
      x === '::' ||
      x.startsWith('fc') ||
      x.startsWith('fd') ||
      x.startsWith('fe8') ||
      x.startsWith('fe9') ||
      x.startsWith('fea') ||
      x.startsWith('feb') ||
      x.startsWith('ff') ||
      x.startsWith('::ffff:10.') ||
      x.startsWith('::ffff:192.168.') ||
      x.startsWith('::ffff:127.') ||
      x.startsWith('::ffff:169.254.')
    );
  }

  return true;
}

async function assertPublicHost(url) {
  const u = new URL(url);

  if (!/^https?:$/.test(u.protocol)) {
    throw new Error('Only http and https links are allowed.');
  }

  if (u.username || u.password) {
    throw new Error(
      'Links containing usernames or passwords are not allowed.'
    );
  }

  const host = u.hostname.toLowerCase();

  if (
    host === 'localhost' ||
    host.endsWith('.localhost') ||
    host.endsWith('.local') ||
    host.endsWith('.internal') ||
    host === 'metadata.google.internal'
  ) {
    throw new Error('Private/local hosts are not allowed.');
  }

  if (net.isIP(host) && privateIp(host)) {
    throw new Error('Private IP addresses are not allowed.');
  }

  if (!net.isIP(host)) {
    const records = await dns.lookup(host, {
      all: true,
      verbatim: true
    });

    if (
      !records.length ||
      records.some(r => privateIp(r.address))
    ) {
      throw new Error(
        'The link resolves to a private or local network.'
      );
    }
  }

  return u;
}

async function readLimited(res) {
  const length = Number(
    res.headers.get('content-length') || 0
  );

  if (length && length > MAX_BYTES) {
    throw new Error('The webpage is too large to inspect.');
  }

  if (!res.body) return '';

  const reader = res.body.getReader();
  const chunks = [];
  let total = 0;

  while (true) {
    const { done, value } = await reader.read();

    if (done) break;

    total += value.byteLength;

    if (total > MAX_BYTES) {
      try {
        await reader.cancel();
      } catch {}

      throw new Error(
        'The webpage is too large to inspect.'
      );
    }

    chunks.push(value);
  }

  const all = new Uint8Array(total);

  let offset = 0;

  for (const c of chunks) {
    all.set(c, offset);
    offset += c.byteLength;
  }

  return new TextDecoder('utf-8', {
    fatal: false
  }).decode(all);
}

function decodeEntities(s) {
  return s
    .replace(/&nbsp;/gi, ' ')
    .replace(/&amp;/gi, '&')
    .replace(/&lt;/gi, '<')
    .replace(/&gt;/gi, '>')
    .replace(/&quot;/gi, '"')
    .replace(/&#39;/g, "'")
    .replace(
      /&#(\d+);/g,
      (_, n) => String.fromCharCode(Number(n))
    );
}

function extract(html, contentType) {
  if (contentType.includes('application/json')) {
    return {
      title: 'JSON response',
      text: html.slice(0, 120000)
    };
  }

  const title = decodeEntities(
    (
      html.match(
        /<title[^>]*>([\s\S]*?)<\/title>/i
      )?.[1] || ''
    )
      .replace(/<[^>]+>/g, ' ')
      .replace(/\s+/g, ' ')
      .trim()
  ).slice(0, 300);

  let text = html
    .replace(/<script[\s\S]*?<\/script>/gi, ' ')
    .replace(/<style[\s\S]*?<\/style>/gi, ' ')
    .replace(/<noscript[\s\S]*?<\/noscript>/gi, ' ')
    .replace(/<svg[\s\S]*?<\/svg>/gi, ' ')
    .replace(/<!--([\s\S]*?)-->/g, ' ')
    .replace(/<[^>]+>/g, ' ');

  text = decodeEntities(text)
    .replace(/\s+/g, ' ')
    .trim();

  return {
    title,
    text: text.slice(0, 120000)
  };
}

async function fetchPublic(url) {
  let current = await assertPublicHost(url);

  for (let i = 0; i <= MAX_REDIRECTS; i++) {
    const controller = new AbortController();

    const timer = setTimeout(
      () => controller.abort(),
      TIMEOUT_MS
    );

    let r;

    try {
      r = await fetch(current, {
        redirect: 'manual',
        signal: controller.signal,
        headers: {
          'User-Agent':
            'Chatterbox-Support-Desk/1.0 (+support diagnostics)'
        }
      });
    } finally {
      clearTimeout(timer);
    }

    if (r.status >= 300 && r.status < 400) {
      const loc = r.headers.get('location');

      if (!loc) {
        throw new Error(
          'The webpage returned a redirect without a destination.'
        );
      }

      if (i === MAX_REDIRECTS) {
        throw new Error('Too many redirects.');
      }

      current = await assertPublicHost(
        new URL(loc, current).href
      );

      continue;
    }

    if (!r.ok) {
      throw new Error(
        `The webpage returned HTTP ${r.status}.`
      );
    }

    const type = (
      r.headers.get('content-type') || ''
    ).toLowerCase();

    if (
      !/(text\/html|application\/xhtml\+xml|text\/plain|application\/json)/.test(
        type
      )
    ) {
      throw new Error(
        'That link does not return a readable webpage or text response.'
      );
    }

    const raw = await readLimited(r);

    return extract(raw, type);
  }

  throw new Error('Could not fetch the webpage.');
}

async function handler(req, res) {
  if (req.method !== 'POST') {
    return json(res, 405, {
      error: 'POST only.'
    });
  }

  try {
    const body =
      typeof req.body === 'string'
        ? JSON.parse(req.body)
        : req.body || {};

    const url = String(body.url || '').trim();

    if (!url) {
      return json(res, 400, {
        code: 'url',
        error: 'A URL is required.'
      });
    }

    const result = await fetchPublic(url);

    return json(res, 200, {
      ok: true,
      url,
      ...result
    });

  } catch (err) {
    const message =
      err?.name === 'AbortError'
        ? 'The webpage took too long to respond.'
        : (
            err?.message ||
            'Could not fetch the webpage.'
          );

    return json(res, 400, {
      code: 'url',
      error: message
    });
  }
}

module.exports = handler;
