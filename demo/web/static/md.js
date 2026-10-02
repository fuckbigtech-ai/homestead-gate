// A small markdown renderer for text a model or an email wrote. It builds DOM nodes and sets text
// with createTextNode / textContent only; nothing is ever parsed as HTML. Supported: paragraphs and
// line breaks, # headings (shown as a bold line), - and 1. lists, > quotes, **bold**, *italic*,
// `code`. A link [text](url) is shown as plain text, "text (url)", never as a link.
"use strict";

function mdInline(parent, text, doc) {
  const re = /(\*\*([^*]+)\*\*|__([^_]+)__|`([^`]+)`|\*([^*\s](?:[^*]*[^*\s])?)\*|\[([^\]]+)\]\(([^)\s]+)\))/g;
  let last = 0;
  let m;
  while ((m = re.exec(text)) !== null) {
    if (m.index > last) parent.appendChild(doc.createTextNode(text.slice(last, m.index)));
    let node;
    if (m[2] !== undefined || m[3] !== undefined) {
      node = doc.createElement("strong");
      mdInline(node, m[2] !== undefined ? m[2] : m[3], doc);
    } else if (m[4] !== undefined) {
      node = doc.createElement("code");
      node.textContent = m[4];
    } else if (m[5] !== undefined) {
      node = doc.createElement("em");
      mdInline(node, m[5], doc);
    } else {
      node = doc.createTextNode(`${m[6]} (${m[7]})`);
    }
    parent.appendChild(node);
    last = re.lastIndex;
  }
  if (last < text.length) parent.appendChild(doc.createTextNode(text.slice(last)));
}

function renderMarkdown(text, doc) {
  doc = doc || document;
  const frag = doc.createDocumentFragment();
  const lines = String(text === undefined || text === null ? "" : text).replace(/\r\n?/g, "\n").split("\n");
  let para = null;
  let list = null;
  let quote = null;            // lines of a > quote, rendered as markdown of their own when it ends
  const endQuote = () => {
    if (!quote) return;
    const q = doc.createElement("blockquote");
    q.appendChild(renderMarkdown(quote.join("\n"), doc));
    frag.appendChild(q);
    quote = null;
  };
  const reset = () => { para = null; list = null; endQuote(); };
  for (const raw of lines) {
    const line = raw.replace(/\s+$/, "");
    let m;
    if ((m = line.match(/^>\s?(.*)$/))) {
      para = null; list = null;
      (quote = quote || []).push(m[1]);
      continue;
    }
    endQuote();
    if (!line.trim()) { reset(); continue; }
    if ((m = line.match(/^#{1,6}\s+(.*)$/))) {
      reset();
      const h = doc.createElement("div");
      h.className = "md-h";
      mdInline(h, m[1], doc);
      frag.appendChild(h);
      continue;
    }
    if ((m = line.match(/^\s*([-*+]|\d{1,3}[.)])\s+(.*)$/))) {
      const tag = /\d/.test(m[1]) ? "ol" : "ul";
      if (!list || list.tagName.toLowerCase() !== tag) {
        para = null; quote = null;
        list = doc.createElement(tag);
        frag.appendChild(list);
      }
      const li = doc.createElement("li");
      mdInline(li, m[2], doc);
      list.appendChild(li);
      continue;
    }
    if (list && /^\s{2,}\S/.test(raw) && list.lastChild) {      // a list item's next line
      list.lastChild.appendChild(doc.createElement("br"));
      mdInline(list.lastChild, line.trim(), doc);
      continue;
    }
    if (!para) {
      list = null; quote = null;
      para = doc.createElement("p");
      frag.appendChild(para);
    } else {
      para.appendChild(doc.createElement("br"));
    }
    mdInline(para, line, doc);
  }
  endQuote();
  return frag;
}

if (typeof module !== "undefined" && module.exports) module.exports = { renderMarkdown };
