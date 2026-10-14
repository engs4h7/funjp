'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

const html = fs.readFileSync(path.join(__dirname, '../public/index.html'), 'utf8');

test('frontend has no unresolved merge conflict markers', () => {
  assert.doesNotMatch(html, /^(?:<<<<<<<|=======|>>>>>>>)/m);
});

test('frontend contains one complete document with unique element IDs', () => {
  assert.match(html, /^<!DOCTYPE html>/i);
  for (const tag of ['html', 'head', 'body']) {
    assert.equal([...html.matchAll(new RegExp(`<${tag}\\b`, 'gi'))].length, 1);
    assert.equal([...html.matchAll(new RegExp(`</${tag}>`, 'gi'))].length, 1);
  }
  const markup = html.replace(/<script\b[^>]*>[\s\S]*?<\/script>/gi, '');
  const identifiers = [...markup.matchAll(/\bid="([^"]+)"/g)].map(match => match[1]);
  assert.ok(identifiers.length > 0);
  assert.equal(new Set(identifiers).size, identifiers.length);
  for (const identifier of ['themeBtn', 'authBar', 'authBtn']) {
    assert.ok(identifiers.includes(identifier));
  }
});

test('frontend inline JavaScript parses without syntax errors', () => {
  const scripts = [...html.matchAll(/<script\b[^>]*>([\s\S]*?)<\/script>/gi)]
    .map(match => match[1]).filter(source => source.trim());
  assert.ok(scripts.length > 0);
  for (const source of scripts) {
    assert.doesNotThrow(() => new vm.Script(source, { filename: 'public/index.html' }));
  }
});
