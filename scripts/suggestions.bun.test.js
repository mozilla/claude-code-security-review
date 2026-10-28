#!/usr/bin/env bun

/**
 * Unit tests for suggestions.js using Bun test runner
 */

import { test, expect, describe } from "bun:test";
const { addedLines, planSuggestions, suggestionBlock, findingId, findingMarker } = require('./suggestions');

// Patch as /pulls/{n}/files returns it: lines 11-13 of src/app.py are context,
// 14-18 are added; line 17 is the vulnerable execute() call.
const PATCH = [
  '@@ -11,3 +11,9 @@ def get_db():',
  '     return sqlite3.connect("app.db")',
  ' ',
  ' ',
  '+@app.get("/users/search")',
  '+def search_users():',
  '+    name = request.args.get("name", "")',
  '+    rows = get_db().execute("SELECT id, name FROM users WHERE name = \'" + name + "\'").fetchall()',
  '+    return jsonify([{"id": row[0], "name": row[1]} for row in rows])',
].join('\n');
const FILE_MAP = { 'src/app.py': { filename: 'src/app.py', patch: PATCH } };
const FIXED = '    rows = get_db().execute("SELECT id, name FROM users WHERE name = ?", (name,)).fetchall()';

function finding(overrides = {}) {
  return {
    file: 'src/app.py',
    line: 17,
    category: 'sql_injection',
    suggested_fix: { start_line: 17, end_line: 17, replacement: FIXED },
    ...overrides,
  };
}

describe('addedLines', () => {
  test('numbers only added lines, as in the PR head', () => {
    const added = addedLines(PATCH);
    expect([...added.keys()]).toEqual([14, 15, 16, 17, 18]);
    expect(added.get(14)).toBe('@app.get("/users/search")');
  });

  test('a "+++ " line inside a hunk is an added line, not a header', () => {
    const added = addedLines('@@ -1 +1,2 @@\n context\n+++ counter');
    expect(added.get(2)).toBe('++ counter');
  });

  test('missing patch', () => {
    expect(addedLines(undefined).size).toBe(0);
  });
});

describe('planSuggestions', () => {
  const sqlFinding = finding;

  test('single-line fix on an added line', () => {
    const plan = planSuggestions([sqlFinding()], FILE_MAP);
    expect(plan.get(0)).toEqual({ start: 17, end: 17, block: '```suggestion\n' + FIXED + '\n```' });
  });

  test('multi-line fix', () => {
    const replacement = '    name = request.args.get("name", "")\n' + FIXED;
    const plan = planSuggestions([sqlFinding({ suggested_fix: { start_line: 16, end_line: 17, replacement } })], FILE_MAP);
    expect(plan.get(0).start).toBe(16);
    expect(plan.get(0).end).toBe(17);
    expect(plan.get(0).block).toBe('```suggestion\n' + replacement + '\n```');
  });

  test('trailing newline and CRLF are normalised', () => {
    const plan = planSuggestions([sqlFinding({ suggested_fix: { start_line: 17, end_line: 17, replacement: FIXED + '\r\n' } })], FILE_MAP);
    expect(plan.get(0).block).toBe('```suggestion\n' + FIXED + '\n```');
  });

  test.each([
    ['no fix', { suggested_fix: undefined }],
    ['range includes a context line', { suggested_fix: { start_line: 12, end_line: 17, replacement: FIXED } }],
    ['range past the added lines', { suggested_fix: { start_line: 17, end_line: 19, replacement: FIXED } }],
    ['range does not cover the finding line', { line: 15, suggested_fix: { start_line: 17, end_line: 17, replacement: FIXED } }],
    ['end before start', { suggested_fix: { start_line: 17, end_line: 16, replacement: FIXED } }],
    ['non-integer lines', { suggested_fix: { start_line: '17', end_line: 17, replacement: FIXED } }],
    ['empty replacement', { suggested_fix: { start_line: 17, end_line: 17, replacement: '  \n' } }],
    ['replacement is not a string', { suggested_fix: { start_line: 17, end_line: 17, replacement: 42 } }],
    ['unchanged code', { suggested_fix: { start_line: 17, end_line: 17, replacement: addedLines(PATCH).get(17) } }],
    ['file not in the PR', { file: 'other.py' }],
  ])('no suggestion: %s', (_, overrides) => {
    expect(planSuggestions([sqlFinding(overrides)], FILE_MAP).size).toBe(0);
  });

  test('overlapping findings in the same file get no suggestion', () => {
    const other = { file: 'src/app.py', line: 17, category: 'xss' };
    const plan = planSuggestions([sqlFinding(), other], FILE_MAP);
    expect(plan.size).toBe(0);
  });

  test('a finding on another line or file does not block the suggestion', () => {
    const elsewhere = [{ file: 'src/app.py', line: 18, category: 'xss' }, { file: 'other.py', line: 17 }];
    const plan = planSuggestions([sqlFinding(), ...elsewhere], FILE_MAP);
    expect([...plan.keys()]).toEqual([0]);
  });
});

describe('suggestionBlock', () => {
  test('fence is longer than any backtick run in the code', () => {
    expect(suggestionBlock('a = `x`')).toBe('```suggestion\na = `x`\n```');
    expect(suggestionBlock('s = """```"""')).toBe('````suggestion\ns = """```"""\n````');
  });
});

describe('findingId and findingMarker', () => {
  test('ID depends on the code, not the line number', () => {
    const shifted = {
      'src/app.py': { patch: PATCH.replace('@@ -11,3 +11,9 @@', '@@ -16,3 +16,9 @@') },
    };
    expect(findingId(finding({ line: 17 }), FILE_MAP)).toBe(findingId(finding({ line: 22 }), shifted));
    expect(findingId(finding({ line: 17 }), FILE_MAP)).not.toBe(findingId(finding({ line: 16 }), FILE_MAP));
    expect(findingId(finding({ line: 17 }), FILE_MAP)).toMatch(/^[0-9a-f]{8}$/);
  });

  test('marker only carries safe characters', () => {
    const marker = findingMarker(finding({ line: 17, category: 'sql --> <b>x</b>' }), FILE_MAP, 'abc123 -->');
    expect(marker).toMatch(/^<!-- ai-security-review:finding id=[0-9a-f]{8} category=sqlbxb sha=abc123 -->$/);
    expect(marker.match(/-->/g)).toHaveLength(1);
  });
});
