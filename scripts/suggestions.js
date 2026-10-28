/**
 * Committable fix suggestions and finding IDs for the PR review comments.
 */

const crypto = require('crypto');

// Lines a file's patch (from /pulls/{n}/files) adds, numbered as in the PR head:
// line number -> text. Hunks include context lines, so only "+" lines count.
function addedLines(patch) {
  const added = new Map();
  let newLine = null;
  for (const line of (patch || '').split('\n')) {
    if (line.startsWith('@@ ')) {
      const match = /^@@ -\S+ \+(\d+)/.exec(line);
      newLine = match ? parseInt(match[1], 10) : null;
    } else if (newLine !== null) {
      if (line.startsWith('+')) {
        added.set(newLine, line.slice(1).replace(/\r$/, ''));
        newLine++;
      } else if (line.startsWith(' ')) {
        newLine++;
      }
    }
  }
  return added;
}

function findingLine(finding) {
  return finding.line || (finding.start && finding.start.line) || 1;
}

function findingFile(finding) {
  return finding.file || finding.path;
}

// The fix's line range and replacement, or null if it is malformed.
function fixRange(finding) {
  const fix = finding.suggested_fix;
  if (!fix || typeof fix !== 'object' || typeof fix.replacement !== 'string') {
    return null;
  }
  const start = fix.start_line;
  const end = fix.end_line;
  if (!Number.isInteger(start) || !Number.isInteger(end) || start < 1 || end < start) {
    return null;
  }
  return { start, end, replacement: fix.replacement.replace(/\r\n/g, '\n').replace(/\n$/, '') };
}

// A fence longer than any run of backticks in the code, so it cannot close early.
function suggestionBlock(replacement) {
  const longestRun = Math.max(0, ...(replacement.match(/`+/g) || []).map(run => run.length));
  const fence = '`'.repeat(Math.max(3, longestRun + 1));
  return `${fence}suggestion\n${replacement}\n${fence}`;
}

/**
 * Decide which findings get a committable suggestion.
 *
 * A suggestion replaces exactly start_line..end_line, so it is only offered when
 * every line in that range is added by the PR, the range covers the finding's
 * line, the replacement changes something, and no other finding in the same
 * file overlaps the range (conflicting fixes).
 *
 * @param {Array} findings - findings from findings.json
 * @param {Object} fileMap - filename -> entry from /pulls/{n}/files
 * @returns {Map} finding index -> { start, end, block }
 */
function planSuggestions(findings, fileMap) {
  const spans = findings.map(finding => {
    const range = fixRange(finding);
    const line = findingLine(finding);
    return range ? [range.start, range.end] : [line, line];
  });

  const plan = new Map();
  findings.forEach((finding, index) => {
    const range = fixRange(finding);
    const file = fileMap[findingFile(finding)];
    if (!range || !file) {
      return;
    }
    const line = findingLine(finding);
    if (line < range.start || line > range.end) {
      return;
    }

    const added = addedLines(file.patch);
    const current = [];
    for (let n = range.start; n <= range.end; n++) {
      if (!added.has(n)) {
        return;
      }
      current.push(added.get(n));
    }
    if (range.replacement.trim() === '' || range.replacement === current.join('\n')) {
      return;
    }

    const overlaps = findings.some((other, otherIndex) =>
      otherIndex !== index &&
      findingFile(other) === findingFile(finding) &&
      spans[otherIndex][0] <= range.end && spans[otherIndex][1] >= range.start
    );
    if (overlaps) {
      return;
    }

    plan.set(index, { start: range.start, end: range.end, block: suggestionBlock(range.replacement) });
  });
  return plan;
}

// Stable ID for a finding: hashes the code, not the line number, so it survives
// unrelated lines being added above it.
function findingId(finding, fileMap) {
  const file = fileMap[findingFile(finding)];
  const code = (addedLines(file && file.patch).get(findingLine(finding)) || '').trim().replace(/\s+/g, ' ');
  return crypto.createHash('sha256')
    .update(`${findingFile(finding)}|${finding.category || ''}|${code}`)
    .digest('hex')
    .slice(0, 8);
}

// Hidden marker tying a comment to a finding, for later feedback tracking. The
// category comes from model output, so only safe characters go into the comment.
function findingMarker(finding, fileMap, sha) {
  const category = String(finding.category || 'security_issue').replace(/[^A-Za-z0-9_]/g, '');
  const commit = String(sha || '').replace(/[^0-9a-f]/gi, '');
  return `<!-- ai-security-review:finding id=${findingId(finding, fileMap)} category=${category} sha=${commit} -->`;
}

module.exports = { addedLines, planSuggestions, suggestionBlock, findingId, findingMarker };
