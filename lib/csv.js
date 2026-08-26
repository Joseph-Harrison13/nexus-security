// Safe CSV cell encoding.
//
// Spreadsheet apps (Excel/Sheets) execute a cell whose text begins with =, +, -,
// @ (or a leading tab/CR) as a formula — so attacker-controlled fields like a
// name or message can run code on whoever opens the export. We neutralize that by
// prefixing such cells with a single quote, then quote/escape normally.

function csvCell(value) {
  let s = value === null || value === undefined ? '' : String(value);
  if (/^[=+\-@\t\r]/.test(s)) s = `'${s}`;
  return `"${s.replace(/"/g, '""')}"`;
}

function csvRow(values) {
  return values.map(csvCell).join(',');
}

module.exports = { csvCell, csvRow };
