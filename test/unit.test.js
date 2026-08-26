const { csvCell, csvRow } = require('../lib/csv');
const plans = require('../lib/plans');

describe('csv', () => {
  it('prefixes formula-trigger cells with a quote', () => {
    expect(csvCell('=SUM(1)')).toBe('"\'=SUM(1)"');
    expect(csvCell('+1')).toBe('"\'+1"');
    expect(csvCell('-2')).toBe('"\'-2"');
    expect(csvCell('@x')).toBe('"\'@x"');
  });

  it('leaves ordinary text alone', () => {
    expect(csvCell('hello')).toBe('"hello"');
  });

  it('escapes embedded double quotes', () => {
    expect(csvCell('a"b')).toBe('"a""b"');
  });

  it('handles null/undefined', () => {
    expect(csvCell(null)).toBe('""');
    expect(csvCell(undefined)).toBe('""');
  });

  it('joins a row', () => {
    expect(csvRow(['a', 1, '=b'])).toBe('"a","1","\'=b"');
  });
});

describe('plans', () => {
  it('returns known plan limits', () => {
    expect(plans.limitGB('Pro')).toBe(200);
    expect(plans.limitGB('Growth')).toBe(50);
    expect(plans.limitBytes('Starter')).toBe(10 * 1024 ** 3);
  });

  it('falls back for unknown plans', () => {
    expect(plans.limitGB('Nonexistent')).toBe(10);
  });
});
