const { breachCount, isBreached } = require('../lib/breachCheck');

// SHA-1('password') = 5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8
// → prefix 5BAA6, suffix 1E4C9B93F3F0682250B6CF8331B7EE68FD8
const PASSWORD_SUFFIX = '1E4C9B93F3F0682250B6CF8331B7EE68FD8';

describe('password breach check (HIBP k-anonymity)', () => {
  const realFetch = global.fetch;
  afterEach(() => { global.fetch = realFetch; });

  it('reports the breach count when the suffix is in the range', async () => {
    global.fetch = async () => ({ ok: true, text: async () => `${PASSWORD_SUFFIX}:42\r\nDEADBEEF:5` });
    expect(await breachCount('password')).toBe(42);
    expect(await isBreached('password')).toBe(42);
  });

  it('returns 0 / false for a password not in the range', async () => {
    global.fetch = async () => ({ ok: true, text: async () => 'FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF:1' });
    expect(await breachCount('password')).toBe(0);
    expect(await isBreached('password')).toBe(false);
  });

  it('fails open (returns null/false) when the API is unreachable', async () => {
    global.fetch = async () => { throw new Error('network down'); };
    expect(await breachCount('password')).toBe(null);
    expect(await isBreached('password')).toBe(false);
  });

  it('only sends the first 5 hash chars to the API (k-anonymity)', async () => {
    let requestedUrl = '';
    global.fetch = async (url) => { requestedUrl = url; return { ok: true, text: async () => '' }; };
    await breachCount('password');
    expect(requestedUrl).toBe('https://api.pwnedpasswords.com/range/5BAA6');
  });
});
