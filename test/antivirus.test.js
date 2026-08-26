const { resetDb, registerAndLogin, uploadFile } = require('./helpers');
const av = require('../lib/antivirus');

beforeEach(() => resetDb());

describe('malware scanning', () => {
  it('is skipped (and uploads succeed) when AV is disabled', async () => {
    expect(av.avEnabled()).toBe(false); // default off in test env
    const result = await av.scanFile('/nonexistent/file');
    expect(result.skipped).toBe(true);
    expect(result.clean).toBe(true);

    const { token } = await registerAndLogin({ email: 'av-off@test.com' });
    const up = await uploadFile(token);
    expect(up.status).toBe(201);
  });

  it('fails closed: blocks the upload when AV is enabled but the scanner is unreachable', async () => {
    process.env.AV_ENABLED = 'true';
    process.env.CLAMD_PORT = '65500'; // nothing is listening here
    try {
      const { token } = await registerAndLogin({ email: 'av-fail@test.com' });
      const up = await uploadFile(token);
      expect(up.status).toBe(503);
      expect(up.body.code).toBe('SCAN_UNAVAILABLE');
    } finally {
      delete process.env.AV_ENABLED;
      delete process.env.CLAMD_PORT;
    }
  });
});
