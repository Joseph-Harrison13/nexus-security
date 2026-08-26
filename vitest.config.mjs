import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    // 'forks' runs each test file in a child process — safest for the native
    // better-sqlite3 addon, and gives each file its own fresh in-memory DB.
    pool: 'forks',
    // Expose describe/it/expect as globals so CommonJS test files don't need to
    // require('vitest') (which Vitest 4 disallows from CJS).
    globals: true,
    include: ['test/**/*.test.js'],
    env: {
      NODE_ENV: 'test',
      DB_PATH: ':memory:',
      UPLOADS_DIR: 'test/uploads',
      JWT_SECRET: 'test-secret-not-for-production-0123456789abcdef',
    },
  },
});
