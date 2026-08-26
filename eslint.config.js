const js = require('@eslint/js');
const globals = require('globals');
const prettier = require('eslint-config-prettier');

module.exports = [
  // Lint the server-side code only; the static front-end has its own browser
  // globals and conventions and isn't worth linting under the Node config.
  {
    ignores: [
      'node_modules/**',
      'public/**',
      'backups/**',
      'uploads/**',
      'logs/**',
      'coverage/**',
      'test/.uploads/**',
      'db/*.db*',
    ],
  },
  js.configs.recommended,
  {
    files: ['**/*.js'],
    languageOptions: {
      ecmaVersion: 2023,
      sourceType: 'commonjs',
      globals: { ...globals.node },
    },
    rules: {
      'no-unused-vars': ['warn', { argsIgnorePattern: '^_', varsIgnorePattern: '^_' }],
      'no-empty': ['warn', { allowEmptyCatch: true }],
    },
  },
  {
    // Test files use Vitest globals (globals: true in vitest.config).
    files: ['test/**/*.js'],
    languageOptions: {
      globals: { ...globals.node, ...globals.vitest },
    },
  },
  prettier,
];
