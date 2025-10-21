import tseslint from '@typescript-eslint/eslint-plugin';
import tsparser from '@typescript-eslint/parser';

export default [
  {
    files: ['src/**/*.ts'],
    ignores: ['**/*.test.ts', 'dist/**', 'node_modules/**', 'coverage/**'],
    languageOptions: {
      parser: tsparser,
      parserOptions: {
        project: './tsconfig.json',
        ecmaVersion: 2022,
        sourceType: 'module',
      },
    },
    plugins: {
      '@typescript-eslint': tseslint,
    },
    rules: {
      // TypeScript recommended rules
      ...tseslint.configs.recommended.rules,

      // Enforce code quality standards from AGENT_DESIGN.md
      'max-lines-per-function': ['error', { max: 25, skipBlankLines: true, skipComments: true }],
      'max-lines': ['error', { max: 150, skipBlankLines: true, skipComments: true }],
      'complexity': ['error', 10],

      // Prevent common errors
      '@typescript-eslint/no-unused-vars': ['error', { argsIgnorePattern: '^_' }],
      '@typescript-eslint/no-explicit-any': 'error',
      '@typescript-eslint/explicit-function-return-type': ['error', { allowExpressions: true }],

      // Code style
      'no-console': 'warn',
      'prefer-const': 'error',
    },
  },
  {
    // Relaxed rules for test files (no type checking)
    files: ['**/*.test.ts'],
    languageOptions: {
      parser: tsparser,
      parserOptions: {
        ecmaVersion: 2022,
        sourceType: 'module',
      },
    },
    plugins: {
      '@typescript-eslint': tseslint,
    },
    rules: {
      ...tseslint.configs.recommended.rules,
      'max-lines-per-function': 'off', // Test functions can be longer
      '@typescript-eslint/no-explicit-any': 'off', // Allow any in tests for mocking
      '@typescript-eslint/explicit-function-return-type': 'off', // No return types required in tests
    },
  },
];
