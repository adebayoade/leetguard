import eslint from '@eslint/js';
import tseslint from 'typescript-eslint';
import globals from 'globals';

const eslintConfig = [
  eslint.configs.recommended,
  ...tseslint.configs.recommended,
  {
    ignores: [
      'dist/**',
      'build/**',
      '.cache/**',
      '.tmp/**',
      'node_modules/**',
      '*.config.js',
      '*.config.mjs',
      'notes/**',
      'tests/fixtures/**',
    ],
  },
  {
    languageOptions: {
      ecmaVersion: 2022,
      sourceType: 'module',
      globals: { ...globals.node, ...globals.browser },
    },
    rules: {
      'no-console': 'off',
      '@typescript-eslint/no-explicit-any': 'error',
      '@typescript-eslint/no-unused-vars': 'error',
      '@typescript-eslint/no-require-imports': 'off',
    },
  },
];

export default eslintConfig;
