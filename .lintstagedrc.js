export default {
  'src/**/*.ts': [
    'eslint --max-warnings=0',
    'prettier --check',
    () => 'tsc --noEmit', // Project-wide type check (ignores file list)
  ],
  '*.{json,md}': 'prettier --check',
};
