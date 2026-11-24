import ts from "typescript-eslint";
export default ts.config(
  { ignores: ["dist/"] },
  { files: ["src/**/*.{ts,tsx}"], extends: ts.configs.recommended },
);
