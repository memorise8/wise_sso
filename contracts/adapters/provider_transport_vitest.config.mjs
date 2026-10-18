export default {
  test: {
    exclude: ["auth-server/dist/**", "**/node_modules/**"],
    setupFiles: ["auth-server/vitest.setup.ts"]
  }
};
