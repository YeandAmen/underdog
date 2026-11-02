import {defineConfig} from '@playwright/test';

export default defineConfig({
  testDir: './tests',
  testIgnore: '**/public-privacy.spec.js',
  outputDir:'./test-results/private-checks',
  fullyParallel: false,
  workers: 1,
  timeout: 30000,
  use: {baseURL:'http://127.0.0.1:8788', viewport:{width:1440,height:1000}, trace:'retain-on-failure'},
  webServer: {
    command:'go run ./cmd/identityshield serve',
    url:'http://127.0.0.1:8788/api/health',
    reuseExistingServer:false,
    timeout:120000,
    env:{IDENTITYSHIELD_ADDR:'127.0.0.1:8788',IDENTITYSHIELD_DATA_DIR:'./test-results/private-checks/workspace',IDENTITYSHIELD_DEMO:'true',IDENTITYSHIELD_AI_PROVIDER:'local',IDENTITYSHIELD_ACCESS_TOKEN:'',IDENTITYSHIELD_PUBLIC_ACCESS:'false',DATABASE_URL:'',VERCEL:''},
  },
});
