import {defineConfig} from '@playwright/test';

export default defineConfig({
  testDir:'./tests',
  testMatch:'**/public-privacy.spec.js',
  outputDir:'./test-results/public-checks',
  workers:1,
  timeout:30000,
  use:{baseURL:'http://127.0.0.1:8789',viewport:{width:1440,height:1000},trace:'retain-on-failure'},
  webServer:{
    command:'go run ./cmd/underdog serve',
    url:'http://127.0.0.1:8789/api/health',
    reuseExistingServer:false,
    timeout:120000,
    env:{IDENTITYSHIELD_ADDR:'127.0.0.1:8789',IDENTITYSHIELD_DATA_DIR:'./test-results/public-checks/workspace',IDENTITYSHIELD_DEMO:'true',IDENTITYSHIELD_AI_PROVIDER:'local',UNDERDOG_AI_BACKEND:'direct',IDENTITYSHIELD_ACCESS_TOKEN:'private-research-test-token',IDENTITYSHIELD_PUBLIC_ACCESS:'true',AGENT_ROUTER_API_KEY:'',UNDERDOG_WORKER_TOKEN:'',DATABASE_URL:'',VERCEL:''},
  },
});
