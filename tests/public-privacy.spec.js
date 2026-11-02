import {test,expect} from '@playwright/test';

test('public pages and API responses exclude research data and controls',async({page,request})=>{
  const errors=[];page.on('pageerror',error=>errors.push(error.message));
  await page.goto('/');
  await expect(page.getByRole('heading',{name:'Security, in context.'})).toBeVisible();
  await expect(page.getByRole('link',{name:'Datasets',exact:true})).toHaveCount(0);
  await expect(page.getByRole('link',{name:'Research',exact:true})).toHaveCount(0);
  await expect(page.locator('[data-action=import],[data-action=replay],.model-mini,.activity-list')).toHaveCount(0);
  const state=await(await request.get('/api/state')).json();
  expect(state.research_access).toBe(false);
  for(const key of ['datasets','catalog','models','scenarios','kaggle_configured'])expect(state).not.toHaveProperty(key);
  for(const path of ['/datasets','/research'])expect((await request.get(path)).status()).toBe(404);
  for(const path of ['/api/events','/api/export/events','/api/export/model/authentication','/api/datasets/kaggle/files'])expect((await request.get(path)).status()).toBe(401);
  for(const path of ['/investigations','/identity','/rules']){
    await page.goto(path);
    await expect(page.locator('#main .view')).toBeVisible();
    await expect(page.locator('[data-action=replay],[data-action=evidence],[data-action=export-snapshot],[data-action=import-snapshot],[data-toggle-rule]')).toHaveCount(0);
  }
  await page.getByRole('button',{name:'Search workspace',exact:true}).click();
  await page.getByRole('textbox',{name:'Search workspace commands'}).fill('datasets');
  await expect(page.locator('#command-results [data-route]')).toHaveCount(0);
  await page.keyboard.press('Escape');
  await page.getByRole('button',{name:'Workspace settings',exact:true}).click();
  await expect(page.locator('dialog')).not.toContainText('Kaggle');
  expect(errors).toEqual([]);
});

test('public investigations keep citations without exposing raw records or collection labels',async({page,request})=>{
  await page.goto('/investigations');
  await page.getByRole('searchbox',{name:'Search investigations'}).fill('Encoded PowerShell');
  await page.getByRole('button',{name:'Open Encoded PowerShell execution for alex.rivera'}).click();
  await expect(page.getByRole('button',{name:'Copy evidence',exact:true})).toHaveCount(0);
  const id=(await page.locator('.case-id').innerText()).match(/CASE-[a-z0-9]+/)[0];
  const evidence=await(await request.get(`/api/incidents/${id}`)).json();
  for(const event of evidence.events){
    expect(event.id).toMatch(/^EVT-[a-f0-9]+$/);
    for(const key of ['source','dataset_id','run_id','label','raw','raw_sha256'])expect(event).not.toHaveProperty(key);
  }
  expect(evidence.incident).not.toHaveProperty('ground_truth');
  await page.getByRole('button',{name:'Save local brief',exact:true}).click();
  await expect(page.locator('#toast-root')).toContainText('Local evidence brief saved');
  const report=await(await request.get(`/api/incidents/${id}`)).json();
  const allowed=new Set(report.events.map(event=>event.id));
  expect(report.report.claims.every(claim=>claim.evidence_ids.every(id=>allowed.has(id)))).toBe(true);
  const exported=await request.get(`/api/export/report/${id}`);
  expect(exported.status()).toBe(200);
  expect(await exported.text()).not.toMatch(/LAB-showcase|northstar-lab/);
  await page.locator('[data-event]').first().click();
  await expect(page.locator('dialog')).not.toContainText('Preserved raw evidence');
  await expect(page.getByRole('button',{name:'Copy record',exact:true})).toHaveCount(0);
  await expect(page.getByRole('button',{name:'Review label',exact:true})).toHaveCount(0);
});
