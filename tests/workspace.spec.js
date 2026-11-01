import {test,expect} from '@playwright/test';

test('overview uses real workspace counts, navigation, keyboard search, and persistent theme',async({page,request})=>{
  const errors=[];page.on('pageerror',error=>errors.push(error.message));
  await page.goto('/');
  await expect(page.getByRole('heading',{name:'Security, in context.'})).toBeVisible();
  const state=await (await request.get('/api/state')).json();
  await expect(page.locator('.metric').filter({hasText:'Evidence events'}).locator('.metric-value')).toHaveText(state.counts.events.toLocaleString());
  await page.getByRole('button',{name:'Toggle color theme'}).click();
  await expect(page.locator('html')).toHaveAttribute('data-theme','dark');
  await page.reload();await expect(page.locator('html')).toHaveAttribute('data-theme','dark');
  await expect(page.getByRole('heading',{name:'Security, in context.'})).toBeVisible();
  await page.keyboard.press('Control+k');
  await page.getByRole('textbox',{name:'Search workspace commands'}).fill('datasets');
  await page.keyboard.press('Enter');
  await expect(page.getByRole('heading',{name:'Give your models better context.'})).toBeVisible();
  expect(errors).toEqual([]);
});

test('permission path and read-only remediation preview explain their blast radius',async({page,request})=>{
  const before=await (await request.get('/api/state')).json();
  await page.goto('/identity');
  await expect(page.getByRole('heading',{name:'Know where privilege comes from.'})).toBeVisible();
  await expect(page.locator('.path-tags')).toContainText('GG_Helpdesk');
  await page.getByRole('button',{name:'Preview remediation impact'}).click();
  await expect(page.getByRole('heading',{name:'Understand the impact first.'})).toBeVisible();
  await expect(page.locator('dialog')).toContainText('maya.chen');
  await expect(page.locator('dialog')).toContainText('leo.martin');
  const after=await (await request.get('/api/state')).json();
  expect(after.snapshot).toEqual(before.snapshot);
});

test('scenario replay persists new evidence and actually changes detection results',async({page,request})=>{
  const before=await (await request.get('/api/state')).json();
  await page.goto('/');
  await page.getByRole('button',{name:'Replay lab',exact:true}).click();
  await page.locator('#replay-scenario').selectOption('password-spray');
  await page.getByRole('button',{name:'Replay scenario',exact:true}).click();
  await expect(page.locator('dialog')).toHaveCount(0);
  const after=await (await request.get('/api/state')).json();
  expect(after.counts.events).toBe(before.counts.events+16);
  expect(after.incidents.some(item=>item.rule_id==='IS-001')).toBe(true);
});

test('a benign case can produce a cited local brief, export, and a durable analyst review',async({page,request})=>{
  await page.goto('/investigations');
  await page.getByRole('searchbox',{name:'Search investigations'}).fill('Encoded PowerShell');
  await page.getByRole('button',{name:'Open Encoded PowerShell execution for alex.rivera'}).click();
  const footer=await page.locator('.investigation-footer').boundingBox();
  expect(footer.y+footer.height).toBeLessThanOrEqual(1000);
  await page.getByRole('button',{name:'Save local brief',exact:true}).click();
  await expect(page.getByRole('button',{name:'Export',exact:true})).toBeVisible();
  const [download]=await Promise.all([page.waitForEvent('download'),page.getByRole('button',{name:'Export',exact:true}).click()]);
  expect(download.suggestedFilename()).toContain('-report.md');
  await page.getByRole('button',{name:'Record verdict'}).click();
  await page.getByLabel('What supports this decision?').fill('CHG-2048 records an approved deployment; the encoded command is a controlled benign marker.');
  await page.getByRole('button',{name:'Save review',exact:true}).click();
  await expect(page.getByRole('heading',{name:'Encoded PowerShell execution',exact:true})).toBeVisible();
  const state=await (await request.get('/api/state')).json();
  expect(Object.values(state.reviews).some(review=>review.reason.includes('CHG-2048'))).toBe(true);
});

test('dataset import keeps unknown labels and renders untrusted event fields as text',async({page,request})=>{
  await page.goto('/datasets');
  await page.getByRole('button',{name:'Import evidence',exact:true}).click();
  const record={timestamp:'2026-11-01T12:34:56Z',kind:'process',actor:'<img src=x onerror="window.injected=true">',host:'fixture-host',label:'unknown',data:{command:'powershell.exe -EncodedCommand harmless-test-marker'}};
  await page.locator('#import-file').setInputFiles({name:'review-fixture.jsonl',mimeType:'application/x-ndjson',buffer:Buffer.from(JSON.stringify(record)+'\n')});
  await page.locator('dialog').getByRole('button',{name:'Import evidence',exact:true}).click();
  await expect(page.locator('dialog')).toHaveCount(0);
  await expect(page.getByRole('button',{name:/review-fixture.jsonl/})).toBeVisible();
  const state=await (await request.get('/api/state')).json();
  const dataset=state.datasets.find(item=>item.name==='review-fixture.jsonl');
  expect(dataset.unknown_count).toBe(1);
  expect(dataset.benign_count).toBe(0);
  await page.getByRole('link',{name:'Investigations',exact:true}).click();
  await page.getByRole('searchbox',{name:'Search investigations'}).fill('fixture-host');
  await expect(page.locator('.investigation-list img')).toHaveCount(0);
  await expect(page.locator('.investigation-list')).toContainText('<img src=x onerror="window.injected=true">');
  expect(await page.evaluate(()=>window.injected)).toBeUndefined();
});

test('training and rule toggles invoke the Go backend and retain measured results',async({page,request})=>{
  await page.goto('/research');
  await page.getByRole('button',{name:'Train & evaluate',exact:true}).click();
  await expect(page.locator('#toast-root')).toContainText('Forest trained');
  await expect(page.getByRole('heading',{name:'Isolation Forest',exact:true})).toBeVisible();
  const state=await (await request.get('/api/state')).json();
  expect(state.models.authentication.test_windows).toBeGreaterThan(0);
  await page.goto('/rules');
  await page.getByRole('switch',{name:'Enable Password spraying',exact:true}).click();
  await expect(page.getByRole('switch',{name:'Enable Password spraying',exact:true})).toHaveAttribute('aria-checked','false');
  await page.getByRole('switch',{name:'Enable Password spraying',exact:true}).click();
  await expect(page.getByRole('switch',{name:'Enable Password spraying',exact:true})).toHaveAttribute('aria-checked','true');
});

test('small-screen layout stays usable without horizontal document overflow',async({page})=>{
  await page.setViewportSize({width:390,height:844});
  await page.goto('/');
  await expect(page.getByRole('heading',{name:'Security, in context.'})).toBeVisible();
  expect(await page.evaluate(()=>document.documentElement.scrollWidth<=window.innerWidth)).toBe(true);
  await page.getByRole('link',{name:'Datasets',exact:true}).click();
  await expect(page.getByRole('heading',{name:'Give your models better context.'})).toBeVisible();
  expect(await page.evaluate(()=>document.documentElement.scrollWidth<=window.innerWidth)).toBe(true);
});
