import {test,expect} from '@playwright/test';

async function workerWorkspace(page) {
  await page.route('**/api/state',async route=>{
    const response=await route.fetch();
    const state=await response.json();
    state.ai={...state.ai,provider:'agentrouter',model:'gpt-6.1-sol',engine:'worker',configured:true,remote:true,worker:{online:true}};
    await route.fulfill({response,json:state});
  });
  await page.goto('/investigations');
  await page.getByRole('searchbox',{name:'Search investigations'}).fill('Encoded PowerShell');
  await page.getByRole('button',{name:'Open Encoded PowerShell execution for alex.rivera'}).click();
}

test('Generate follows a queued worker report through progress to cited output',async({page})=>{
  await workerWorkspace(page);
  const incidentID=await page.locator('.case-id').innerText();
  const id=incidentID.match(/CASE-[a-z0-9]+/)[0];
  const citation=await page.locator('.citation').first().getAttribute('data-citation');
  const job={id:'JOB-browser-fixture',incident_id:id,status:'queued',created_at:new Date().toISOString()};
  const report={incident_id:id,provider:'agentrouter',model:'gpt-6.1-sol',summary:'The selected event records encoded PowerShell activity.',verdict:'suspicious',claims:[{text:'The recorded process uses encoded PowerShell.',evidence_ids:[citation]}],next_steps:['Review the approved operator change.'],limitations:['The command alone does not establish compromise.']};
  let polls=0;
  await page.route(`**/api/incidents/${id}/report`,route=>route.fulfill({status:202,json:{job}}));
  await page.route('**/api/report-jobs/JOB-browser-fixture',route=>{
    polls++;
    return route.fulfill({json:polls===1?{job:{...job,status:'running'},worker:{online:true}}:{job:{...job,status:'succeeded'},report,worker:{online:true}}});
  });
  await page.getByRole('button',{name:'Generate AI report',exact:true}).click();
  await expect(page.locator('#report-message')).toContainText('Waiting for the project worker');
  await expect(page.locator('#report-message')).toContainText('Our model is analysing selected evidence');
  await expect(page.locator('#report-content .report-summary')).toHaveText(report.summary);
  await expect(page.locator('#report-content .report-status')).toHaveText('OUR MODEL');
  await expect(page.locator('#report-content .citation')).toHaveAttribute('data-citation',citation);
  await expect(page.getByRole('button',{name:'Generate AI report',exact:true})).toBeEnabled();
  await expect(page.locator('#report-message')).toBeEmpty();
  expect(polls).toBe(2);
});

test('an offline worker error preserves the existing evidence brief',async({page})=>{
  await workerWorkspace(page);
  const summary=await page.locator('#report-content .report-summary').innerText();
  await page.route('**/api/incidents/*/report',route=>route.fulfill({status:503,json:{error:'Our model worker is offline. Please retry when the project terminal reconnects.'}}));
  await page.getByRole('button',{name:'Generate AI report',exact:true}).click();
  await expect(page.locator('#report-message')).toContainText('Our model worker is offline');
  await expect(page.locator('#report-content .report-summary')).toHaveText(summary);
  await expect(page.getByRole('button',{name:'Generate AI report',exact:true})).toBeEnabled();
});
