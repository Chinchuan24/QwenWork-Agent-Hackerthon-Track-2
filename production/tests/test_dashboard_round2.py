"""Round-two checks against served assets and the isolated fake backend."""
import os
from pathlib import Path
import shutil
BROWSER_ENV = dict(os.environ)

NODE = shutil.which('node')
import subprocess
import unittest

from tests.test_dashboard_http import DashboardHTTPTests


class DashboardRound2Tests(DashboardHTTPTests):
    def test_round2_served_source(self):
        html = self.client.get('/dashboard').text
        js = self.client.get('/dashboard/assets/dashboard.js').text
        self.assertNotIn('Review the exact action', html)
        self.assertNotIn('approval-details', html + js)
        self.assertRegex(html, r'id="decision-input"[^>]*hidden')
        panel = html.split('id="approval-title"', 1)[1].split('</section>', 1)[0]
        for identifier in ('approval-heading', 'reason', 'approve', 'deny'):
            self.assertIn('id="' + identifier + '"', panel)
        self.assertNotIn('MutationObserver', js)
        self.assertEqual(js.count("make('pre'"), 1)
        self.assertIn("make('summary','View action details')", js)
        self.assertNotIn("detail.open", js)
        self.assertIn('Guard answer not available in this test run.', js)
        self.assertNotIn('No captured response or stored explanation available', js)
        self.assertNotIn('second opinion A', js)
        self.assertIn('New decisions were added. Check the record to verify them.', js)
        for text in ('Record intact', 'Tampering found', 'sealed_decisions', 'action-checked', 'guard-icon'):
            self.assertIn(text, js)
        self.assertNotIn('innerHTML', js)
        self.assertIn("'X-CSRF-Token':csrf", js)
        self.assertIn('prefers-reduced-motion: reduce', js)
        self.assertIn('Real-provider mode when available; otherwise labelled recorded mock runs.', html)
        subprocess.run([NODE, '--check', str(Path(__file__).resolve().parents[1] / 'aegis/assets/dashboard.js')], check=True)

    def test_plain_rule_browser_actual_fake_response(self):
        import json
        state = self.post('start', task='invoices').json()
        self.post('advance', task_id=state['id'])
        state = self.post('advance', task_id=state['id']).json()
        html = self.client.get('/dashboard').text
        js = self.client.get('/dashboard/assets/dashboard.js').text
        css = self.client.get('/dashboard/assets/dashboard.css').text
        self.assertNotIn('without a plain-language reason', js)
        script = r"""
const {chromium}=require(process.env.PW_MODULE);
(async()=>{
 const input=JSON.parse(require('fs').readFileSync(0,'utf8'));
 const browser=await chromium.launch({headless:true});
 const page=await browser.newPage({viewport:{width:1440,height:1000}});
 await page.route('**/*',async route=>{
  const url=route.request().url();
  if(url.endsWith('dashboard.js'))return route.fulfill({contentType:'text/javascript',body:input.js});
  if(url.endsWith('dashboard.css'))return route.fulfill({contentType:'text/css',body:input.css});
  if(url.includes('/live-product/'))return route.fulfill({json:input.state});
  if(url.endsWith('/dashboard'))return route.fulfill({contentType:'text/html',body:input.html});
  return route.abort();
 });
 await page.goto('http://fake.test/dashboard');
 await page.locator('[data-task="invoices"]').click();
 await page.waitForSelector('.action');
 const cards=page.locator('.action');
 const read=await cards.nth(0).innerText(),held=await cards.nth(1).innerText();
 const assert=require('assert');
 assert(read.includes('Aegis: Safe. Reading is part of task.'));
 assert(read.includes('Delta: Safe. Nothing leaves sandbox.'));
 assert(!read.includes('Guard answer not available in this test run.'));
  for(const width of [1440,1024,390]){
   await page.setViewportSize({width,height:1000});
   await page.waitForTimeout(400);
   const boxes=await page.locator('#chain .record-link').evaluateAll(els=>els.map(el=>{const r=el.getBoundingClientRect(),h=el.querySelector('.seal-hash').getBoundingClientRect();return {x:r.x,y:r.y,width:r.width,height:r.height,hashRight:h.right,right:r.right};}));
  assert.strictEqual(boxes.length,2);
   for(const b of boxes){assert.strictEqual(b.width,156);assert(b.hashRight<=b.right);assert(b.x>=0&&b.right<=width);}
   for(let i=0;i<boxes.length;i++)for(let j=i+1;j<boxes.length;j++){
    const a=boxes[i],b=boxes[j];assert(a.x+a.width+11.9<=b.x||b.x+b.width+11.9<=a.x||a.y+a.height+11.9<=b.y||b.y+b.height+11.9<=a.y);
   }
   console.log(JSON.stringify({viewport:width,boxes}));
  }
 assert.strictEqual(await page.locator('#rail-aegis').innerText(),'Safe, needs your OK');
 assert.strictEqual(await page.locator('#rail-delta').innerText(),'Safe, needs your OK');
 for(const name of ['Aegis','Delta'])assert(held.includes(name+': Safe, but deleting needs your OK.'));
 assert(held.includes('File rule: Deleting a file needs your OK.'));
 assert(!/R01|R16|AI-SECOND|without a plain-language reason/.test(read+held));
 assert.strictEqual(await page.locator('details[open]').count(),0);
 if(process.env.DASHBOARD_SCREENSHOT)await page.screenshot({path:process.env.DASHBOARD_SCREENSHOT,fullPage:true});
 input.state.actions[0].judges=[];
 input.state.actions[1].explanations=[];
 await page.reload();await page.locator('[data-task="invoices"]').click();await page.waitForSelector('.action');
  const missing=await page.locator('.action').nth(0).innerText();
 assert(missing.includes('Guard answer not available in this test run.'));
 assert(missing.includes('The file rule allowed this read; live guard answers are not available in this test run.'));
 const unknown=await page.locator('.action').nth(1).innerText();
 assert(unknown.includes('Aegis: Safe, but this action needs your OK. Safe.'));assert(!unknown.includes('file rule still needs'));
 assert(!unknown.includes('File rule:'));
 await browser.close();
})().catch(e=>{console.error(e);process.exit(1)});
"""
        subprocess.run([NODE, '-e', script], input=json.dumps(
            dict(state=state, html=html, js=js, css=css)), text=True, check=True,
            env=BROWSER_ENV)

    def test_round2_pending_binding_and_record(self):
        state = self.post('start', task='invoices').json()
        sid = state['id']
        self.post('advance', task_id=sid)
        state = self.post('advance', task_id=sid).json()
        held = next(a for a in state['actions'] if state['pending'] in (a.get('id'), a.get('approval_id')))
        self.assertEqual(held['args']['doc_id'], 'march-duplicate.txt')
        self.assertEqual(held['verdict'], 'hold')
        reason = 'Keep this exact fictional duplicate; reviewed.'
        state = self.post('approval', task_id=sid, action_id=state['pending'], approved=False, reason=reason).json()
        self.assertIsNone(state['pending'])
        self.assertEqual(state['outside_effects'], 0)
        self.assertTrue(self.post('verify', task_id=sid).json()['ok'])


if __name__ == '__main__':
    unittest.main()
