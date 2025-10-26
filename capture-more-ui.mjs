import { chromium } from 'playwright';

async function captureMoreScreenshots() {
  const browser = await chromium.launch({ headless: true });
  const context = await browser.newContext({
    viewport: { width: 1920, height: 1080 },
    deviceScaleFactor: 1,
  });
  const page = await context.newPage();

  const baseUrl = 'http://localhost:3000';
  
  try {
    console.log('Navigating to application...');
    await page.goto(baseUrl, { waitUntil: 'networkidle', timeout: 30000 });
    await page.waitForTimeout(2000);
    
    // 1. Click on Search tab and capture
    console.log('Capturing search tab...');
    await page.click('button:has-text("Search")');
    await page.waitForTimeout(1000);
    await page.screenshot({ 
      path: 'docs/images/modern-ui-search.png',
      fullPage: false
    });
    
    // 2. Click on Alerts tab and capture
    console.log('Capturing alerts tab...');
    await page.click('button:has-text("Alerts")');
    await page.waitForTimeout(1000);
    await page.screenshot({ 
      path: 'docs/images/modern-ui-alerts.png',
      fullPage: false
    });
    
    // 3. Capture just the tab navigation
    console.log('Capturing tab navigation...');
    await page.click('button:has-text("Analysis")');
    await page.waitForTimeout(500);
    await page.screenshot({ 
      path: 'docs/images/modern-ui-tabs.png',
      fullPage: false,
      clip: { x: 300, y: 140, width: 1320, height: 120 }
    });
    
    // 4. Capture the upload panel close-up
    console.log('Capturing upload panel...');
    await page.screenshot({ 
      path: 'docs/images/modern-ui-upload.png',
      fullPage: false,
      clip: { x: 50, y: 280, width: 900, height: 400 }
    });
    
    // 5. Capture History tab
    console.log('Capturing history tab...');
    await page.click('button:has-text("History")');
    await page.waitForTimeout(1000);
    await page.screenshot({ 
      path: 'docs/images/modern-ui-history.png',
      fullPage: false
    });
    
    // 6. Capture full page overview
    console.log('Capturing full overview...');
    await page.screenshot({ 
      path: 'docs/images/modern-ui-overview.png',
      fullPage: true
    });
    
    console.log('Additional screenshots captured successfully!');
    
  } catch (error) {
    console.error('Error capturing screenshots:', error);
  } finally {
    await browser.close();
  }
}

captureMoreScreenshots();