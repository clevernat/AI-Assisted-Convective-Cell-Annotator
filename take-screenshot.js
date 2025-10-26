const { chromium } = require('playwright');

(async () => {
  const browser = await chromium.launch({
    headless: true,
    args: ['--no-sandbox', '--disable-setuid-sandbox']
  });
  
  const page = await browser.newPage();
  
  // Set viewport for a good desktop screenshot
  await page.setViewportSize({ width: 1920, height: 1080 });
  
  // Navigate to the application
  await page.goto('https://3000-iiqzr0hiif3i299iwltsl-b32ec7bb.sandbox.novita.ai', {
    waitUntil: 'networkidle'
  });
  
  // Wait for the main content to load
  await page.waitForSelector('#uploadForm', { timeout: 10000 });
  
  // Take a full page screenshot
  await page.screenshot({
    path: 'screenshot.png',
    fullPage: false
  });
  
  console.log('Screenshot saved as screenshot.png');
  
  // Also take a screenshot with some interaction
  // Click on the file input to show it's interactive
  await page.locator('#fileInput').focus();
  
  await page.screenshot({
    path: 'screenshot-full.png',
    fullPage: true
  });
  
  console.log('Full page screenshot saved as screenshot-full.png');
  
  await browser.close();
})();