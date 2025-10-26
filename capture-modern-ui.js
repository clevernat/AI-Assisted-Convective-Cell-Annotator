const { chromium } = require('playwright');

async function captureScreenshots() {
  const browser = await chromium.launch({ headless: true });
  const context = await browser.newContext({
    viewport: { width: 1920, height: 1080 },
    deviceScaleFactor: 1,
  });
  const page = await context.newPage();

  // Go to the application
  const baseUrl = 'http://localhost:3000';
  
  try {
    console.log('Navigating to application...');
    await page.goto(baseUrl, { waitUntil: 'networkidle', timeout: 30000 });
    
    // Wait for the page to fully load
    await page.waitForTimeout(3000);
    
    // 1. Capture main interface
    console.log('Capturing main interface...');
    await page.screenshot({ 
      path: 'docs/images/modern-ui-main.png',
      fullPage: false,
      clip: { x: 0, y: 0, width: 1920, height: 1080 }
    });
    
    // 2. Click on file input to simulate file selection (we'll just show the interface)
    console.log('Capturing variable selection area...');
    await page.screenshot({ 
      path: 'docs/images/modern-ui-variables.png',
      fullPage: false,
      clip: { x: 100, y: 200, width: 800, height: 600 }
    });
    
    // 3. Open login modal
    console.log('Opening login modal...');
    await page.click('button:has-text("Login")');
    await page.waitForTimeout(1000); // Wait for animation
    await page.screenshot({ 
      path: 'docs/images/modern-ui-login.png',
      fullPage: true
    });
    
    // Close login modal
    await page.click('button:has-text("Cancel")');
    await page.waitForTimeout(500);
    
    // 4. Open register modal
    console.log('Opening register modal...');
    await page.click('button:has-text("Register")');
    await page.waitForTimeout(1000); // Wait for animation
    await page.screenshot({ 
      path: 'docs/images/modern-ui-register.png',
      fullPage: true
    });
    
    // Close register modal
    await page.click('button:has-text("Cancel")');
    await page.waitForTimeout(500);
    
    // 5. Click on Search tab
    console.log('Capturing search tab...');
    await page.click('button:has-text("Search")');
    await page.waitForTimeout(500);
    await page.screenshot({ 
      path: 'docs/images/modern-ui-search.png',
      fullPage: false,
      clip: { x: 0, y: 200, width: 1920, height: 700 }
    });
    
    // 6. Capture tab navigation close-up
    console.log('Capturing tab navigation...');
    await page.click('button:has-text("Analysis")');
    await page.waitForTimeout(500);
    await page.screenshot({ 
      path: 'docs/images/modern-ui-tabs.png',
      fullPage: false,
      clip: { x: 300, y: 180, width: 1320, height: 100 }
    });
    
    // 7. Try to capture alerts tab
    console.log('Capturing alerts tab...');
    await page.click('button:has-text("Alerts")');
    await page.waitForTimeout(500);
    await page.screenshot({ 
      path: 'docs/images/modern-ui-alerts.png',
      fullPage: false,
      clip: { x: 0, y: 200, width: 1920, height: 700 }
    });
    
    // 8. Capture full page for overview
    console.log('Capturing full overview...');
    await page.click('button:has-text("Analysis")');
    await page.waitForTimeout(500);
    await page.screenshot({ 
      path: 'docs/images/modern-ui-overview.png',
      fullPage: true
    });
    
    console.log('All screenshots captured successfully!');
    
  } catch (error) {
    console.error('Error capturing screenshots:', error);
  } finally {
    await browser.close();
  }
}

captureScreenshots();