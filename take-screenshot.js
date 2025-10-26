const puppeteer = require('puppeteer');
const path = require('path');

async function takeScreenshots() {
  console.log('Launching browser...');
  const browser = await puppeteer.launch({
    headless: 'new',
    args: ['--no-sandbox', '--disable-setuid-sandbox']
  });

  const page = await browser.newPage();
  await page.setViewport({ width: 1920, height: 1080 });

  try {
    // Main application page
    console.log('Taking main application screenshot...');
    await page.goto('http://localhost:3000', { waitUntil: 'networkidle2', timeout: 30000 });
    await page.waitForTimeout(2000);
    await page.screenshot({ 
      path: path.join(__dirname, 'docs/images/main-app.png'),
      fullPage: false 
    });
    console.log('✅ Main app screenshot saved');

    // Try to click on tabs and take more screenshots
    // Search tab
    const searchTab = await page.$('#tabSearch');
    if (searchTab) {
      await searchTab.click();
      await page.waitForTimeout(1000);
      await page.screenshot({ 
        path: path.join(__dirname, 'docs/images/search-tab.png'),
        fullPage: false 
      });
      console.log('✅ Search tab screenshot saved');
    }

    // Alerts tab
    const alertsTab = await page.$('#tabAlerts');
    if (alertsTab) {
      await alertsTab.click();
      await page.waitForTimeout(1000);
      await page.screenshot({ 
        path: path.join(__dirname, 'docs/images/alerts-tab.png'),
        fullPage: false 
      });
      console.log('✅ Alerts tab screenshot saved');
    }

    // 3D View tab
    const tab3D = await page.$('#tab3D');
    if (tab3D) {
      await tab3D.click();
      await page.waitForTimeout(1000);
      await page.screenshot({ 
        path: path.join(__dirname, 'docs/images/3d-view-tab.png'),
        fullPage: false 
      });
      console.log('✅ 3D View tab screenshot saved');
    }

    // Collaboration tab
    const collabTab = await page.$('#tabCollab');
    if (collabTab) {
      await collabTab.click();
      await page.waitForTimeout(1000);
      await page.screenshot({ 
        path: path.join(__dirname, 'docs/images/collaboration-tab.png'),
        fullPage: false 
      });
      console.log('✅ Collaboration tab screenshot saved');
    }

    // Take a full page screenshot
    const analysisTab = await page.$('#tabAnalysis');
    if (analysisTab) {
      await analysisTab.click();
      await page.waitForTimeout(1000);
    }
    await page.screenshot({ 
      path: path.join(__dirname, 'docs/images/screenshot.png'),
      fullPage: true 
    });
    console.log('✅ Full page screenshot saved');

  } catch (error) {
    console.error('Error taking screenshot:', error);
  } finally {
    await browser.close();
    console.log('Browser closed');
  }
}

takeScreenshots().catch(console.error);