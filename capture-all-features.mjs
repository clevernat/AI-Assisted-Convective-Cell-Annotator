import puppeteer from 'puppeteer';
import { mkdir } from 'fs/promises';

const APP_URL = 'https://3000-iiqzr0hiif3i299iwltsl-b32ec7bb.sandbox.novita.ai';

async function captureScreenshots() {
  // Create directory for images
  await mkdir('docs/images', { recursive: true });

  const browser = await puppeteer.launch({
    headless: 'new',
    args: ['--no-sandbox', '--disable-setuid-sandbox'],
    defaultViewport: { width: 1920, height: 1080 }
  });

  const page = await browser.newPage();

  console.log('Capturing main interface...');
  await page.goto(APP_URL, { waitUntil: 'networkidle2', timeout: 60000 });
  await new Promise(r => setTimeout(r, 2000));
  await page.screenshot({ path: 'docs/images/01-main-interface.png', fullPage: false });

  // Capture variable extraction with file upload simulation
  console.log('Capturing variable extraction...');
  await page.evaluate(() => {
    // Simulate file selection UI
    document.getElementById('fileInput').style.display = 'block';
    const variableSection = document.getElementById('variableSection');
    if (variableSection) {
      variableSection.classList.remove('hidden');
      // Add sample variables to the select
      const select = document.getElementById('variableSelect');
      if (select) {
        select.innerHTML = `
          <option>O3 - Ozone Concentration</option>
          <option>NO2 - Nitrogen Dioxide</option>
          <option>SO2 - Sulfur Dioxide</option>
        `;
      }
      // Show temporal info
      const variableInfo = document.getElementById('variableInfo');
      if (variableInfo) {
        variableInfo.innerHTML = `
          <div class="bg-yellow-50 p-3 rounded border border-yellow-200">
            <h4 class="font-semibold text-yellow-700 mb-2">
              <i class="fas fa-clock mr-1"></i> Temporal Information
            </h4>
            <p class="text-sm text-yellow-600">Time dimension not available in this dataset</p>
            <p class="text-xs text-gray-500 mt-1">This appears to be a single time snapshot.</p>
          </div>
        `;
      }
    }
  });
  await new Promise(r => setTimeout(r, 1000));
  await page.screenshot({ path: 'docs/images/02-variable-extraction.png', fullPage: false });

  // Capture Search tab
  console.log('Capturing search tab...');
  await page.click('#tabSearch');
  await new Promise(r => setTimeout(r, 1000));
  await page.screenshot({ path: 'docs/images/03-search-tab.png', fullPage: false });

  // Capture Alerts tab
  console.log('Capturing alerts tab...');
  await page.click('#tabAlerts');
  await new Promise(r => setTimeout(r, 1000));
  await page.screenshot({ path: 'docs/images/04-alerts-tab.png', fullPage: false });

  // Capture History tab
  console.log('Capturing history tab...');
  await page.click('#tabHistory');
  await new Promise(r => setTimeout(r, 1000));
  await page.screenshot({ path: 'docs/images/05-history-tab.png', fullPage: false });

  // Capture Time-lapse tab
  console.log('Capturing time-lapse tab...');
  await page.click('#tabTimelapse');
  await new Promise(r => setTimeout(r, 1000));
  await page.screenshot({ path: 'docs/images/06-timelapse-tab.png', fullPage: false });

  // Capture 3D View tab
  console.log('Capturing 3D view tab...');
  await page.click('#tab3D');
  await new Promise(r => setTimeout(r, 1000));
  await page.screenshot({ path: 'docs/images/07-3d-view-tab.png', fullPage: false });

  // Capture Collaboration tab
  console.log('Capturing collaboration tab...');
  await page.click('#tabCollab');
  await new Promise(r => setTimeout(r, 1000));
  await page.screenshot({ path: 'docs/images/08-collaboration-tab.png', fullPage: false });

  // Back to Analysis tab and simulate results
  console.log('Capturing analysis results...');
  await page.click('#tabAnalysis');
  await new Promise(r => setTimeout(r, 500));
  
  // Show results section with sample data
  await page.evaluate(() => {
    const resultsSection = document.getElementById('resultsSection');
    const resultsPlaceholder = document.getElementById('resultsPlaceholder');
    if (resultsPlaceholder) resultsPlaceholder.classList.add('hidden');
    if (resultsSection) {
      resultsSection.classList.remove('hidden');
      resultsSection.innerHTML = `
        <h2 class="text-xl font-semibold mb-4 text-gray-800">
          <i class="fas fa-brain mr-2 text-purple-500"></i>
          AI Analysis Results
          <span class="ml-2 text-sm font-normal text-green-600">
            <i class="fas fa-check-circle"></i> Complete
          </span>
        </h2>
        <div class="bg-gradient-to-r from-purple-50 to-indigo-50 p-5 rounded-lg mb-4">
          <h3 class="text-lg font-bold text-purple-800">Supercell</h3>
          <p class="text-gray-700 mt-2 text-sm">Supercell structure identified with maximum reflectivity of 65.5 dBZ and mesocyclone presence.</p>
          <div class="mt-3 flex items-center justify-between">
            <div>
              <span class="text-sm text-gray-600">Confidence:</span>
              <span class="ml-1 font-semibold text-purple-700">92.0%</span>
            </div>
          </div>
        </div>
      `;
    }
  });
  await new Promise(r => setTimeout(r, 1000));
  await page.screenshot({ path: 'docs/images/09-analysis-results.png', fullPage: false });

  // Capture plots section
  console.log('Capturing plots section...');
  await page.evaluate(() => {
    const plotsSection = document.getElementById('plotsSection');
    if (plotsSection) {
      plotsSection.classList.remove('hidden');
      // Scroll to plots
      plotsSection.scrollIntoView({ behavior: 'smooth', block: 'start' });
    }
  });
  await new Promise(r => setTimeout(r, 1500));
  await page.screenshot({ path: 'docs/images/10-plots-section.png', fullPage: false });

  await browser.close();
  console.log('Screenshots captured successfully!');
}

captureScreenshots().catch(console.error);