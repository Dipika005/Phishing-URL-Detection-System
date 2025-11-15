// Load stats on page load
document.addEventListener('DOMContentLoaded', function() {
    loadStats();
    
    // Allow Enter key to check URL
    document.getElementById('urlInput').addEventListener('keypress', function(e) {
        if (e.key === 'Enter') {
            checkURL();
        }
    });
});

// Load and display model statistics
async function loadStats() {
    try {
        const response = await fetch('/api/stats');
        const data = await response.json();
        
        document.getElementById('accuracy').textContent = data.accuracy.toFixed(2) + '%';
        document.getElementById('precision').textContent = data.precision.toFixed(2) + '%';
        document.getElementById('recall').textContent = data.recall.toFixed(2) + '%';
        document.getElementById('f1').textContent = data.f1_score.toFixed(2) + '%';
        
        document.getElementById('totalUrls').textContent = data.total_urls.toLocaleString();
        document.getElementById('legitimateUrls').textContent = data.legitimate_urls.toLocaleString();
        document.getElementById('phishingUrls').textContent = data.phishing_urls.toLocaleString();
        document.getElementById('features').textContent = data.num_features;
    } catch (error) {
        console.error('Error loading stats:', error);
    }
}



// Check URL for phishing
async function checkURL() {
    try {
        const urlInput = document.getElementById('urlInput').value.trim();
        
        if (!urlInput) {
            alert('Please enter a URL');
            return;
        }
        
        // Show loading
        document.getElementById('loadingIndicator').style.display = 'block';
        document.getElementById('urlResult').style.display = 'none';
        
        console.log('Checking URL:', urlInput);
        
        const response = await fetch('/api/check-url', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ url: urlInput })
        });
        
        console.log('Response status:', response.status);
        const data = await response.json();
        console.log('Response data:', data);
        
        document.getElementById('loadingIndicator').style.display = 'none';
        
        if (data.success) {
            const isPhishing = data.prediction === 1;
            const phishingScore = data.confidence.phishing;
            const legitimateScore = data.confidence.legitimate;
            const color = isPhishing ? '#f44336' : '#4CAF50';
            const emoji = isPhishing ? '⚠️ PHISHING' : '✅ LEGITIMATE';
            const bgColor = isPhishing ? 'rgba(244, 67, 54, 0.1)' : 'rgba(76, 175, 80, 0.1)';
            
            document.getElementById('urlResultHeader').innerHTML = `
                <div style="background: ${bgColor}; padding: 20px; border-radius: 5px; color: ${color}; font-size: 1.2em; font-weight: bold;">
                    ${emoji}
                </div>
            `;
            
            document.getElementById('urlResultDetails').innerHTML = `
                <div class="result-detail">
                    <label>URL:</label>
                    <value style="word-break: break-all; font-size: 0.9em;">${data.url}</value>
                </div>
                <div class="result-detail">
                    <label>Legitimate Score:</label>
                    <value style="color: #4CAF50; font-size: 1.2em;">${legitimateScore.toFixed(2)}%</value>
                </div>
                <div class="result-detail">
                    <label>Phishing Score:</label>
                    <value style="color: #f44336; font-size: 1.2em;">${phishingScore.toFixed(2)}%</value>
                </div>
                <div class="progress-bar" style="margin-top: 10px; height: 30px; background: #f0f0f0; border-radius: 15px; overflow: hidden;">
                    <div class="progress-fill legitimate-fill" style="width: ${legitimateScore}%; display: flex; align-items: center; justify-content: flex-end; padding-right: 10px; color: white; font-weight: bold; background: linear-gradient(90deg, #4CAF50, #45a049);">
                        ${legitimateScore.toFixed(0)}%
                    </div>
                </div>
            `;
            
            // Show extracted features (top 15)
            const features = data.features;
            let featuresHTML = '<h4 style="margin-top: 20px; margin-bottom: 15px;">Extracted Features (showing top 15):</h4><div class="features-list">';
            let count = 0;
            for (const [key, value] of Object.entries(features)) {
                if (count >= 15) break;
                const displayValue = typeof value === 'number' ? value.toFixed(2) : value;
                featuresHTML += `
                    <div class="feature-item">
                        <label>${key}</label>
                        <value>${displayValue}</value>
                    </div>
                `;
                count++;
            }
            featuresHTML += '</div>';
            
            document.getElementById('urlFeatures').innerHTML = featuresHTML;
            
            document.getElementById('urlResult').style.display = 'block';
            
            // Clear input for next check
            document.getElementById('urlInput').value = '';
        } else {
            alert('Error: ' + data.error);
            console.error('Error details:', data);
        }
    } catch (error) {
        document.getElementById('loadingIndicator').style.display = 'none';
        console.error('Error checking URL:', error);
        alert('Error: ' + error.message);
    }
}
