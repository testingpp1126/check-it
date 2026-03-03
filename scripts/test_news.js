(async () => {
  try {
    const key = process.env.NEWS_API_KEY;
    if (!key) return console.error('Set NEWS_API_KEY environment variable before running this script.');
    const q = encodeURIComponent('cyber OR ransomware OR malware OR breach');
    const url = `https://newsapi.org/v2/everything?q=${q}&language=en&pageSize=5&apiKey=${key}`;
    const res = await fetch(url);
    const body = await res.json();
    console.log('HTTP status:', res.status);
    console.log(JSON.stringify(body, null, 2));
  } catch (err) {
    console.error('Fetch error:', err);
  }
})();
