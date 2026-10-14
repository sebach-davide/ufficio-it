import fs from 'fs';
const src = fs.readFileSync('src/worker.src.js', 'utf8');
const out = src.replace('__DASHBOARD_HTML__', () => JSON.stringify(fs.readFileSync('src/dashboard.html', 'utf8'))).replace('__LOGIN_HTML__', () => JSON.stringify(fs.readFileSync('src/login.html', 'utf8')));
fs.writeFileSync('worker.js', out);
console.log('ok', out.length);
