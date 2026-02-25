// web/sw.js

self.addEventListener('install', event => {
    self.skipWaiting();
    console.log('[SW]: Installed and ready to intercept files.');
});

self.addEventListener('activate', event => {
    event.waitUntil(self.clients.claim());
});

// Intercept the POST request from the WhatsApp/Android Share Menu
self.addEventListener('fetch', event => {
    if (event.request.method === 'POST' && event.request.url.endsWith('/_share_target')) {
        event.respondWith((async () => {
            try {
                const formData = await event.request.formData();
                const file = formData.get('file'); // Matches the 'name' in manifest.json
                
                if (file) {
                    // Find the open PWA window and send the file to it
                    const clients = await self.clients.matchAll();
                    for (const client of clients) {
                        client.postMessage({ type: 'SHARED_FILE', file: file });
                    }
                }
                
                // Redirect back to the main UI so the user sees the transfer happening
                return Response.redirect('/', 303);
            } catch (err) {
                console.error('[SW]: Error processing shared file:', err);
                return Response.redirect('/', 303);
            }
        })());
    }
});
