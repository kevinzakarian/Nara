/* Uses the exact production LuCI view with a simulated RPC boundary. */
(async function() {
  const base = '/luci-app-nava/htdocs/luci-static/resources/';
  const state = {
    ok: true, app_version: '1.0.0-30', test_target: 'google', running: false, busy: false, core: {}, has_subscription: false,
    routing: {available: {}},
    settings: { routing: {enabled: false, ip_source: 'ir', domain_source: 'ir'}, selected: 'auto', ipv6: true, autostart: false, active_subscription: '', dns_mode: 'default', custom_dns: '', skin: localStorage.getItem('nara-preview-skin') === 'orange' ? 'orange' : 'default' },
    subscriptions: [], nodes: [], job: {}, warnings: []
  };
  let subscriptionCounter = 0;
  function E(tag, attrs, content) {
    const node = document.createElement(tag);
    Object.entries(attrs || {}).forEach(([key, value]) => node.setAttribute(key, value));
    (Array.isArray(content) ? content : [content]).forEach(child => {
      if (child != null) node.appendChild(child instanceof Node ? child : document.createTextNode(String(child)));
    });
    return node;
  }
  const rpc = { declare: spec => spec.method === 'status' ? async () => { const publicState = structuredClone(state); publicState.subscriptions.forEach(item => delete item._url); return publicState; } : spec.method === 'subscription' ? async id => { const item = state.subscriptions.find(item => item.id === id); return item ? { ok: true, url: item._url } : { ok: false, error: 'Subscription not found.' }; } : async (action, url, subscriptionId, subscriptionName, selected, ipv6, autostart, dnsMode, customDns, testTarget, skin, routingEnabled, ipSource, domainSource, directIps, directDomains, vpnIps, vpnDomains) => {
    const operationId = crypto.randomUUID();
    state.busy = true;
    state.job = { state: 'running', operation_id: operationId, requested_dns_mode: dnsMode, requested_subscription_id: subscriptionId, action, message: action === 'save_routing' ? 'Saving routing settings…' : action === 'update_routing' ? 'Updating routing lists…' : action === 'save_general' ? 'Saving skin…' : action === 'disconnect' ? 'Disconnecting…' : action === 'update' ? 'Downloading the latest stable core…' : 'Preparing your connection…', updated: Date.now() / 1000 };
    setTimeout(() => {
      let entry = state.subscriptions.find(item => item.id === subscriptionId);
      if (action === 'add_subscription') {
        entry = { id: 'sub-preview-' + (++subscriptionCounter), name: subscriptionName || 'Subscription ' + subscriptionCounter,
          _url: url, scheme: url.split(':')[0], display_url: new URL(url).origin, nodes: [], active: false };
        state.subscriptions.push(entry);
      }
      if (action === 'edit_subscription' && entry) {
        entry.name = subscriptionName || entry.name;
        if (url && url !== entry._url) { entry._url = url; entry.scheme = url.split(':')[0]; entry.display_url = new URL(url).origin; entry.nodes = []; }
      }
      if (action === 'delete_subscription') {
        state.subscriptions = state.subscriptions.filter(item => item.id !== subscriptionId);
        if (state.settings.active_subscription === subscriptionId) {
          state.settings.active_subscription = ''; state.settings.selected = 'auto';
        }
      }
      if (action === 'connect' || action === 'save') {
        if (action === 'connect') state.settings.active_subscription = subscriptionId;
        state.settings = { ...state.settings, selected, ipv6, autostart, dns_mode: dnsMode || 'default', custom_dns: customDns || '' };
      }
      if (action === 'save_routing') state.settings.routing = {enabled: routingEnabled, ip_source: ipSource, domain_source: domainSource, direct_ips: directIps, direct_domains: directDomains, vpn_ips: vpnIps, vpn_domains: vpnDomains};
      if (action === 'update_routing') { state.routing.updated = Date.now()/1000; ['ir','cn','ru'].forEach(country => ['ip','domain'].forEach(kind => state.routing.available[country+'-'+kind] = true)); }
      if (action === 'test_subscriptions') state.test_target = testTarget;
      if (action === 'save_general') { state.settings.skin = skin; localStorage.setItem('nara-preview-skin', skin); }
      state.subscriptions.forEach(item => {
        if (((action === 'connect' || action === 'update_subscription' || action === 'add_subscription') && item === entry) || action === 'test_subscriptions' || action === 'update_all_subscriptions') {
          item.nodes = [
            { id: 'node-0000000000000001', name: 'Frankfurt', type: 'vless' },
            { id: 'node-0000000000000002', name: 'Amsterdam', type: 'trojan' },
            { id: 'node-0000000000000003', name: 'Helsinki', type: 'hysteria2' }
          ];
          item.updated = Date.now() / 1000;
          item.tests = {};
        }
        if (action === 'test_subscriptions') item.tests = {
          target: testTarget, checked: Date.now()/1000,
          ping: { state: 'ok', ms: 43.2, passed: 2, tested: 3, server: 'Frankfurt' },
          tcping: { state: 'ok', ms: 59.1, passed: 2, tested: 3, applicable: 2, server: 'Amsterdam' },
          url_test: { state: 'ok', ms: 182, passed: 3, tested: 3, server: 'Frankfurt', http_code: 200 }
        };
      });
      state.subscriptions.forEach(item => { item.active = item.id === state.settings.active_subscription; });
      state.has_subscription = state.subscriptions.length > 0;
      const active = state.subscriptions.find(item => item.active);
      state.nodes = active ? active.nodes : [];
      state.updated = active ? active.updated : null;
      if (action === 'connect' || action === 'update') state.core = { version: '1.14.3' };
      if (action === 'connect') state.running = true;
      if (action === 'disconnect') { state.running = false; state.settings.autostart = false; state.health = {}; }
      if (state.running) state.health = { ok: true, checked: Date.now() / 1000, latency_ms: 182, target: 'Google', url: 'https://www.gstatic.com/generate_204' };
      state.busy = false;
      state.job = { state: 'done', operation_id: operationId, action, message: action === 'save_routing' ? 'Routing saved. It will apply when you connect. (Preview simulation)' : action === 'update_routing' ? 'Routing lists updated. Apply routing or reconnect to use them. (Preview simulation)' : action === 'disconnect' ? 'Disconnected. Automatic start is off.' : action === 'connect' ? 'Connected. Internet access verified. (Preview simulation)' : 'Done. (Preview simulation)', updated: Date.now() / 1000 };
    }, 1700);
    return { ok: true, accepted: true, operation_id: operationId };
  } };
  const ui = { addNotification: (_, content, kind) => {
    const notice = E('div', { class: 'notice ' + kind }, content);
    document.querySelector('#notifications').appendChild(notice);
    setTimeout(() => notice.remove(), 6000);
  } };
  const poll = { add: (fn, seconds) => setInterval(fn, seconds * 1000) };
  const L = { resource: path => base + path, hasViewPermission: () => true };
  const view = { extend: obj => obj };
  try {
    const source = await (await fetch(base + 'view/nava.js')).text();
    const page = new Function('view', 'rpc', 'poll', 'ui', 'E', 'L', source)(view, rpc, poll, ui, E, L);
    document.querySelector('#app').appendChild(page.render(await page.load()));
  } catch (error) {
    document.querySelector('#app').textContent = 'Preview could not load: ' + error.message;
  }
})();
