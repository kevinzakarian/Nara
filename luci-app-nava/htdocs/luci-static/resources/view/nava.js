'use strict';
'require view';
'require rpc';
'require poll';
'require ui';

var getSubscription = rpc.declare({ object: 'nava', method: 'subscription', params: ['subscription_id'], expect: {} });
var getStatus = rpc.declare({ object: 'nava', method: 'status', expect: {} });
var runAction = rpc.declare({
	object: 'nava', method: 'action',
	params: ['action', 'subscription_url', 'subscription_id', 'subscription_name', 'selected', 'ipv6', 'autostart', 'dns_mode', 'custom_dns', 'test_target', 'skin', 'routing_enabled', 'ip_source', 'domain_source', 'direct_ips', 'direct_domains', 'vpn_ips', 'vpn_domains'], expect: {}
});

return view.extend({
	handleSave: null,
	handleSaveApply: null,
	handleReset: null,
	load: function() { return getStatus(); },
	render: function(initial) {
		var writable = L.hasViewPermission ? L.hasViewPermission() : !this.readonly;
		var current = initial || {};
		var pending = false;
		var pendingAction = '';
		var activeOperation = '';
		var retiredOperations = new Set();
		var dirty = false;
		var generalDirty = false;
		var routingDirty = false;
		var nodeSignature = '';
		var lastJob = (current.job || {}).updated + (current.job || {}).message;
		var refreshing = false;
		var subscriptionId = (current.settings || {}).active_subscription || '';
		var subscriptionSignature = '';
		var modalOpen = false;
		var editingSubscriptionId = '';
		function el(tag, cls, content) {
			// Never give untrusted subscription names or messages to LuCI as HTML.
			if (typeof content === 'string' || typeof content === 'number') content = [document.createTextNode(String(content))];
			return E(tag, { 'class': cls || '' }, content == null ? [] : content);
		}
		function text(element, value) { element.textContent = value; }
		function actionIcon(kind, label) {
			var button = E('button', { type: 'button', 'class': 'nv-button nv-icon-button' + (kind === 'remove' ? ' nv-danger' : ''), title: label, 'aria-label': label });
			var svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
			svg.setAttribute('viewBox', '0 0 24 24');
			svg.setAttribute('aria-hidden', 'true');
			svg.setAttribute('focusable', 'false');
			var shapes = { update: ['M20 7v5h-5', 'M4 17v-5h5', 'M6.1 6.1A8 8 0 0 1 20 12M4 12a8 8 0 0 0 13.9 5.9'], edit: ['M12 20H4v-8', 'M16 3l5 5-11 11-5 1 1-5Z', 'M14 5l5 5'], remove: ['M3 6h18M9 6V3h6v3', 'M5 6l1 15h12l1-15', 'M10 10v7M14 10v7'] };
			shapes[kind].forEach(function(value) { var path = document.createElementNS('http://www.w3.org/2000/svg', 'path'); path.setAttribute('d', value); svg.appendChild(path); });
			button.appendChild(svg);
			return button;
		}
		function date(value) { return value ? new Date(value * 1000).toLocaleString('en-GB') : 'Never'; }
		function notify(message, error) { ui.addNotification(null, el('p', '', message), error ? 'error' : 'info'); }
		var root = el('div', 'nava');
		root.setAttribute('dir', 'ltr');
		var style = E('link', { rel: 'stylesheet', href: L.resource('nava/nava.css') + '?v=1.0.0-30' });
		var badge = el('span', 'nv-badge', 'Checking status');
		var statusTitle = el('h2', '', 'Ready when you are');
		var statusDescription = el('p', 'nv-muted', 'Add your subscription to get started.');
		var statusOrb = E('button', { type: 'button', 'class': 'nv-orb', 'aria-label': 'Connect tunnel', title: 'Connect tunnel' }, [el('span', 'nv-orb-inner', '⏻')]);
		var coreValue = el('strong', '', 'Not installed');
		var appValue = el('strong', '', '—');
		var aboutVersion = el('strong', '', '—');
		var serverValue = el('strong', '', '0');
		var latencyValue = el('strong', '', '—');
		var progress = el('div', 'nv-progress');
		progress.setAttribute('role', 'status');
		progress.setAttribute('aria-live', 'polite');
		var subscription = E('input', {
			type: 'text', id: 'nv-subscription', placeholder: 'https://provider.com/subscription/…',
			autocomplete: 'off', spellcheck: 'false', 'aria-label': 'Subscription URL'
		});
		var subscriptionName = E('input', { type: 'text', id: 'nv-subscription-name', placeholder: 'For example: Work VPN', autocomplete: 'off', 'aria-label': 'Subscription name' });
		var select = E('select', { id: 'nv-server', 'aria-label': 'Server | Inbound' }, [E('option', { value: 'auto' }, 'Automatic · fastest available')]);
		var autoStart = E('input', { type: 'checkbox', id: 'nv-autostart' });
		var ipv6 = E('input', { type: 'checkbox', id: 'nv-ipv6' });
		var dnsSelect = E('select', { id: 'nv-dns', 'aria-label': 'DNS provider' }, [
			E('option', { value: 'default' }, 'Default DNS'),
			E('option', { value: 'cloudflare' }, 'Cloudflare · 1.1.1.1'),
			E('option', { value: 'google' }, 'Google · 8.8.8.8'),
			E('option', { value: 'opendns' }, 'OpenDNS · 208.67.222.222'),
			E('option', { value: 'custom' }, 'Custom DNS')
		]);
		var customDns = E('input', { type: 'text', id: 'nv-custom-dns', placeholder: '9.9.9.9 or https://dns.quad9.net/dns-query', autocomplete: 'off', 'aria-label': 'Custom DNS servers' });
		var dnsNote = el('p', 'nv-field-note', 'No DNS configuration. Use the system defaults; subscription DNS settings are not imported.');
		var refreshed = el('small', 'nv-last-updated', 'Last updated: Never');
		var warnings = el('div', 'nv-warnings');
		var reconnect = E('button', { type: 'button', id: 'nv-reconnect', 'class': 'nv-button nv-primary' }, 'Apply & reconnect');
		var save = E('button', { type: 'button', 'class': 'nv-button nv-secondary' }, 'Save settings');
		var update = E('button', { type: 'button', 'class': 'nv-button nv-secondary' }, 'Update core');
		var subscriptionSelect = E('select', { id: 'nv-subscriptions', 'aria-label': 'Subscription' }, [E('option', { value: '' }, 'Select a subscription')]);
		var subscriptionTableBody = E('tbody');
		var controls = [statusOrb, subscriptionSelect, select, autoStart, ipv6, dnsSelect, customDns, reconnect, save, update];
		[select, autoStart, ipv6, dnsSelect, customDns].forEach(function(input) {
			input.addEventListener('change', function() { dirty = true; });
			input.addEventListener('input', function() { dirty = true; });
		});
		var overviewTab = E('button', { type: 'button', role: 'tab', id: 'nv-connection-tab', 'aria-controls': 'nv-connection-panel', 'class': 'nv-tab nv-tab-active' }, 'Connection');
		var subscriptionsTab = E('button', { type: 'button', role: 'tab', id: 'nv-subscriptions-tab', 'aria-controls': 'nv-subscriptions-panel', 'class': 'nv-tab' }, 'Subscriptions');
		var overviewPanel = E('div', { id: 'nv-connection-panel', role: 'tabpanel', 'aria-labelledby': 'nv-connection-tab', 'class': 'nv-panel' });
		var subscriptionsPanel = E('div', { id: 'nv-subscriptions-panel', role: 'tabpanel', 'aria-labelledby': 'nv-subscriptions-tab', 'class': 'nv-panel' });
		var generalTab = E('button', { type: 'button', role: 'tab', id: 'nv-general-tab', 'aria-controls': 'nv-general-panel', 'class': 'nv-tab' }, 'General');
		var aboutTab = E('button', { type: 'button', role: 'tab', id: 'nv-about-tab', 'aria-controls': 'nv-about-panel', 'class': 'nv-tab' }, 'About');
		var generalPanel = E('div', { id: 'nv-general-panel', role: 'tabpanel', 'aria-labelledby': 'nv-general-tab', 'class': 'nv-panel' });
		var aboutPanel = E('div', { id: 'nv-about-panel', role: 'tabpanel', 'aria-labelledby': 'nv-about-tab', 'class': 'nv-panel' });
		var routingTab = E('button', { type: 'button', role: 'tab', id: 'nv-routing-tab', 'aria-controls': 'nv-routing-panel', 'class': 'nv-tab' }, 'Routing');
		var routingPanel = E('div', { id: 'nv-routing-panel', role: 'tabpanel', 'aria-labelledby': 'nv-routing-tab', 'class': 'nv-panel' });
		var routingOn = E('input', { type: 'radio', name: 'nv-routing-enabled', id: 'nv-routing-on', value: 'enabled' });
		var routingOff = E('input', { type: 'radio', name: 'nv-routing-enabled', id: 'nv-routing-off', value: 'disabled' });
		function countrySelect(id, label) {
			return E('select', { id: id, 'aria-label': label }, [E('option', { value: 'ir' }, 'Iran · Chocolate4U'), E('option', { value: 'cn' }, 'China · Loyalsoldier'), E('option', { value: 'ru' }, 'Russia · runetfreedom')]);
		}
		var routingIp = countrySelect('nv-routing-ip', 'IP list');
		var routingDomain = countrySelect('nv-routing-domain', 'Domain list');
		function routingBox(id, label, placeholder) {
			return E('textarea', { id: id, rows: '6', maxlength: '8192', spellcheck: 'false', autocomplete: 'off', 'aria-label': label, placeholder: placeholder });
		}
		var directIps = routingBox('nv-direct-ips', 'Direct IP addresses', '192.0.2.10\n198.51.100.0/24');
		var directDomains = routingBox('nv-direct-domains', 'Direct domains', 'example.com\nexample.org');
		var vpnIps = routingBox('nv-vpn-ips', 'VPN IP addresses', '203.0.113.20\n203.0.113.0/24');
		var vpnDomains = routingBox('nv-vpn-domains', 'VPN domains', 'example.net\nservice.example.net');
		var customRoutingFields = { direct_ips: directIps, direct_domains: directDomains, vpn_ips: vpnIps, vpn_domains: vpnDomains };
		Object.keys(customRoutingFields).forEach(function(key) {
			customRoutingFields[key].addEventListener('input', function() { routingDirty = true; });
			controls.push(customRoutingFields[key]);
		});
		var applyRouting = E('button', { type: 'button', 'class': 'nv-button nv-primary' }, 'Apply routing');
		var updateRouting = E('button', { type: 'button', 'class': 'nv-button nv-secondary' }, 'Update routing lists');
		var routingNote = el('p', 'nv-field-note');
		var routingUpdated = el('span', 'nv-routing-updated');
		var routingIpStatus = el('p', 'nv-field-note');
		var routingDomainStatus = el('p', 'nv-field-note');
		[routingOn, routingOff, routingIp, routingDomain].forEach(function(input) {
			input.addEventListener('change', function() { routingDirty = true; paint(current); });
		});
		controls.push(routingOn, routingOff, routingIp, routingDomain, applyRouting, updateRouting);
		var skinSelect = E('select', { id: 'nv-skin', 'aria-label': 'Skin' }, [E('option', { value: 'default' }, 'Default'), E('option', { value: 'orange' }, 'Orange')]);
		var saveSkin = E('button', { type: 'button', 'class': 'nv-button nv-primary' }, 'Save skin');
		var skinNote = el('p', 'nv-field-note');
		function applySkin() { root.setAttribute('data-skin', skinSelect.value === 'orange' ? 'orange' : 'default'); }
		skinSelect.addEventListener('change', function() { generalDirty = true; applySkin(); paint(current); });
		controls.push(skinSelect, saveSkin);
		var subscriptionsTable = E('table', { 'class': 'nv-subscription-table' });
		subscriptionsTable.appendChild(E('thead', {}, [E('tr', {}, [
			E('th', {}, 'Name'), E('th', {}, 'Type'), E('th', {}, 'Ping'), E('th', {}, 'TCPing'), E('th', {}, 'URL Test'), E('th', {}, 'Actions')
		])]));
		subscriptionsTable.appendChild(subscriptionTableBody);
		var targetChoices = { apple: 'Apple', cloudflare: 'Cloudflare', facebook: 'Facebook', github: 'GitHub', google: 'Google', instagram: 'Instagram', microsoft: 'Microsoft' };
		var urlTarget = E('select', { id: 'nv-url-target', 'aria-label': 'URL Test website' }, Object.keys(targetChoices).map(function(key) { return E('option', { value: key }, targetChoices[key]); }));
		urlTarget.value = targetChoices[current.test_target] ? current.test_target : 'google';
		var testAll = E('button', { type: 'button', 'class': 'nv-button nv-secondary' }, 'Test all subscriptions');
		var updateAll = E('button', { type: 'button', 'class': 'nv-button nv-secondary' }, 'Update all subscriptions');
		var newSubscription = E('button', { type: 'button', 'class': 'nv-button nv-primary' }, 'New subscription');
		var modalTitle = el('h3', '', 'New subscription');
		var modalDescription = el('p', 'nv-muted', 'Add a name and an HTTP or HTTPS link. The server list is downloaded automatically before saving.');
		var modal = el('div', 'nv-modal');
		modal.hidden = true;
		modal.setAttribute('role', 'dialog');
		modal.setAttribute('aria-modal', 'true');
		modal.appendChild(el('div', 'nv-modal-backdrop'));
		modal.appendChild(el('div', 'nv-modal-dialog', [
			el('div', 'nv-modal-heading', [modalTitle, modalDescription]),
			E('label', { 'for': 'nv-subscription-name', 'class': 'nv-label' }, 'Subscription name'), subscriptionName,
			E('label', { 'for': 'nv-subscription', 'class': 'nv-label' }, 'Subscription URL'),
			subscription,
			el('p', 'nv-field-note', 'HTTP links are unencrypted. Use them only with a trusted provider.'),
			el('div', 'nv-modal-actions', [E('button', { type: 'button', 'class': 'nv-button nv-secondary' }, 'Cancel'), E('button', { type: 'button', 'class': 'nv-button nv-primary' }, 'Save subscription')])
		]));
		var modalCancel = modal.querySelector('.nv-modal-actions .nv-secondary');
		var modalSave = modal.querySelector('.nv-modal-actions .nv-primary');
		function showTab(tab) {
			[[overviewTab, overviewPanel, 'overview'], [subscriptionsTab, subscriptionsPanel, 'subscriptions'], [routingTab, routingPanel, 'routing'], [generalTab, generalPanel, 'general'], [aboutTab, aboutPanel, 'about']].forEach(function(item) {
				var active = item[2] === tab;
				item[1].hidden = !active;
				item[0].classList.toggle('nv-tab-active', active);
				item[0].setAttribute('aria-selected', String(active));
				item[0].tabIndex = active ? 0 : -1;
			});
		}
		var tabItems = [[overviewTab, 'overview'], [subscriptionsTab, 'subscriptions'], [routingTab, 'routing'], [generalTab, 'general'], [aboutTab, 'about']];
		tabItems.forEach(function(item, index) { item[0].addEventListener('keydown', function(event) {
			var next = event.key === 'ArrowRight' ? (index + 1) % tabItems.length : event.key === 'ArrowLeft' ? (index + tabItems.length - 1) % tabItems.length : event.key === 'Home' ? 0 : event.key === 'End' ? tabItems.length - 1 : -1;
			if (next >= 0) { event.preventDefault(); showTab(tabItems[next][1]); tabItems[next][0].focus(); }
		}); });
		function closeSubscriptionModal() {
			modalOpen = false;
			modal.hidden = true;
			subscription.value = '';
			subscriptionName.value = '';
			paint(current);
			newSubscription.focus();
		}
		function openSubscriptionModal(item) {
			modalOpen = true;
			editingSubscriptionId = item && item.id || '';
			subscription.value = '';
			subscriptionName.value = item && item.name || '';
			text(modalTitle, editingSubscriptionId ? 'Edit subscription' : 'New subscription');
			text(modalDescription, editingSubscriptionId ? 'Edit the saved name and subscription link.' : 'Add a name and an HTTP or HTTPS link. The server list is downloaded automatically before saving.');
			subscription.placeholder = editingSubscriptionId ? 'Loading saved URL…' : 'https://provider.com/subscription/…';
			modal.hidden = false;
			subscriptionName.focus();
			if (editingSubscriptionId) {
				var requestedId = editingSubscriptionId;
				modalSave.disabled = true;
				subscription.disabled = true;
				getSubscription(requestedId).then(function(result) {
					if (!modalOpen || editingSubscriptionId !== requestedId) return;
					if (!result.ok) throw new Error(result.error || 'Could not load the saved link.');
					subscription.value = result.url;
					subscription.placeholder = 'HTTP or HTTPS subscription URL';
					subscription.disabled = false;
					modalSave.disabled = false;
				}).catch(function(error) {
					if (!modalOpen || editingSubscriptionId !== requestedId) return;
					notify(error.message, true);
					closeSubscriptionModal();
				});
			} else { subscription.disabled = false; }
		}
		function syncSettings(state) {
			var options = state.settings || {};
			select.value = options.selected || 'auto';
			autoStart.checked = !!options.autostart;
			ipv6.checked = options.ipv6 !== false;
			dnsSelect.value = options.dns_mode || 'default';
			customDns.value = options.custom_dns || '';
			subscriptionId = options.active_subscription || '';
			subscriptionSelect.value = subscriptionId;
		}
		function resultCell(item, key) {
			var tests = item.tests || {};
			var result = tests[key] || {};
			var labels = { pending: 'Testing…', failed: 'Failed', no_reply: 'No reply', not_applicable: 'N/A', restricted: 'Restricted' };
			var passed = result.state === 'ok';
			var label = passed ? result.ms + ' ms' : labels[result.state] || (tests.error ? 'Failed' : '—');
			var cell = E('td', { 'class': passed ? 'nv-result-good' : result.state === 'restricted' ? 'nv-result-restricted' : '' }, label);
			if (result.tested) cell.appendChild(el('small', 'nv-result-count', result.passed + '/' + (result.applicable || result.tested) + ' passed'));
			if (key === 'url_test' && tests.target) cell.appendChild(el('small', 'nv-result-target', targetChoices[tests.target] || tests.target));
			cell.title = tests.error || (result.state === 'not_applicable' ? 'UDP protocols do not have a TCP endpoint.' :
				(result.server ? 'Best server: ' + result.server + '. ' : '') + (result.http_code ? 'HTTP ' + result.http_code + '. ' : '') +
				'Checked: ' + date(tests.checked) + (key === 'url_test' && tests.target_url ? '. Target: ' + tests.target_url : '') +
				(key === 'ping' ? '. No ICMP reply does not necessarily mean the proxy is unavailable.' : ''));
			return cell;
		}
		function paint(state) {
			var operation = (state.job || {}).operation_id;
			if (retiredOperations.has(operation) || (activeOperation && operation !== activeOperation)) return;
			current = state;
			if (!dirty) syncSettings(state);
			if (!generalDirty) skinSelect.value = (state.settings || {}).skin === 'orange' ? 'orange' : 'default';
			if (!routingDirty) {
				var routeOptions = (state.settings || {}).routing || {};
				routingOn.checked = !!routeOptions.enabled;
				routingOff.checked = !routeOptions.enabled;
				routingIp.value = routeOptions.ip_source || 'ir';
				routingDomain.value = routeOptions.domain_source || 'ir';
				Object.keys(customRoutingFields).forEach(function(key) { customRoutingFields[key].value = routeOptions[key] || ''; });
			}
			var lists = state.routing || {}, available = lists.available || {};
			text(routingUpdated, 'Last updated: ' + date(lists.updated));
			text(routingIpStatus, available[routingIp.value + '-ip'] ? 'IP list ready' : 'IP list missing — update routing lists before connecting.');
			text(routingDomainStatus, available[routingDomain.value + '-domain'] ? 'Domain list ready' : 'Domain list missing — update routing lists before connecting.');
			text(routingNote, state.running ? 'Apply routing reconnects the active subscription. Changes are saved only after connection verification.' : 'Disconnected: Apply routing only saves your choices for the next connection. Your current Internet connection stays unchanged.');
			applySkin();
			text(skinNote, generalDirty ? 'Previewing ' + (skinSelect.value === 'orange' ? 'Orange' : 'Default') + '. Save skin to keep this appearance.' : 'Your saved skin is used whenever you open NARA.');
			var busy = pending || state.busy || !!activeOperation;
			var jobAction = pending ? pendingAction : (state.job || {}).action;
			var savingRouting = busy && jobAction === 'save_routing' && !state.running;
			var updatingRouting = busy && jobAction === 'update_routing';
			var savingSkin = busy && (pending ? pendingAction : (state.job || {}).action) === 'save_general';
			var health = state.health || {};
			var recent = health.checked && Date.now() / 1000 - health.checked < 300;
			var verified = state.running && health.ok && recent;
			var failed = state.running && health.checked && !health.ok;
			root.classList.toggle('nv-connected', !!verified);
			root.classList.toggle('nv-active', !!state.running);
			statusOrb.setAttribute('aria-label', state.running ? 'Disconnect tunnel' : 'Connect tunnel');
			statusOrb.title = state.running ? 'Disconnect tunnel' : 'Connect tunnel';
			root.classList.toggle('nv-busy', !!busy);
			text(badge, busy ? 'Working' : verified ? 'Connected' : failed ? 'Check connection' : state.running ? 'Tunnel running' : 'Disconnected');
			text(statusTitle, busy ? (savingSkin ? 'Saving your skin' : savingRouting ? 'Saving routing settings' : updatingRouting ? 'Updating routing lists' : 'Getting things ready') : verified ? 'You’re connected' : state.running ? 'Your tunnel is running' : 'Your network. One connection.');
			text(statusDescription, busy ? (savingSkin ? 'Saving your appearance preference.' : savingRouting ? 'Your current Internet connection stays unchanged.' : updatingRouting ? 'Downloading and validating country IP and domain lists.' : 'This may take a few minutes on the first connection.') : verified ? 'Router tunnel and proxy verified at ' + date(health.checked) + '.' : failed ? 'The Internet test failed. Select another server and reconnect.' : state.running ? 'Use Apply & reconnect to verify current Internet access.' : 'Connect your router and the devices on your network.');
			if (state.running && state.dns_forwarding && state.dns_forwarding.state === 'error') {
				text(badge, 'Check DNS');
				text(statusDescription, state.dns_forwarding.message || 'The DNS override could not start. Reconnect to retry.');
			}
			text(coreValue, state.core && state.core.version ? 'v' + state.core.version : 'Not installed');
			text(appValue, state.app_version || '—');
			text(aboutVersion, state.app_version || '—');
			text(serverValue, String((state.nodes || []).length));
			text(latencyValue, state.running && health.ok && health.latency_ms != null ? health.latency_ms + ' ms' : '—');
			controls.forEach(function(control) { control.disabled = !!busy || !writable; });
			reconnect.disabled = !!busy || !writable || !subscriptionId;
			newSubscription.disabled = !!busy || !writable;
			modalSave.disabled = !!busy || !writable || subscription.disabled;
			updateAll.disabled = !!busy || !writable || !(state.subscriptions || []).length;
			testAll.disabled = !!busy || !writable || !(state.subscriptions || []).length;
			urlTarget.disabled = !!busy || !writable;
			customDns.hidden = dnsSelect.value !== 'custom';
			dnsNote.textContent = dnsSelect.value === 'custom' ? 'Use IP addresses, hostnames or DNS URLs separated by commas. Router DNS is forwarded to your chosen resolver while connected. Apply & reconnect to use changes.' : dnsSelect.value === 'default' ? 'No DNS configuration. Use the system defaults; subscription DNS settings are not imported.' : 'The selected provider is reached through the proxy tunnel.';
			var job = state.job || {};
			text(progress, pending ? (savingSkin ? 'Saving skin…' : savingRouting ? 'Saving routing settings…' : updatingRouting ? 'Updating routing lists…' : 'Preparing…') : job.message || '');
			var obsoleteError = job.state === 'error' && dirty &&
				(job.requested_dns_mode !== dnsSelect.value || job.requested_subscription_id !== subscriptionId);
			progress.hidden = !pending && (!job.message || obsoleteError);
			progress.classList.toggle('nv-error', job.state === 'error');
			var subSignature = JSON.stringify([state.subscriptions || [], !!busy, writable]);
			if (subSignature !== subscriptionSignature) {
				subscriptionSignature = subSignature;
				while (subscriptionSelect.options.length > 1) subscriptionSelect.remove(1);
				(state.subscriptions || []).forEach(function(item) { subscriptionSelect.appendChild(E('option', { value: item.id }, item.name)); });
				if (!(state.subscriptions || []).some(function(item) { return item.id === subscriptionId; })) subscriptionId = '';
				subscriptionSelect.value = subscriptionId;
				while (subscriptionTableBody.firstChild) subscriptionTableBody.removeChild(subscriptionTableBody.firstChild);
				if (!(state.subscriptions || []).length) {
					subscriptionTableBody.appendChild(E('tr', {}, [E('td', { colspan: '6', 'class': 'nv-empty-cell' }, 'No subscriptions saved yet.') ]));
				} else {
					(state.subscriptions || []).forEach(function(item) {
						var refresh = actionIcon('update', 'Update ' + item.name);
						refresh.disabled = !!busy || !writable;
						refresh.addEventListener('click', function() { act('update_subscription', { subscriptionId: item.id }); });
						var edit = actionIcon('edit', 'Edit ' + item.name);
						edit.disabled = !!busy || !writable;
						edit.addEventListener('click', function() { openSubscriptionModal(item); });
						var remove = actionIcon('remove', 'Remove ' + item.name);
						remove.disabled = !!busy || !writable;
						remove.addEventListener('click', function() {
							if (window.confirm('Remove this subscription from NARA?')) act('delete_subscription', { subscriptionId: item.id, subscriptionName: item.name });
						});
						var protocols = { vless: 'VLESS', vmess: 'VMess', trojan: 'Trojan', shadowsocks: 'Shadowsocks', hysteria2: 'Hysteria2', tuic: 'TUIC', anytls: 'AnyTLS', hysteria: 'Hysteria' };
						var types = Array.from(new Set((item.nodes || []).map(function(node) { return protocols[node.type] || node.type; }))).join(' · ');
						var name = el('div', 'nv-sub-name', item.name);
						name.appendChild(el('small', item.active ? 'nv-status-active' : 'nv-muted', item.active ? 'Active' : 'Saved'));
						subscriptionTableBody.appendChild(E('tr', {}, [
							E('td', {}, [name]), E('td', { 'class': 'nv-protocols' }, types || 'Update to detect'),
							resultCell(item, 'ping'), resultCell(item, 'tcping'), resultCell(item, 'url_test'),
							E('td', { 'class': 'nv-table-actions' }, [el('div', 'nv-row-actions', [refresh, edit, remove])])
						]));
					});
				}
			}
			var chosen = (state.subscriptions || []).find(function(item) { return item.id === subscriptionId; });
			text(refreshed, 'Last updated: ' + date(chosen ? chosen.updated || (chosen.active ? state.updated : 0) : 0));
			var nodes = chosen ? chosen.nodes || (chosen.active ? state.nodes || [] : []) : [];
			var signature = JSON.stringify([subscriptionId, nodes]);
			if (signature !== nodeSignature) {
				nodeSignature = signature;
				var oldValue = select.value;
				while (select.options.length > 1) select.remove(1);
				(nodes).forEach(function(node) {
					var option = E('option', { value: node.id });
					text(option, node.name + ' · ' + node.type.toUpperCase());
					select.appendChild(option);
				});
				if (dirty && Array.from(select.options).some(function(o) { return o.value === oldValue; })) select.value = oldValue;
			}
			if (!dirty) select.value = (state.settings || {}).selected || 'auto';
			if (!select.value) select.value = 'auto';
			reconnect.disabled = !!busy || !writable || !subscriptionId;
			warnings.replaceChildren();
			if ((state.warnings || []).length) {
				var detail = E('details', {}, [E('summary', {}, String(state.warning_count || state.warnings.length) + ' subscription entries need attention')]);
				state.warnings.forEach(function(warning) { detail.appendChild(el('p', '', warning)); });
				warnings.appendChild(detail);
			}
			if (job.state === 'error' && job.updated + job.message !== lastJob) {
				lastJob = job.updated + job.message;
				notify(job.message, true);
			}
		}
		function refreshStatus() {
			if (refreshing) return Promise.resolve();
			refreshing = true;
			return getStatus().then(function(state) {
				if (!state.ok) throw new Error(state.error || 'Status is unavailable.');
				paint(state);
			}).catch(function() {
				text(badge, 'Status unavailable');
				text(statusDescription, 'Could not reach the router. Check your local connection.');
			}).finally(function() { refreshing = false; });
		}
		function act(action, overrides) {
			if (pending || current.busy || !writable) return;
			overrides = overrides || {};
			var url = overrides.url !== undefined ? String(overrides.url).trim() : '';
			var targetId = overrides.subscriptionId !== undefined ? overrides.subscriptionId : subscriptionId;
			var targetName = overrides.subscriptionName !== undefined ? overrides.subscriptionName : '';
			if (action === 'save') targetId = (current.settings || {}).active_subscription || '';
			if (url && !/^https?:\/\//i.test(url)) {
				notify('Enter a valid HTTP or HTTPS subscription URL.', true);
				subscription.focus();
				return;
			}
			if (action === 'connect' && !targetId) {
				notify('Select a subscription first.', true);
				subscriptionSelect.focus();
				return;
			}
			pendingAction = action;
			pending = true;
			paint(current);
			var editsSettings = ['connect', 'refresh', 'save', 'select_subscription', 'delete_subscription'].indexOf(action) >= 0;
			var libraryAction = ['add_subscription', 'edit_subscription', 'update_subscription', 'delete_subscription'].indexOf(action) >= 0;
			var options = current.settings || {};
			var selectedServer = action === 'save' && subscriptionId !== options.active_subscription ? options.selected || 'auto' : select.value;
			return runAction(action, url, editsSettings || libraryAction ? targetId : '', targetName,
				editsSettings ? selectedServer : options.selected || 'auto', editsSettings ? ipv6.checked : options.ipv6 !== false,
				editsSettings ? autoStart.checked : !!options.autostart, editsSettings ? dnsSelect.value : options.dns_mode || 'default',
				editsSettings ? customDns.value.trim() : options.custom_dns || '', urlTarget.value, skinSelect.value, routingOn.checked, routingIp.value, routingDomain.value, directIps.value, directDomains.value, vpnIps.value, vpnDomains.value)
				.then(function(result) {
					if (!result.ok) throw new Error(result.error || 'The operation could not start.');
					var previousOperation = (current.job || {}).operation_id;
					if (previousOperation && previousOperation !== result.operation_id) retiredOperations.add(previousOperation);
					activeOperation = result.operation_id || '';
					// Keep edits until the worker reports successful persistence.
					var waitForCompletion = function() {
						return getStatus().then(function(state) {
							if (!state.ok) throw new Error(state.error || 'Status is unavailable.');
							if (activeOperation && (state.job || {}).operation_id !== activeOperation) {
								if (root.isConnected) window.setTimeout(waitForCompletion, 2000);
								return;
							}
							pending = false;
							if (!state.busy) activeOperation = '';
							if (!state.busy && state.job && state.job.state === 'done') {
								if (editsSettings && !libraryAction && action !== 'save') dirty = false;
								if (action === 'save_general') generalDirty = false;
								if (action === 'save_routing') routingDirty = false;
								if (overrides.closeModal) closeSubscriptionModal();
							}
							paint(state);
							if (state.busy && root.isConnected) window.setTimeout(waitForCompletion, 2000);
						}).catch(function() {
							if (activeOperation && root.isConnected) window.setTimeout(waitForCompletion, 5000);
						});
					};
					return waitForCompletion();
				}).catch(function(error) { notify(error.message, true); })
				.finally(function() { pending = false; paint(current); });
		}
		statusOrb.addEventListener('click', function() { act(current.running ? 'disconnect' : 'connect'); });
		updateAll.addEventListener('click', function() { act('update_all_subscriptions'); });
		testAll.addEventListener('click', function() { act('test_subscriptions'); });
		reconnect.addEventListener('click', function() { act('connect'); });
		save.addEventListener('click', function() { act('save'); });
		dnsSelect.addEventListener('change', function() { paint(current); });
		update.addEventListener('click', function() { act('update'); });
		applyRouting.addEventListener('click', function() { act('save_routing'); });
		updateRouting.addEventListener('click', function() { act('update_routing'); });
		saveSkin.addEventListener('click', function() { act('save_general'); });
		[ [routingTab, 'routing'], [generalTab, 'general'], [aboutTab, 'about'] ].forEach(function(item) { item[0].addEventListener('click', function() { showTab(item[1]); }); });
		overviewTab.addEventListener('click', function() { showTab('overview'); });
		subscriptionsTab.addEventListener('click', function() { showTab('subscriptions'); });
		subscriptionSelect.addEventListener('change', function() { subscriptionId = subscriptionSelect.value; dirty = true; select.value = 'auto'; paint(current); });
		newSubscription.addEventListener('click', function() { openSubscriptionModal(); });
		modalCancel.addEventListener('click', closeSubscriptionModal);
		modal.querySelector('.nv-modal-backdrop').addEventListener('click', closeSubscriptionModal);
		modalSave.addEventListener('click', function() {
			if (!editingSubscriptionId && !subscription.value.trim()) {
				notify('Enter a subscription URL first.', true);
				subscription.focus();
				return;
			}
			act(editingSubscriptionId ? 'edit_subscription' : 'add_subscription', { url: subscription.value, subscriptionId: editingSubscriptionId, subscriptionName: subscriptionName.value, closeModal: true });
		});
		document.addEventListener('keydown', function(event) {
			if (event.key === 'Escape' && modalOpen) closeSubscriptionModal();
		});
		function metric(label, value) { return el('div', 'nv-metric', [el('span', '', label), value]); }
		function toggle(input, title, description) {
			return E('label', { 'class': 'nv-toggle', 'for': input.id }, [el('span', '', [el('strong', '', title), el('small', '', description)]), input]);
		}
		root.appendChild(style);
		function brandBlock(headingTag) {
			return el('div', 'nv-brand', [el('span', 'nv-logo', 'N'), el('div', '', [el(headingTag, 'nv-brand-title', 'NARA'), el('p', '', 'Sing-box for OpenWrt')])]);
		}
		var brand = el('div', 'nv-brand-line', [brandBlock('h1')]);
		root.appendChild(el('section', 'nv-hero', [el('div', 'nv-hero-copy', [brand, badge, statusTitle, statusDescription]), statusOrb]));
		root.appendChild(el('div', 'nv-metrics', [metric('APPLICATION VERSION', appValue), metric('CORE VERSION', coreValue), metric('AVAILABLE SERVERS', serverValue), metric('LAST HTTPS TEST · GOOGLE', latencyValue)]));
		root.appendChild(progress);
		root.appendChild(E('div', { 'class': 'nv-tabs', role: 'tablist', 'aria-label': 'NARA sections' }, [overviewTab, subscriptionsTab, routingTab, generalTab, aboutTab]));
		overviewPanel.appendChild(el('div', 'nv-columns', [
			el('section', 'nv-card nv-main', [
				el('div', 'nv-card-heading', [el('span', 'nv-step', '01'), el('div', '', [el('h3', '', 'Connection settings'), el('p', '', 'Choose a saved subscription and configure the tunnel.')])]),
				E('label', { 'for': 'nv-subscriptions', 'class': 'nv-label' }, 'Subscription'), subscriptionSelect,
				el('p', 'nv-field-note', 'Select a subscription, then use Apply & reconnect to connect.'),
				E('label', { 'for': 'nv-server', 'class': 'nv-label' }, 'Server | Inbound'), select,
				el('p', 'nv-field-note', 'Automatic mode regularly tests servers and selects a responsive one.'),
				E('label', { 'for': 'nv-dns', 'class': 'nv-label' }, 'DNS provider'), dnsSelect, customDns, dnsNote,
				warnings,
				el('div', 'nv-actions nv-actions-bottom', [reconnect, refreshed])
			]),
			el('aside', 'nv-side', [
				el('section', 'nv-card', [
					el('div', 'nv-card-heading', [el('span', 'nv-step', '02'), el('div', '', [el('h3', '', 'Make it yours'), el('p', '', 'A few useful preferences.')])]),
					toggle(autoStart, 'Start on boot', 'Reconnect when your router restarts.'),
					toggle(ipv6, 'IPv6 traffic', 'Proxy IPv6 traffic. When off, public IPv6 is blocked while connected. Turns off automatically if only IPv4 connects.'), save
				]),
				el('section', 'nv-card nv-core-card', [el('h3', '', 'Keep your core current'), el('p', 'nv-muted', 'Get the latest stable sing-box release directly from GitHub, with SHA-256 verification.'), update])
			])
		]));
		subscriptionsPanel.appendChild(el('div', 'nv-card nv-subscriptions-card', [
			el('div', 'nv-card-heading', [el('span', 'nv-step', '01'), el('div', '', [el('h3', '', 'Saved subscriptions'), el('p', '', 'Keep several providers and choose one whenever you connect.')]), newSubscription]),
			el('div', 'nv-test-toolbar', [el('div', 'nv-test-target', [E('label', { 'for': 'nv-url-target', 'class': 'nv-label' }, 'URL Test website'), urlTarget]), el('div', 'nv-toolbar-actions', [testAll, updateAll])]),
			el('p', 'nv-field-note nv-table-note', 'Ping: server response over ICMP. TCPing: connection to the server port (N/A for UDP protocols). URL Test: HTTPS response from the selected website through each proxy. Rows show the best result per test; those results can come from different servers. Restricted means the site returned an access restriction.'),
			el('div', 'nv-table-scroll', [subscriptionsTable])
		]));
		root.appendChild(overviewPanel);
		root.appendChild(subscriptionsPanel);
		routingPanel.appendChild(el('section', 'nv-card nv-routing-card', [
			el('div', 'nv-card-heading', [el('span', 'nv-step', '01'), el('div', '', [el('h3', '', 'Country routing'), el('p', '', 'Keep selected destinations direct. Send everything else through your VPN.')])]),
			E('fieldset', { 'class': 'nv-routing-switch' }, [E('legend', {}, 'Country routing'),
				E('label', { 'for': 'nv-routing-off' }, [routingOff, el('span', '', 'Disabled')]),
				E('label', { 'for': 'nv-routing-on' }, [routingOn, el('span', '', 'Enabled')])]),
			el('div', 'nv-routing-grid', [
				el('div', 'nv-routing-field', [el('span', 'nv-routing-kind', 'IP ADDRESSES'), E('label', { 'for': 'nv-routing-ip', 'class': 'nv-label' }, 'IP list'), routingIp, routingIpStatus]),
				el('div', 'nv-routing-field', [el('span', 'nv-routing-kind', 'DOMAIN NAMES'), E('label', { 'for': 'nv-routing-domain', 'class': 'nv-label' }, 'Domain list'), routingDomain, routingDomainStatus])]),
			el('div', 'nv-routing-flow', [el('div', '', [el('strong', '', 'IP or domain matches'), el('span', '', 'Direct connection')]), el('div', '', [el('strong', '', 'No match'), el('span', '', 'Selected VPN server')])]),
			el('p', 'nv-field-note', 'Domain rules use the hostname visible to sing-box. Encrypted or unavailable hostnames may only match by IP. DNS on ports 53 and 853 keeps its VPN route instead of taking a country bypass. Default DNS adds no DNS configuration and leaves router DNS unchanged.'),
			el('div', 'nv-routing-updates', [updateRouting, routingUpdated]),
		]));
		function customField(input, label, note) {
			return el('div', 'nv-custom-field', [E('label', { 'for': input.id, 'class': 'nv-label' }, label), input, el('p', 'nv-field-note', note)]);
		}
		routingPanel.appendChild(el('section', 'nv-card nv-custom-routing-card', [
			el('div', 'nv-card-heading', [el('span', 'nv-step', '02'), el('div', '', [el('h3', '', 'Custom routing'), el('p', '', 'Your own exceptions, independent of country routing.')])]),
			el('div', 'nv-custom-grid', [
				el('div', 'nv-custom-group', [el('h4', '', 'Always use Direct'), el('p', 'nv-muted', 'Connect to these Internet destinations directly.'),
					customField(directIps, 'IP addresses', 'One IPv4, IPv6 or CIDR range per line.'),
					customField(directDomains, 'Domains', 'One domain per line. Subdomains are included.')]),
				el('div', 'nv-custom-group', [el('h4', '', 'Always use VPN'), el('p', 'nv-muted', 'Keep these Internet destinations on the selected VPN.'),
					customField(vpnIps, 'IP addresses', 'One IPv4, IPv6 or CIDR range per line.'),
					customField(vpnDomains, 'Domains', 'One domain per line. Subdomains are included.')])]),
			el('p', 'nv-field-note', 'VPN rules take priority over Direct and country lists. Custom rules apply while connected, even when country routing is disabled. Local network access, DNS provider and IPv6 preferences keep their existing behavior.'),
			el('p', 'nv-field-note', 'Domains match hostnames visible to sing-box, not DNS queries for those names. Hidden or encrypted hostnames may only match IP rules. Maximum 256 entries and 8 KB per box.')
		]));
		routingPanel.appendChild(el('div', 'nv-routing-save', [routingNote, el('div', 'nv-actions', [applyRouting])]));
		root.appendChild(routingPanel);
		root.appendChild(modal);
		generalPanel.appendChild(el('section', 'nv-card nv-general-card', [
			el('div', 'nv-card-heading', [el('span', 'nv-step', '01'), el('div', '', [el('h3', '', 'Appearance'), el('p', '', 'Choose a skin for NARA.')])]),
			el('div', 'nv-skin-field', [E('label', { 'for': 'nv-skin', 'class': 'nv-label' }, 'Skin'), skinSelect, skinNote]),
			el('div', 'nv-skin-preview', [el('span', 'nv-skin-dot nv-skin-accent'), el('span', 'nv-skin-dot nv-skin-surface'), el('span', 'nv-skin-dot nv-skin-ink'), el('span', '', 'Sing-box for OpenWrt')]),
			el('div', 'nv-actions nv-actions-bottom', [saveSkin])
		]));
		function externalLink(url, label) { return E('a', { href: url, target: '_blank', rel: 'noopener noreferrer' }, label); }
		aboutPanel.appendChild(el('section', 'nv-card nv-about-card', [
			el('div', 'nv-about-brand', [brandBlock('h3')]),
			el('div', 'nv-about-meta', [el('p', 'nv-about-credit', 'Kevin Zakarian'), el('div', 'nv-about-version', [el('span', '', 'Application version'), aboutVersion])]),
			el('p', '', 'An independent English LuCI interface for sing-box on OpenWrt. Manage subscriptions, choose a server and DNS provider, and test connections.'),
			el('h4', '', 'Subscriptions & protocols'),
			el('p', '', 'VLESS · VMess · Trojan · Shadowsocks · Hysteria2 · TUIC · AnyTLS'),
			el('p', '', 'Supports HTTP/HTTPS links, sing-box JSON and V2Ray link/Base64 subscriptions. New subscriptions are updated automatically. Saved subscriptions become active only when you select them and apply the connection.'),
			el('h4', '', 'DNS & connection'),
			el('p', '', 'Choose Default DNS, Cloudflare, Google, OpenDNS or Custom DNS. Default DNS adds no DNS configuration, does not import subscription DNS settings, and leaves router DNS unchanged. Local networks stay accessible. Disconnecting restores normal routing; this is not a kill switch.'),
			el('h4', '', 'Country routing'),
			el('p', '', 'Match either the selected IP list or domain list to connect directly; other public traffic follows the selected VPN. Sources: Chocolate4U for Iran, Loyalsoldier for China (maintained direct domain list), and runetfreedom for Russia (geographic RU IPs and category-ru domains, not the blocked-sites list). DNS traffic on ports 53 and 853 is excluded from country bypasses. Lists update only when requested.'),
			el('p', '', [externalLink('https://github.com/Chocolate4U/Iran-sing-box-rules', 'Chocolate4U'), ' · ', externalLink('https://github.com/Loyalsoldier/v2ray-rules-dat', 'Loyalsoldier'), ' · ', externalLink('https://github.com/runetfreedom/russia-v2ray-rules-dat', 'runetfreedom')]),
			el('h4', '', 'Custom routing'),
			el('p', '', 'Save Direct and VPN exceptions as separate IP/CIDR and domain lists, one entry per line. Domains include subdomains. VPN exceptions take priority over Direct and country lists. Custom rules also work with country routing disabled. Local network access, DNS provider and IPv6 preferences are preserved.'),
			el('h4', '', 'Connection tests'),
			el('p', '', 'Ping measures ICMP response time to the proxy server. TCPing measures a TCP connection to its port. URL Test measures a verified HTTPS response through each proxy. Lower milliseconds mean a faster response, not higher download speed. Restricted means the website returned HTTP 401, 403 or 429. Each table metric shows its own best server.'),
			el('h4', '', 'Core & documentation'),
			el('p', '', 'The latest stable sing-box core is downloaded from SagerNet’s official GitHub releases with SHA-256 verification. NARA is an independent community interface.'),
			el('p', '', [externalLink('https://sing-box.sagernet.org/', 'sing-box documentation'), ' · ', externalLink('https://github.com/SagerNet/sing-box', 'sing-box source'), ' · NARA license: MIT.'])
		]));
		root.appendChild(generalPanel);
		root.appendChild(aboutPanel);
		if (!writable) root.insertBefore(el('p', 'nv-progress', 'Read-only access. Sign in with management permissions to make changes.'), root.firstChild);
		showTab('overview');
		paint(initial || {});
		poll.add(refreshStatus, 3);
		return root;
	}
});
