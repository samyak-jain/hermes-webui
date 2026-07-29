(function () {
  'use strict';

  const $ = (id) => document.getElementById(id);
  const loading = $('loadingState');
  const approvalView = $('approvalView');
  const enrollmentView = $('enrollmentView');
  const terminalState = $('terminalState');
  const statusChip = $('statusChip');
  const errorMessage = $('errorMessage');
  let countdownTimer = null;

  function b64uToBytes(value) {
    let input = String(value || '').replace(/-/g, '+').replace(/_/g, '/');
    while (input.length % 4) input += '=';
    const binary = atob(input);
    return Uint8Array.from(binary, (char) => char.charCodeAt(0));
  }

  function bytesToB64u(value) {
    const bytes = new Uint8Array(value);
    let binary = '';
    bytes.forEach((byte) => { binary += String.fromCharCode(byte); });
    return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
  }

  async function api(path, body) {
    const options = {
      cache: 'no-store',
      credentials: 'omit',
      headers: { 'Content-Type': 'application/json' },
    };
    if (body !== undefined) {
      options.method = 'POST';
      options.body = JSON.stringify(body);
    }
    const response = await fetch(path, options);
    let payload = {};
    try { payload = await response.json(); } catch (_error) {}
    if (!response.ok) {
      const error = new Error(payload.error || `Request failed (${response.status})`);
      error.status = response.status;
      throw error;
    }
    return payload;
  }

  function routeCapability() {
    const match = location.pathname.match(/^\/(sudo-approval|sudo-enrollment)\/([A-Za-z0-9_-]{20,128})$/);
    if (!match) return null;
    return { kind: match[1] === 'sudo-approval' ? 'approval' : 'enrollment', value: match[2] };
  }

  function setBusy(button, busy) {
    button.disabled = busy;
    button.setAttribute('aria-busy', busy ? 'true' : 'false');
  }

  function showError(message) {
    errorMessage.textContent = message;
    errorMessage.hidden = false;
  }

  function clearError() {
    errorMessage.textContent = '';
    errorMessage.hidden = true;
  }

  function showTerminal(state, title, message) {
    loading.hidden = true;
    approvalView.hidden = true;
    enrollmentView.hidden = true;
    terminalState.hidden = false;
    statusChip.textContent = state;
    statusChip.className = `status-chip ${state}`;
    $('terminalTitle').textContent = title;
    $('terminalMessage').textContent = message;
    $('terminalGlyph').textContent = state === 'approved' ? '✓' : state === 'denied' ? '×' : '!';
    if (countdownTimer) window.clearInterval(countdownTimer);
  }

  async function sha256Hex(text) {
    const bytes = new TextEncoder().encode(text);
    const digest = await crypto.subtle.digest('SHA-256', bytes);
    return Array.from(new Uint8Array(digest), (byte) => byte.toString(16).padStart(2, '0')).join('');
  }

  function startCountdown(expiresAt) {
    const render = () => {
      const seconds = Math.max(0, Math.ceil(expiresAt - Date.now() / 1000));
      $('countdown').textContent = seconds ? `${seconds}s remaining` : 'Expired';
      if (!seconds) {
        $('approveButton').disabled = true;
        $('denyButton').disabled = true;
        statusChip.textContent = 'Expired';
        statusChip.className = 'status-chip expired';
        if (countdownTimer) window.clearInterval(countdownTimer);
      }
    };
    render();
    countdownTimer = window.setInterval(render, 250);
  }

  function normalizeAssertionOptions(publicKey) {
    publicKey.challenge = b64uToBytes(publicKey.challenge);
    publicKey.allowCredentials = (publicKey.allowCredentials || []).map((credential) => ({
      ...credential,
      id: b64uToBytes(credential.id),
    }));
    return publicKey;
  }

  function normalizeRegistrationOptions(publicKey) {
    publicKey.challenge = b64uToBytes(publicKey.challenge);
    publicKey.user = { ...publicKey.user, id: b64uToBytes(publicKey.user.id) };
    publicKey.excludeCredentials = (publicKey.excludeCredentials || []).map((credential) => ({
      ...credential,
      id: b64uToBytes(credential.id),
    }));
    return publicKey;
  }

  async function loadApproval(nonce) {
    const payload = await api(`/api/sudo-approval/requests/${encodeURIComponent(nonce)}`);
    const request = payload.request;
    if (!request || typeof request.command !== 'string') throw new Error('Malformed approval request');
    const displayedHash = await sha256Hex(request.command);
    if (displayedHash !== request.command_sha256) throw new Error('Command hash verification failed');
    if (request.state !== 'pending') {
      const terminalCopy = {
        approved: ['Approved', 'This request has been approved and is waiting for its exact local consumer.'],
        denied: ['Denied', 'This request was denied. No sudo authorization was issued.'],
        consumed: ['Already used', 'This single-use approval has already been consumed.'],
        expired: ['Expired', 'This request expired without issuing a sudo authorization.'],
      }[request.state] || ['Unavailable', 'This request is no longer actionable.'];
      showTerminal(request.state, terminalCopy[0], terminalCopy[1]);
      return;
    }

    $('requestCommand').textContent = request.command;
    $('requester').textContent = request.requester;
    $('commandHash').textContent = request.command_sha256;
    const expiry = new Date(request.expires_at * 1000);
    $('expiry').dateTime = expiry.toISOString();
    $('expiry').textContent = expiry.toLocaleString();
    loading.hidden = true;
    approvalView.hidden = false;
    statusChip.textContent = 'Pending';
    statusChip.className = 'status-chip pending';
    startCountdown(request.expires_at);

    $('approveButton').addEventListener('click', async () => {
      clearError();
      setBusy($('approveButton'), true);
      $('denyButton').disabled = true;
      try {
        if (!window.PublicKeyCredential || !navigator.credentials) {
          throw new Error('This browser does not support WebAuthn in the current context.');
        }
        const options = await api('/api/sudo-approval/options', { nonce });
        const credential = await navigator.credentials.get({
          publicKey: normalizeAssertionOptions(options.publicKey),
        });
        if (!credential) throw new Error('Approval was cancelled.');
        await api('/api/sudo-approval/approve', {
          nonce,
          id: credential.id,
          rawId: bytesToB64u(credential.rawId),
          type: credential.type,
          response: {
            authenticatorData: bytesToB64u(credential.response.authenticatorData),
            clientDataJSON: bytesToB64u(credential.response.clientDataJSON),
            signature: bytesToB64u(credential.response.signature),
            userHandle: credential.response.userHandle
              ? bytesToB64u(credential.response.userHandle)
              : null,
          },
        });
        showTerminal('approved', 'Approved', 'User-verified approval recorded. It is valid only for the exact request shown.');
      } catch (error) {
        showError(error.message || 'Approval failed');
        setBusy($('approveButton'), false);
        $('denyButton').disabled = false;
      }
    });

    $('denyButton').addEventListener('click', async () => {
      clearError();
      setBusy($('denyButton'), true);
      $('approveButton').disabled = true;
      try {
        await api('/api/sudo-approval/deny', { nonce });
        showTerminal('denied', 'Denied', 'Denial recorded. No sudo authorization was issued.');
      } catch (error) {
        showError(error.message || 'Denial failed');
        setBusy($('denyButton'), false);
        $('approveButton').disabled = false;
      }
    });
  }

  async function loadEnrollment(token) {
    const payload = await api(`/api/sudo-approval/enrollments/${encodeURIComponent(token)}`);
    $('enrollmentLabel').textContent = payload.enrollment.label;
    $('eyebrow').textContent = 'Trusted-path enrollment';
    $('pageTitle').textContent = 'Approval credential';
    document.title = 'Approval credential enrollment';
    statusChip.textContent = 'One time';
    statusChip.className = 'status-chip enrollment';
    loading.hidden = true;
    enrollmentView.hidden = false;

    $('enrollButton').addEventListener('click', async () => {
      clearError();
      setBusy($('enrollButton'), true);
      try {
        if (!window.PublicKeyCredential || !navigator.credentials) {
          throw new Error('This browser does not support WebAuthn in the current context.');
        }
        const options = await api('/api/sudo-approval/enrollment/options', { token });
        const credential = await navigator.credentials.create({
          publicKey: normalizeRegistrationOptions(options.publicKey),
        });
        if (!credential) throw new Error('Enrollment was cancelled.');
        await api('/api/sudo-approval/enrollment/finish', {
          token,
          id: credential.id,
          rawId: bytesToB64u(credential.rawId),
          type: credential.type,
          response: {
            clientDataJSON: bytesToB64u(credential.response.clientDataJSON),
            attestationObject: bytesToB64u(credential.response.attestationObject),
          },
        });
        showTerminal('approved', 'Credential enrolled', 'The one-time enrollment link is now spent. Future approvals require user verification.');
      } catch (error) {
        showError(error.message || 'Enrollment failed');
        setBusy($('enrollButton'), false);
      }
    });
  }

  async function boot() {
    const route = routeCapability();
    if (!route) {
      showTerminal('error', 'Invalid link', 'This approval link is malformed.');
      return;
    }
    try {
      if (route.kind === 'approval') await loadApproval(route.value);
      else await loadEnrollment(route.value);
    } catch (error) {
      showTerminal(
        error.status === 410 ? 'expired' : 'error',
        error.status === 410 ? 'Expired' : 'Request unavailable',
        error.message || 'The request could not be loaded.',
      );
    }
  }

  boot();
}());
