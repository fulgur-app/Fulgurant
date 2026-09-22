// Sends a file from the browser to one or more Fulgur devices.
//
// Wire format matches the Fulgur client (sync/share/send.rs):
//   base64( age_encrypt( gzip( utf8_text ) ) )
// encrypted to each destination device's age X25519 public key, so the
// server never sees the plaintext. Requires `age.min.js` (see `npm run js:build`).
(function () {
  'use strict';

  // Number of leading bytes inspected for a NUL byte, mirroring Fulgur's `looks_binary`.
  var BINARY_SNIFF_LEN = 8000;

  function formatBytes(bytes) {
    if (bytes < 1024) {
      return bytes + ' bytes';
    }
    var units = ['KB', 'MB', 'GB', 'TB'];
    var value = bytes;
    var unit = '';
    for (var i = 0; i < units.length; i++) {
      value /= 1024;
      unit = units[i];
      if (value < 1024) {
        break;
      }
    }
    return (Number.isInteger(value) ? value.toFixed(0) : value.toFixed(1)) + ' ' + unit;
  }

  function bytesToBase64(bytes) {
    var CHUNK = 0x8000;
    var binary = '';
    for (var i = 0; i < bytes.length; i += CHUNK) {
      binary += String.fromCharCode.apply(null, bytes.subarray(i, i + CHUNK));
    }
    return btoa(binary);
  }

  function looksBinary(bytes) {
    var limit = Math.min(bytes.length, BINARY_SNIFF_LEN);
    for (var i = 0; i < limit; i++) {
      if (bytes[i] === 0) {
        return true;
      }
    }
    return false;
  }

  async function gzip(text) {
    var stream = new Blob([text]).stream().pipeThrough(new CompressionStream('gzip'));
    return new Uint8Array(await new Response(stream).arrayBuffer());
  }

  async function encryptForDevice(text, publicKey) {
    var compressed = await gzip(text);
    var encrypter = new age.Encrypter();
    encrypter.addRecipient(publicKey);
    var ciphertext = await encrypter.encrypt(compressed);
    return bytesToBase64(ciphertext);
  }

  document.addEventListener('DOMContentLoaded', function () {
    var form = document.getElementById('new-share-form');
    if (!form) {
      return;
    }
    var maxBytes = form.dataset.maxBytes ? Number(form.dataset.maxBytes) : null;
    var fileInput = document.getElementById('file-input');
    var fileTarget = document.getElementById('file-target');
    var idle = document.getElementById('file-target-idle');
    var readout = document.getElementById('file-readout');
    var readoutName = document.getElementById('file-readout-name');
    var readoutSize = document.getElementById('file-readout-size');
    var readoutChecks = document.getElementById('file-readout-checks');
    var shareError = document.getElementById('share-error');
    var sendButton = document.getElementById('send-button');
    var csrfMeta = document.querySelector('meta[name="csrf-token"]');
    var csrfToken = csrfMeta ? csrfMeta.getAttribute('content') : '';

    var fileText = null;
    var fileName = null;
    var sending = false;

    function selectedDevices() {
      return Array.prototype.slice.call(form.querySelectorAll('input[name="device"]:checked'));
    }

    function refreshSendButton() {
      sendButton.disabled = sending || fileText === null || selectedDevices().length === 0;
    }

    function showError(message) {
      shareError.textContent = message;
      shareError.hidden = !message;
    }

    function addCheck(text, ok) {
      var item = document.createElement('li');
      item.className = ok ? 'text-success' : 'text-error';
      item.textContent = text;
      readoutChecks.appendChild(item);
    }

    function setDeviceStatus(deviceId, text, tone) {
      var status = form.querySelector('[data-status-for="' + deviceId + '"]');
      if (!status) {
        return;
      }
      status.textContent = text;
      status.classList.remove('text-error', 'text-success', 'text-base-content/60');
      status.classList.add(tone);
    }

    function clearDeviceStatuses() {
      form.querySelectorAll('.device-status').forEach(function (status) {
        status.textContent = '';
      });
    }

    async function inspectFile(file) {
      fileText = null;
      fileName = null;
      readoutChecks.textContent = '';
      readoutName.textContent = file.name;
      readoutSize.textContent = formatBytes(file.size);
      idle.hidden = true;
      readout.hidden = false;
      showError('');
      clearDeviceStatuses();

      var bytes = new Uint8Array(await file.arrayBuffer());
      var isText = !looksBinary(bytes);
      var text = null;
      if (isText) {
        try {
          text = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
        } catch (_) {
          isText = false;
        }
      }
      if (file.size === 0) {
        addCheck('The file is empty', false);
      } else if (isText) {
        addCheck('Text file, Fulgur can open it', true);
      } else {
        addCheck('Not a text file, Fulgur cannot open it', false);
      }

      var fitsLimit = maxBytes === null || file.size <= maxBytes;
      if (maxBytes !== null) {
        addCheck(
          fitsLimit
            ? 'Fits under the ' + formatBytes(maxBytes) + ' limit'
            : 'Larger than the ' + formatBytes(maxBytes) + ' limit',
          fitsLimit
        );
      }

      if (isText && fitsLimit && file.size > 0) {
        fileText = text;
        fileName = file.name;
      }
      refreshSendButton();
    }

    fileInput.addEventListener('change', function () {
      if (fileInput.files && fileInput.files[0]) {
        inspectFile(fileInput.files[0]);
      }
    });

    fileTarget.addEventListener('dragover', function (event) {
      event.preventDefault();
      fileTarget.classList.add('border-primary', 'bg-base-300/40');
    });
    fileTarget.addEventListener('dragleave', function () {
      fileTarget.classList.remove('border-primary', 'bg-base-300/40');
    });
    fileTarget.addEventListener('drop', function (event) {
      event.preventDefault();
      fileTarget.classList.remove('border-primary', 'bg-base-300/40');
      if (event.dataTransfer && event.dataTransfer.files[0]) {
        inspectFile(event.dataTransfer.files[0]);
      }
    });

    form.addEventListener('change', function (event) {
      if (event.target.name === 'device') {
        refreshSendButton();
      }
    });

    async function sendToDevice(checkbox) {
      var deviceId = checkbox.value;
      setDeviceStatus(deviceId, 'Encrypting', 'text-base-content/60');
      var content;
      try {
        content = await encryptForDevice(fileText, checkbox.dataset.publicKey);
      } catch (_) {
        throw new Error('Could not encrypt for this device. Sync it from Fulgur again to refresh its key.');
      }
      if (maxBytes !== null && content.length > maxBytes) {
        throw new Error('Encrypted file is larger than the ' + formatBytes(maxBytes) + ' limit');
      }
      setDeviceStatus(deviceId, 'Sending', 'text-base-content/60');
      var response = await fetch('/share', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'x-csrf-token': csrfToken
        },
        body: JSON.stringify({
          destination_device_id: deviceId,
          file_name: fileName,
          content: content
        })
      });
      if (!response.ok) {
        var message = 'Request failed (' + response.status + ')';
        try {
          var body = await response.json();
          if (body && body.error) {
            message = body.error;
          }
        } catch (_) {
          // Non-JSON error body: keep the status-based message.
        }
        throw new Error(message);
      }
      var result = await response.json();
      setDeviceStatus(deviceId, 'Sent, expires ' + result.expiration_date, 'text-success');
    }

    form.addEventListener('submit', async function (event) {
      event.preventDefault();
      if (sending || fileText === null) {
        return;
      }
      if (typeof age === 'undefined' || typeof CompressionStream === 'undefined') {
        showError('This browser cannot encrypt files. Use a recent Firefox, Chrome or Safari.');
        return;
      }
      sending = true;
      showError('');
      refreshSendButton();

      var devices = selectedDevices();
      var failures = 0;
      for (var i = 0; i < devices.length; i++) {
        try {
          await sendToDevice(devices[i]);
          devices[i].checked = false;
        } catch (error) {
          failures += 1;
          setDeviceStatus(devices[i].value, error.message, 'text-error');
        }
      }

      sending = false;
      if (failures === 0) {
        window.location.assign('/');
        return;
      }
      showError(
        failures === devices.length
          ? 'The file could not be sent. Fix the issues above and try again.'
          : 'Some devices did not receive the file. They stay selected so you can retry.'
      );
      refreshSendButton();
    });
  });
})();
