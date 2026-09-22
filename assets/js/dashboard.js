document.addEventListener('DOMContentLoaded', function () {
  var form = document.getElementById('add-device-form-element');
  if (form) {
    form.addEventListener('htmx:afterRequest', function (event) {
      var errorContainer = document.getElementById('device-error-message');
      if (event.detail.successful) {
        errorContainer.textContent = '';
        errorContainer.classList.remove('alert', 'alert-error');
        form.reset();
      } else {
        // The server answers with the error_message.html partial; keep only its text.
        var errorDocument = new DOMParser().parseFromString(
          event.detail.xhr.responseText,
          'text/html'
        );
        errorContainer.textContent = errorDocument.body.textContent.trim();
        errorContainer.classList.add('alert', 'alert-error');
      }
    });
  }
});

document.addEventListener('htmx:beforeRequest', function (event) {
  function removeInlineForms() {
    document.querySelectorAll('.device-inline-form').forEach(function (form) {
      form.remove();
    });
  }

  var trigger = event.detail && event.detail.elt ? event.detail.elt : event.target;
  if (!trigger || typeof trigger.closest !== 'function') {
    return;
  }

  var actionButton = trigger.closest('.device-edit-btn, .device-renew-btn');
  if (!actionButton) {
    return;
  }

  var deviceRow = actionButton.closest('.device-row');
  if (!deviceRow || !deviceRow.id) {
    return;
  }

  var deviceId = deviceRow.id.replace('device-', '');
  var targetFormId = actionButton.classList.contains('device-edit-btn')
    ? 'inline-edit-' + deviceId
    : 'inline-renew-' + deviceId;

  var targetForm = document.getElementById(targetFormId);

  if (targetForm) {
    event.preventDefault();
    removeInlineForms();
    return;
  }

  removeInlineForms();
});
