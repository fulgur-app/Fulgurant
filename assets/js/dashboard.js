document.addEventListener('DOMContentLoaded', function () {
  var form = document.getElementById('add-device-form-element');
  if (form) {
    form.addEventListener('htmx:afterRequest', function (event) {
      var errorContainer = document.getElementById('device-error-message');
      if (event.detail.successful) {
        errorContainer.textContent = '';
        form.reset();
      } else {
        errorContainer.textContent = event.detail.xhr.responseText;
      }
    });
  }
});

document.body.addEventListener('click', function (event) {
  var removeBtn = event.target.closest('[data-remove-target]');
  if (removeBtn) {
    var target = document.getElementById(removeBtn.dataset.removeTarget);
    if (target) target.remove();
  }
});

document.body.addEventListener('htmx:beforeRequest', function (event) {
  var target = event.target;
  if (
    target.classList.contains('device-edit-btn') ||
    target.classList.contains('device-renew-btn')
  ) {
    var existingForm = document.querySelector('.device-inline-form');
    if (existingForm) {
      event.preventDefault();
    }
  }
});

document.body.addEventListener('htmx:afterSwap', function (event) {
  var target = event.target;
  var requestConfig = event.detail.requestConfig;
  if (
    target.classList.contains('device-row') &&
    (requestConfig.verb === 'put' || requestConfig.verb === 'post')
  ) {
    var nextRow = target.nextElementSibling;
    if (nextRow && nextRow.classList.contains('device-inline-form')) {
      nextRow.remove();
    }
  }
});
