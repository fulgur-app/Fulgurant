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
