document.addEventListener('DOMContentLoaded', function () {
  var form = document.getElementById('add-user-form-element');
  if (form) {
    form.addEventListener('htmx:afterRequest', function (event) {
      var errorContainer = document.getElementById('user-error-message');
      if (event.detail.successful) {
        errorContainer.textContent = '';
        form.reset();
      } else {
        errorContainer.textContent = event.detail.xhr.responseText;
      }
    });
  }
});
