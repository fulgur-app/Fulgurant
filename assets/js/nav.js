document.addEventListener('alpine:init', function () {
  Alpine.data('navDropdown', function () {
    return {
      open: false,

      toggle: function () {
        this.open = !this.open;
      },

      close: function () {
        this.open = false;
      }
    };
  });
});
