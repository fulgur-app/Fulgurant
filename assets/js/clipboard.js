document.addEventListener('alpine:init', function () {
  Alpine.data('clipboard', function () {
    return {
      copied: false,

      copyFromSibling: function (event) {
        var btn = event.currentTarget;
        var container = btn.closest('.api-key-display, .alert, [x-data]');
        var codeEl = container ? container.querySelector('.api-key-value') : null;
        if (codeEl) {
          this.copy(codeEl.textContent.trim());
        }
      },

      copy: function (text) {
        var self = this;
        if (navigator.clipboard && navigator.clipboard.writeText) {
          navigator.clipboard.writeText(text).then(function () {
            self.showFeedback();
          }).catch(function () {
            if (self.fallbackCopy(text)) {
              self.showFeedback();
            }
          });
        } else {
          if (self.fallbackCopy(text)) {
            self.showFeedback();
          }
        }
      },

      fallbackCopy: function (text) {
        var textarea = document.createElement('textarea');
        textarea.value = text;
        textarea.style.position = 'fixed';
        textarea.style.opacity = '0';
        document.body.appendChild(textarea);
        textarea.select();
        try {
          var success = document.execCommand('copy');
          document.body.removeChild(textarea);
          return success;
        } catch (err) {
          document.body.removeChild(textarea);
          return false;
        }
      },

      showFeedback: function () {
        var self = this;
        self.copied = true;
        setTimeout(function () {
          self.copied = false;
        }, 3000);
      }
    };
  });
});
